package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"go.mozilla.org/hawk"
)

type signaturerequest struct {
	Input   string `json:"input"`
	KeyID   string `json:"keyid"`
	Options interface{}
}

type signatureresponse struct {
	Ref        string `json:"ref"`
	Type       string `json:"type"`
	SignerID   string `json:"signer_id"`
	PublicKey  string `json:"public_key,omitempty"`
	Signature  string `json:"signature"`
	SignedFile string `json:"signed_file"`
	X5U        string `json:"x5u,omitempty"`
}

// xpiOptions contains specific parameters used to sign XPIs
type xpiOptions struct {
	// ID is the add-on ID which is stored in the end-entity subject CN
	ID string `json:"id"`

	// COSEAlgorithms is an optional list of strings referring to IANA algorithms to use for COSE signatures
	COSEAlgorithms []string `json:"cose_algorithms"`

	// PKCS7Digest is a string required for /sign/file referring to algorithm to use for the PKCS7 signature digest
	PKCS7Digest string `json:"pkcs7_digest"`
}

func callAutograph(auth authorization, body []byte, xff string) (signedBody []byte, err error) {
	var requests []signaturerequest
	request := signaturerequest{
		Input: base64.StdEncoding.EncodeToString(body),
		KeyID: auth.Signer,
	}
	if auth.AddonID != "" {
		opt := xpiOptions{
			ID:          auth.AddonID,
			PKCS7Digest: "SHA1",
		}
		if auth.AddonPKCS7Digest != "" {
			opt.PKCS7Digest = auth.AddonPKCS7Digest
		}
		if len(auth.AddonCOSEAlgorithms) > 0 {
			opt.COSEAlgorithms = auth.AddonCOSEAlgorithms
		}
		request.Options = opt
	}
	requests = append(requests, request)
	reqBody, err := json.Marshal(requests)
	if err != nil {
		return
	}
	rdr := bytes.NewReader(reqBody)
	req, err := http.NewRequest(http.MethodPost, conf.BaseURL+"sign/file", rdr)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	// make the hawk auth header
	hawkAuth := hawk.NewRequestAuth(req,
		&hawk.Credentials{
			ID:   auth.User,
			Key:  auth.Key,
			Hash: sha256.New},
		0)
	hawkAuth.Ext = fmt.Sprintf("%d", time.Now().Nanosecond())
	payloadhash := hawkAuth.PayloadHash("application/json")
	payloadhash.Write(reqBody)
	hawkAuth.SetHash(payloadhash)
	req.Header.Set("Authorization", hawkAuth.RequestHeader())

	// Reuse the X-Forwarded-For received from the client over to
	// autograph so we can trace requests back to client from its logs
	req.Header.Set("X-Forwarded-For", xff)

	// make the request
	cli := &http.Client{}
	resp, err := cli.Do(req)
	if err != nil {
		return
	}
	if resp == nil {
		err = errAutographEmptyResponse
		return
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusCreated {
		err = errAutographBadStatusCode
		return
	}
	var responses []signatureresponse
	err = json.Unmarshal(respBody, &responses)
	if err != nil {
		return
	}
	if len(responses) != 1 {
		err = errAutographBadResponseCount
		return
	}
	return base64.StdEncoding.DecodeString(responses[0].SignedFile)
}

type heartbeatRequester interface {
	Get(string) (*http.Response, error)
}

type heartbeatClient struct {
	*http.Client
}
