package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
	"gopkg.in/yaml.v2"
)

var (
	errInvalidToken              = errors.New("invalid authorization token")
	errInvalidMethod             = errors.New("only POST requests are supported")
	errMissingBody               = errors.New("missing request body")
	errAutographBadStatusCode    = errors.New("failed to retrieve signature from autograph")
	errAutographBadResponseCount = errors.New("received an invalid number of responses from autograph")
	errAutographEmptyResponse    = errors.New("autograph returned an invalid empty response")

	conf configuration
)

type configuration struct {
	URL            string
	Authorizations []authorization
}

type authorization struct {
	ClientToken         string `yaml:"client_token"`
	Signer              string
	User                string
	Key                 string
	AddonID             string
	AddonPKCS7Digest    string
	AddonCOSEAlgorithms []string
}

var jsonVersion []byte

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph-edge")

	var err error
	jsonVersion, err = ioutil.ReadFile("version.json")
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	var (
		cfgFile      string
		autographURL string
	)
	flag.StringVar(&cfgFile, "c", "autograph-edge.yaml", "Path to configuration file")
	flag.StringVar(&autographURL, "u", "", "Upstream Autograph URL")
	flag.Parse()

	err := conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	err = findDuplicateClientToken(conf.Authorizations)
	if err != nil {
		log.Fatal(err)
	}

	if autographURL != "" {
		log.Infof("using commandline autograph URL %s instead of conf %s", autographURL, conf.URL)
		conf.URL = autographURL
	}

	http.HandleFunc("/sign", sigHandler)
	http.HandleFunc("/__version__", versionHandler)
	http.HandleFunc("/__heartbeat__", heartbeatHandler)
	http.HandleFunc("/__lbheartbeat__", versionHandler)

	log.Infof("start server on port 8080 with upstream autograph %s", conf.URL)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// sigHandler receives input body must
// contain a base64 encoded file to sign, and the response body contains a base64 encoded
// signed file. The Authorization header of the http request must contain a valid token.
func sigHandler(w http.ResponseWriter, r *http.Request) {
	rid := makeRequestID()
	log.WithFields(log.Fields{
		"remoteAddressChain": "[" + r.Header.Get("X-Forwarded-For") + "]",
		"method":             r.Method,
		"proto":              r.Proto,
		"url":                r.URL.String(),
		"ua":                 r.UserAgent(),
		"rid":                rid,
	}).Info("request")

	// some sanity checking on the request
	if r.Method != http.MethodPost {
		log.WithFields(log.Fields{"rid": rid}).Error("invalid method")
		httpError(w, r, http.StatusMethodNotAllowed, "invalid method")
		return
	}
	if len(r.Header.Get("Authorization")) < 60 {
		log.WithFields(log.Fields{"rid": rid}).Error("missing authorization header")
		httpError(w, r, http.StatusUnauthorized, "missing authorization header")
		return
	}
	// verify auth token
	auth, err := authorize(r.Header.Get("Authorization"))
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		httpError(w, r, http.StatusUnauthorized, "not authorized")
		return
	}

	fd, fdHeader, err := r.FormFile("input")
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		httpError(w, r, http.StatusBadRequest, "failed to read form data")
		return
	}
	defer fd.Close()

	input := make([]byte, fdHeader.Size)
	_, err = io.ReadFull(fd, input)
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		httpError(w, r, http.StatusBadRequest, "failed to read input")
		return
	}
	inputSha256 := fmt.Sprintf("%x", sha256.Sum256(input))

	// prepare an x-forwarded-for by reusing the values received and adding the client IP
	clientip := strings.Split(r.RemoteAddr, ":")
	xff := strings.Join([]string{
		r.Header.Get("X-Forwarded-For"),
		strings.Join(clientip[:len(clientip)-1], ":")},
		",")

	// let's get this file signed!
	output, err := callAutograph(auth, input, xff)
	if err != nil {
		log.WithFields(log.Fields{"rid": rid, "input_sha256": inputSha256}).Error(err)
		httpError(w, r, http.StatusBadGateway, "failed to call autograph for signature")
		return
	}
	outputSha256 := fmt.Sprintf("%x", sha256.Sum256(output))

	log.WithFields(log.Fields{"rid": rid,
		"user":          auth.User,
		"input_sha256":  inputSha256,
		"output_sha256": outputSha256,
	}).Info("returning signed data")

	w.Header().Add("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusCreated)
	w.Write(output)
}

// loadFromFile reads a configuration from a local file
func (c *configuration) loadFromFile(path string) error {
	var confData []byte
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}
	// Try to decrypt the conf using sops or load it as plaintext.
	// If the configuration is not encrypted with sops, the error
	// sops.MetadataNotFound will be returned, in which case we
	// ignore it and continue loading the conf.
	confData, err = decrypt.Data(data, "yaml")
	if err != nil {
		if err == sops.MetadataNotFound {
			// not an encrypted file
			confData = data
		} else {
			return errors.Wrap(err, "failed to load sops encrypted configuration")
		}
	}
	err = yaml.Unmarshal(confData, &c)
	if err != nil {
		return err
	}
	return nil
}

func authorize(authHeader string) (auth authorization, err error) {
	for _, auth := range conf.Authorizations {
		if authHeader == auth.ClientToken {
			return auth, nil
		}
	}
	return authorization{}, errInvalidToken
}

func httpError(w http.ResponseWriter, r *http.Request, errorCode int, errorMessage string, args ...interface{}) {
	log.WithFields(log.Fields{
		"code": errorCode,
	}).Errorf(errorMessage, args...)
	msg := fmt.Sprintf(errorMessage, args...)

	// when nginx is in front of go, nginx requires that the entire
	// request body is read before writing a response.
	// https://github.com/golang/go/issues/15789
	if r.Body != nil {
		io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
	http.Error(w, msg, errorCode)
	return
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonVersion)
}

type heartbeat struct {
	Status bool `json:"status"`
	Checks struct {
		CheckAutographHeartbeat bool `json:"check_autograph_heartbeat"`
	} `json:"checks"`
	Details string `json:"details"`
}

func writeHeartbeatResponse(w http.ResponseWriter, st heartbeat) {
	w.Header().Set("Content-Type", "application/json")
	if !st.Status {
		log.Println(st.Details)
		w.WriteHeader(http.StatusServiceUnavailable)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	jsonSt, err := json.Marshal(st)
	if err != nil {
		log.Fatalf("failed to marshal heartbeat status: %v", err)
	}
	w.Write(jsonSt)
}

// send a GET request to the autograph heartbeat endpoint and
// evaluate its status code before responding
func heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	var st heartbeat
	// assume the best, change if we encounter errors
	st.Status = true
	st.Checks.CheckAutographHeartbeat = true

	u, err := url.Parse(conf.URL)
	if err != nil {
		log.Printf("failed to parse conf url %q: %v", conf.URL, err)
		httpError(w, r, http.StatusInternalServerError, "failed to parse conf URL")
		return
	}
	heartbeatURL := fmt.Sprintf("%s://%s/__heartbeat__", u.Scheme, u.Host)
	resp, err := http.Get(heartbeatURL)
	if err != nil {
		st.Checks.CheckAutographHeartbeat = false
		st.Status = false
		st.Details = fmt.Sprintf("failed to request autograph heartbeat from %s: %v", heartbeatURL, err)
		writeHeartbeatResponse(w, st)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		st.Checks.CheckAutographHeartbeat = false
		st.Status = false
		st.Details = fmt.Sprintf("upstream autograph returned heartbeat code %d %s", resp.StatusCode, resp.Status)
		writeHeartbeatResponse(w, st)
		return
	}
	writeHeartbeatResponse(w, st)
}
func makeRequestID() string {
	rid := make([]rune, 16)
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	for i := range rid {
		rid[i] = letters[rand.Intn(len(letters))]
	}
	return string(rid)
}

// findDuplicateClientToken returns an error if it finds a duplicate
// token in a slice of authorizations
func findDuplicateClientToken(auths []authorization) error {
	// a map of token to index in the auths slice
	seenTokenIndexes := map[string]int{}

	for i, auth := range auths {
		seenTokenIndex, exists := seenTokenIndexes[auth.ClientToken]
		if exists {
			return fmt.Errorf("found duplicate client token at positions %d and %d", seenTokenIndex, i)
		}
		seenTokenIndexes[auth.ClientToken] = i
	}
	return nil
}
