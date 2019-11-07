package main

import (
	"crypto/sha256"
	"crypto/subtle"
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
	BaseURL        string `yaml:"autograph_base_url"`
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
		cfgFile          string
		autographBaseURL string
	)
	flag.StringVar(&cfgFile, "c", "autograph-edge.yaml", "Path to configuration file")
	flag.StringVar(&autographBaseURL, "u", "", "Upstream Autograph Base URL with a trailing slash e.g. http://localhost:8000/")
	flag.Parse()

	err := conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}
	for i, auth := range conf.Authorizations {
		err = validateAuth(auth)
		if err != nil {
			log.Fatalf("error validating auth %d %q", i, err)
		}
	}
	err = findDuplicateClientToken(conf.Authorizations)
	if err != nil {
		log.Fatal(err)
	}

	if autographBaseURL != "" {
		log.Infof("using commandline autograph URL %s instead of conf %s", autographBaseURL, conf.BaseURL)
		conf.BaseURL = autographBaseURL
	}
	err = validateBaseURL(conf.BaseURL)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/sign", sigHandler)
	http.HandleFunc("/__version__", versionHandler)
	http.HandleFunc("/__heartbeat__", heartbeatHandler(conf.BaseURL, &heartbeatClient{&http.Client{}}))
	http.HandleFunc("/__lbheartbeat__", versionHandler)
	http.HandleFunc("/", notFoundHandler)

	log.Infof("start server on port 8080 with upstream autograph base URL %s", conf.BaseURL)
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

	addWebSecurityHeaders(w)
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
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte(auth.ClientToken)) == 1 {
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
	addWebSecurityHeaders(w)
	http.Error(w, msg, errorCode)
	return
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	httpError(w, r, http.StatusNotFound, "404 page not found")
	return
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	addWebSecurityHeaders(w)
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
	addWebSecurityHeaders(w)
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
func heartbeatHandler(baseURL string, client heartbeatRequester) http.HandlerFunc {
	var (
		st           heartbeat
		heartbeatURL string = baseURL + "__heartbeat__"
	)
	return func(w http.ResponseWriter, r *http.Request) {
		// assume the best, change if we encounter errors
		st.Status = true
		st.Checks.CheckAutographHeartbeat = true
		resp, err := client.Get(heartbeatURL)
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

// vaidateAuth returns an error for auths with:
//
// a short (<60 chars) ClientToken
// missing or empty required field autograph user, signer, or key
func validateAuth(auth authorization) error {
	if len(auth.ClientToken) < 60 {
		return fmt.Errorf("client token is too short (%d chars) want at least 60", len(auth.ClientToken))
	}
	if auth.Signer == "" {
		return fmt.Errorf("upstream autograph signer ID is empty")
	}
	if auth.User == "" {
		return fmt.Errorf("upstream autograph user name is empty")
	}
	if auth.Key == "" {
		return fmt.Errorf("upstream autograph user key is empty")
	}
	return nil
}

// validateBaseURL checks that the upstream autograph URL is parseable
// and ends with a trailing slash
func validateBaseURL(baseURL string) error {
	_, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("failed to parse url %q: %v", baseURL, err)
	}
	if !strings.HasSuffix(baseURL, "/") {
		return fmt.Errorf("url does not end with a trailing slash %v", baseURL)
	}
	return nil
}

// addWebSecurityHeaders adds web security headers suitable for API
// responses to a response writer
func addWebSecurityHeaders(w http.ResponseWriter) {
	w.Header().Add("Content-Security-Policy", "default-src 'none'; object-src 'none';")
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Strict-Transport-Security", "max-age=31536000;")
	return
}
