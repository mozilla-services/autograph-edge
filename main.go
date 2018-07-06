package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"

	"github.com/mozilla-services/yaml"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
	"go.mozilla.org/sops"
	"go.mozilla.org/sops/decrypt"
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
	Token   string
	Signer  string
	User    string
	Key     string
	AddonID string
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
	var cfgFile string
	flag.StringVar(&cfgFile, "c", "autograph-edge.yaml", "Path to configuration file")
	flag.Parse()

	err := conf.loadFromFile(cfgFile)
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/sign", sigHandler)
	http.HandleFunc("/__version__", versionHandler)
	http.HandleFunc("/__heartbeat__", heartbeatHandler)
	http.HandleFunc("/__lbheartbeat__", versionHandler)

	log.Info("start server on port 8080")
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
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}
	if len(r.Header.Get("Authorization")) < 60 {
		log.WithFields(log.Fields{"rid": rid}).Error("missing authorization header")
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	// verify auth token
	auth, err := authorize(r.Header.Get("Authorization"))
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		http.Error(w, "not authorized", http.StatusUnauthorized)
		return
	}

	fd, fdHeader, err := r.FormFile("input")
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		http.Error(w, "failed to read form data", http.StatusBadRequest)
		return
	}
	defer fd.Close()

	input := make([]byte, fdHeader.Size)
	_, err = io.ReadFull(fd, input)
	if err != nil {
		log.WithFields(log.Fields{"rid": rid}).Error(err)
		http.Error(w, "failed to read input", http.StatusBadRequest)
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
		http.Error(w, "failed to call autograph for signature", http.StatusBadGateway)
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
		if authHeader == auth.Token {
			return auth, nil
		}
	}
	return authorization{}, errInvalidToken
}

func versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(jsonVersion)
}

// send a GET request to the autograph heartbeat endpoint and
// evaluate its status code before responding
func heartbeatHandler(w http.ResponseWriter, r *http.Request) {
	u, err := url.Parse(conf.URL)
	if err != nil {
		log.Printf("failed to parse conf url %q: %v", conf.URL, err)
		http.Error(w, "failed to parse conf URL", http.StatusInternalServerError)
		return
	}
	heartbeatURL := fmt.Sprintf("%s://%s/__heartbeat__", u.Scheme, u.Host)
	resp, err := http.Get(heartbeatURL)
	if err != nil {
		errMsg := fmt.Sprintf("failed to request autograph heartbeat from %s: %v", heartbeatURL, err)
		http.Error(w, errMsg, http.StatusBadGateway)
		return
	}
	if resp.StatusCode != http.StatusOK {
		errMsg := fmt.Sprintf("upstream autograph returned heartbeat code %d %s", resp.StatusCode, resp.Status)
		log.Println(errMsg)
		http.Error(w, errMsg, http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("all good"))
}
func makeRequestID() string {
	rid := make([]rune, 16)
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	for i := range rid {
		rid[i] = letters[rand.Intn(len(letters))]
	}
	return string(rid)
}
