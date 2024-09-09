package main

import (
	"crypto/subtle"
	_ "embed"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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

//go:generate ./version.sh
//go:embed "version.json"
var jsonVersion []byte

func init() {
	// initialize the logger
	mozlogrus.Enable("autograph-edge")
}

func main() {
	parseArgsAndLoadConf()
	server := prepareServer()

	log.Infof("starting autograph-edge on port 8080 with upstream autograph base URL %s", conf.BaseURL)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func parseArgsAndLoadConf() {
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
}

func prepareServer() *http.Server {
	http.Handle("/sign",
		handleWithMiddleware(
			http.HandlerFunc(sigHandler),
			setRequestID(),
			setResponseHeaders(),
		),
	)
	http.Handle("/__version__",
		handleWithMiddleware(
			http.HandlerFunc(versionHandler),
			setResponseHeaders(),
		),
	)
	http.Handle("/__heartbeat__",
		handleWithMiddleware(
			http.HandlerFunc(
				heartbeatHandler(conf.BaseURL, &heartbeatClient{&http.Client{}}),
			),
			setResponseHeaders(),
		),
	)
	http.Handle("/__lbheartbeat__",
		handleWithMiddleware(
			http.HandlerFunc(versionHandler),
			setResponseHeaders(),
		),
	)
	http.Handle("/",
		handleWithMiddleware(
			http.HandlerFunc(notFoundHandler),
			setResponseHeaders(),
		),
	)
	return &http.Server{
		Addr: ":8080",
	}
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
	http.Error(w, msg, errorCode)
	return
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
