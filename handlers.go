package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"
)

// sigHandler receives input body must
// contain a base64 encoded file to sign, and the response body contains a base64 encoded
// signed file. The Authorization header of the http request must contain a valid token.
func sigHandler(w http.ResponseWriter, r *http.Request) {
	rid := getRequestID(r)
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

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	httpError(w, r, http.StatusNotFound, "404 page not found")
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
