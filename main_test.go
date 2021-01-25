package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// load the signers
	err := conf.loadFromFile(os.Getenv("GOPATH") + "/src/go.mozilla.org/autograph-edge/autograph-edge.yaml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("configuration: %+v\n", conf)
	// run the tests and exit
	r := m.Run()
	os.Exit(r)
}

func TestAuth(t *testing.T) {
	var testcases = []struct {
		expect bool
		token  string
		user   string
		signer string
	}{
		{true, "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547", "alice", "extensions-ecdsa"},
		{true, "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd", "alice", "testapp-android"},
		{false, "c4180d2963fffdcd1cd5a1a343225288b964d8934", "", ""},
		{false, "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67c98712jh", "", ""},
	}
	for i, testcase := range testcases {
		auth, err := authorize(testcase.token)
		if err != nil {
			if err == errInvalidToken && !testcase.expect {
				continue
			}
			if testcase.expect {
				t.Fatalf("testcase %d expected to succeed but failed with %s", i, err)
			}
		}
		if auth.User != testcase.user {
			t.Fatalf("testcase %d failed: expected user %q, got %q", i, testcase.user, auth.User)
		}
		if auth.Signer != testcase.signer {
			t.Fatalf("testcase %d failed: expected signer %q, got %q", i, testcase.signer, auth.Signer)
		}
	}
}

func TestHeartbeatBadURL(t *testing.T) {
	origURL := conf.URL
	conf.URL = "%gh&%ij"

	req := httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil)
	w := httptest.NewRecorder()

	heartbeatBadURLBody := []byte("failed to parse conf URL\n")

	heartbeatHandler(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	conf.URL = origURL

	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("returned unexpected status %v expected %v", resp.StatusCode, http.StatusInternalServerError)
	}
	if !bytes.Equal(body, heartbeatBadURLBody) {
		t.Fatalf("failed to return heartbeat got %#v and expected %#v", string(body), string(heartbeatBadURLBody))
	}
	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("heartbeat returned unexpected content type: %s", resp.Header.Get("Content-Type"))
	}
}

func TestHeartbeatRequestFailure(t *testing.T) {
	origURL := conf.URL
	conf.URL = ""

	req := httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil)
	w := httptest.NewRecorder()

	heartbeatBadURLBody := []byte("{\"status\":false,\"checks\":{\"check_autograph_heartbeat\":false},\"details\":\"failed to request autograph heartbeat from :///__heartbeat__: parse :///__heartbeat__: missing protocol scheme\"}")

	heartbeatHandler(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	conf.URL = origURL

	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("returned unexpected status %v expected %v", resp.StatusCode, http.StatusServiceUnavailable)
	}
	if !bytes.Equal(body, heartbeatBadURLBody) {
		t.Fatalf("failed to return heartbeat got %#v and expected %#v", string(body), string(heartbeatBadURLBody))
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("heartbeat returned unexpected content type: %s", resp.Header.Get("Content-Type"))
	}
}

func TestHeartbeatOK(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil)
	w := httptest.NewRecorder()
	heartbeatHandler(w, req)

	heartbeatOKBody := []byte("{\"status\":true,\"checks\":{\"check_autograph_heartbeat\":true},\"details\":\"\"}")

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("returned unexpected status %v expected %v", resp.StatusCode, http.StatusOK)
	}
	if !bytes.Equal(body, heartbeatOKBody) {
		t.Fatalf("failed to return heartbeat got %s and expected %s", body, heartbeatOKBody)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("heartbeat returned unexpected content type: %s", resp.Header.Get("Content-Type"))
	}
}

func TestVersion(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080/__version__", nil)
	w := httptest.NewRecorder()
	versionHandler(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("returned unexpected status %v expected %v", resp.StatusCode, http.StatusOK)
	}
	if !bytes.Equal(body, jsonVersion) {
		t.Fatalf("failed to return version.json contents got %s and expected %s", body, jsonVersion)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("version returned unexpected content type: %s", resp.Header.Get("Content-Type"))
	}
}
