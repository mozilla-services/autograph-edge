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

func Test_findDuplicateClientToken(t *testing.T) {
	type args struct {
		auths []authorization
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "empty list auths",
			args: args{
				auths: []authorization{},
			},
			wantErr: false,
		},
		{
			name: "dev config tokens (unique)",
			args: args{
				auths: []authorization{
					authorization{
						ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					},
					authorization{
						ClientToken: "b8c8c00f310c9e160dda75790df6be106e29607fde3c1092287d026c014be880",
					},
					authorization{
						ClientToken: "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "duplicate token",
			args: args{
				auths: []authorization{
					authorization{
						ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
						Signer:      "spam",
					},
					authorization{
						ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
						Signer:      "eggs",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "duplicate token with other auths interleaved",
			args: args{
				auths: []authorization{
					authorization{
						ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
						Signer:      "spam",
					},
					authorization{
						ClientToken: "b8c8c00f310c9e160dda75790df6be106e29607fde3c1092287d026c014be880",
					},
					authorization{
						ClientToken: "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd",
					},
					authorization{
						ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
						Signer:      "eggs",
					},
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := findDuplicateClientToken(tt.args.auths); (err != nil) != tt.wantErr {
				t.Errorf("findDuplicateClientToken() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_validateAuth(t *testing.T) {
	type args struct {
		auth authorization
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "valid auth",
			args: args{
				auth: authorization{
					ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:      "extensions-ecdsa",
					User:        "alice",
					Key:         "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: false,
		},
		{
			name: "valid auth with all optional fields",
			args: args{
				auth: authorization{
					ClientToken:         "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:              "extensions-ecdsa",
					User:                "alice",
					Key:                 "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
					AddonID:             "mycoseaddon@allizom.org",
					AddonPKCS7Digest:    "SHA256",
					AddonCOSEAlgorithms: []string{"ES256"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid auth empty client token",
			args: args{
				auth: authorization{
					ClientToken:         "",
					Signer:              "extensions-ecdsa",
					User:                "alice",
					Key:                 "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth short client token",
			args: args{
				auth: authorization{
					ClientToken:         "1234",
					Signer:              "extensions-ecdsa",
					User:                "alice",
					Key:                 "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph signer id",
			args: args{
				auth: authorization{
					ClientToken:         "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:              "",
					User:                "alice",
					Key:                 "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph user id",
			args: args{
				auth: authorization{
					ClientToken:         "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:              "extensions-ecdsa",
					User:                "",
					Key:                 "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph user key",
			args: args{
				auth: authorization{
					ClientToken:         "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:              "extensions-ecdsa",
					User:                "alice",
					Key:                 "",
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateAuth(tt.args.auth); (err != nil) != tt.wantErr {
				t.Errorf("validateAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
