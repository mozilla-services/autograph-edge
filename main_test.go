package main

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestMain(m *testing.M) {
	// load the signers
	err := conf.loadFromFile("./autograph-edge.yaml")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("configuration: %+v\n", conf)
	// run the tests and exit
	r := m.Run()
	os.Exit(r)
}

func Test_authorize(t *testing.T) {
	type args struct {
		authHeader string
	}
	tests := []struct {
		name         string
		args         args
		expectedAuth authorization
		expectedErr  error
	}{
		{
			name: "expect extension-ecdsa auth",
			args: args{authHeader: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547"},
			expectedAuth: authorization{
				User:   "alice",
				Signer: "extensions-ecdsa",
			},
			expectedErr: nil,
		},
		{
			name: "expect testapp-android auth",
			args: args{authHeader: "dd095f88adbf7bdfa18b06e23e83896107d7e0f969f7415830028fa2c1ccf9fd"},
			expectedAuth: authorization{
				User:   "alice",
				Signer: "testapp-android",
			},
			expectedErr: nil,
		},
		{
			name:         "empty auth header",
			args:         args{authHeader: "c4180d2963fffdcd1cd5a1a343225288b964d8934"},
			expectedAuth: authorization{},
			expectedErr:  errInvalidToken,
		},
		{
			name:         "short auth header",
			args:         args{authHeader: "c4180d2963fffdcd1cd5a1a343225288b964d8934"},
			expectedAuth: authorization{},
			expectedErr:  errInvalidToken,
		},
		{
			name:         "invalid auth header",
			args:         args{authHeader: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67c98712jh"},
			expectedAuth: authorization{},
			expectedErr:  errInvalidToken,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAuth, err := authorize(tt.args.authHeader)
			if err != tt.expectedErr {
				t.Errorf("authorize() error = %v, expectedErr %v", err, tt.expectedErr)
			}
			// failures should match the empty authorization
			if err != nil && !reflect.DeepEqual(gotAuth, tt.expectedAuth) {
				t.Errorf("authorize() = %v, expected %v", gotAuth, tt.expectedAuth)
				return
			}
			// otherwise just check the user and signer
			if gotAuth.User != tt.expectedAuth.User {
				t.Fatalf("authorize() auth.User got %v expected %v", gotAuth.User, tt.expectedAuth.User)
			}
			if gotAuth.Signer != tt.expectedAuth.Signer {
				t.Fatalf("authorize() auth.Signer got %v expected %v", gotAuth.Signer, tt.expectedAuth.Signer)
			}
		})
	}
}

func Test_heartbeatHandler(t *testing.T) {
	type args struct {
		r *http.Request
	}
	type expectedResponse struct {
		status      int
		body        []byte
		contentType string
	}
	tests := []struct {
		name string
		args args
		// upstream autograph signing URL
		autographURL     string
		expectedResponse expectedResponse
	}{
		{
			name: "heartbeak OK",
			args: args{
				r: httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil),
			},
			autographURL: conf.BaseURL,
			expectedResponse: expectedResponse{
				status:      http.StatusOK,
				contentType: "application/json",
				body:        []byte("{\"status\":true,\"checks\":{\"check_autograph_heartbeat\":true},\"details\":\"\"}"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			w := httptest.NewRecorder()

			heartbeatHandler(tt.autographURL)(w, tt.args.r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)


			if resp.StatusCode != tt.expectedResponse.status {
				t.Fatalf("heartbeatHandler() returned unexpected status %v expected %v", resp.StatusCode, tt.expectedResponse.status)
			}
			if !bytes.Equal(body, tt.expectedResponse.body) {
				t.Fatalf("heartbeatHandler() returned body %s and expected %s", body, tt.expectedResponse.body)
			}
			if resp.Header.Get("Content-Type") != tt.expectedResponse.contentType {
				t.Fatalf("heartbeatHandler() returned unexpected content type: %s, expected %s", resp.Header.Get("Content-Type"), tt.expectedResponse.contentType)
			}
		})
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
					ClientToken: "",
					Signer:      "extensions-ecdsa",
					User:        "alice",
					Key:         "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth short client token",
			args: args{
				auth: authorization{
					ClientToken: "1234",
					Signer:      "extensions-ecdsa",
					User:        "alice",
					Key:         "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph signer id",
			args: args{
				auth: authorization{
					ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:      "",
					User:        "alice",
					Key:         "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph user id",
			args: args{
				auth: authorization{
					ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:      "extensions-ecdsa",
					User:        "",
					Key:         "fs5wgcer9qj819kfptdlp8gm227ewxnzvsuj9ztycsx08hfhzu",
				},
			},
			wantErr: true,
		},
		{
			name: "invalid auth empty autograph user key",
			args: args{
				auth: authorization{
					ClientToken: "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
					Signer:      "extensions-ecdsa",
					User:        "alice",
					Key:         "",
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

func Test_validateBaseURL(t *testing.T) {
	t.Parallel()

	type args struct {
		baseURL string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "example config base url",
			args: args{
				baseURL: "http://localhost:8000/",
			},
			wantErr: false,
		},
		{
			name: "example config base url without trailing slash errs",
			args: args{
				baseURL: "http://localhost:8000",
			},
			wantErr: true,
		},
		{
			name: "empty base url errs",
			args: args{
				baseURL: "",
			},
			wantErr: true,
		},
		{
			name: "unparseable base url errs",
			args: args{
				baseURL: "%gh&%ij",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateBaseURL(tt.args.baseURL); (err != nil) != tt.wantErr {
				t.Errorf("validateBaseURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
