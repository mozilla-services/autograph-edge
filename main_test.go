package main

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

func TestMain(m *testing.M) {
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

func Test_preparedServer(t *testing.T) {
	// For the purpose of testing - ensure we're using IPv4.
	conf.BaseURL = "http://127.0.0.1:8000/"

	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	testServer.Config = prepareServer()
	testServer.Start()
	defer testServer.Close()

	tests := []struct {
		name              string
		method            string
		path              string
		authHeader        string
		contentTypeHeader string
		body              []byte
		expectedStatus    int
		expectedBody      string
		expectedHeaders   http.Header
	}{
		{
			name:           "test GET /__version__ path ok",
			method:         "GET",
			path:           "/__version__",
			body:           []byte(""),
			expectedStatus: http.StatusOK,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"application/json"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: string(jsonVersion),
		},
		{
			name:           "test GET /__lbheartbeat__ path ok",
			method:         "GET",
			path:           "/__lbheartbeat__",
			body:           []byte(""),
			expectedStatus: http.StatusOK,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"application/json"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: string(jsonVersion),
		},
		{
			name:           "test GET / path not found",
			method:         "GET",
			path:           "/",
			body:           []byte(""),
			expectedStatus: http.StatusNotFound,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "404 page not found\n",
		},
		{
			name:           "test GET /blargh path not found",
			method:         "GET",
			path:           "/blargh",
			body:           []byte(""),
			expectedStatus: http.StatusNotFound,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "404 page not found\n",
		},
		{
			name:           "test GET /__heartbeat__ path service unavailable",
			method:         "GET",
			path:           "/__heartbeat__",
			body:           []byte(""),
			expectedStatus: http.StatusServiceUnavailable,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"application/json"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: `{"status":false,"checks":{"check_autograph_heartbeat":false},"details":"failed to request autograph heartbeat from http://127.0.0.1:8000/__heartbeat__: Get \"http://127.0.0.1:8000/__heartbeat__\": dial tcp 127.0.0.1:8000: connect: connection refused"}`,
		},
		{
			name:           "test GET /sign path method not allowed",
			method:         "GET",
			path:           "/sign",
			body:           []byte(""),
			expectedStatus: http.StatusMethodNotAllowed,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "invalid method\n",
		},
		{
			name:           "test POST /sign path no auth header unauthorized",
			method:         "POST",
			path:           "/sign",
			body:           []byte(""),
			expectedStatus: http.StatusUnauthorized,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "missing authorization header\n",
		},
		{
			name:           "test POST /sign path short auth header unauthorized",
			method:         "POST",
			path:           "/sign",
			authHeader:     "fkdjkso",
			body:           []byte(""),
			expectedStatus: http.StatusUnauthorized,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "missing authorization header\n",
		},
		{
			name:           "test POST /sign path invalid auth header unauthorized",
			method:         "POST",
			path:           "/sign",
			authHeader:     "invalid-a40b512c9d6c09bdfc64989b80c723c5fadabd4ac9a8abf31cbc1c17f401eb40",
			body:           []byte(""),
			expectedStatus: http.StatusUnauthorized,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "not authorized\n",
		},
		{
			name:           "test POST /sign path valid auth header no input form field bad request",
			method:         "POST",
			path:           "/sign",
			authHeader:     "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
			body:           []byte(""),
			expectedStatus: http.StatusBadRequest,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "failed to read form data\n",
		},
		{
			name:              "test POST /sign path valid auth header small input form field form encoded bad request",
			method:            "POST",
			path:              "/sign",
			authHeader:        "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
			contentTypeHeader: "application/x-www-form-urlencoded",
			body:              []byte("input=Foo"),
			expectedStatus:    http.StatusBadRequest,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "failed to read form data\n",
		},
		{
			name:              "test POST /sign path valid auth header small input form field form encoded bad request",
			method:            "POST",
			path:              "/sign",
			authHeader:        "c4180d2963fffdcd1cd5a1a343225288b964d8934b809a7d76941ccf67cc8547",
			contentTypeHeader: "multipart/form-data; boundary=fd8f34fd6a9c766e",
			body: []byte(`--fd8f34fd6a9c766e
Content-Disposition: form-data; name="input"; filename="input"
Content-Type: application/octet-stream

;
--fd8f34fd6a9c766e--
`),
			expectedStatus: http.StatusBadGateway,
			expectedHeaders: http.Header{
				"Content-Type":              []string{"text/plain; charset=utf-8"},
				"Content-Security-Policy":   []string{"default-src 'none'; object-src 'none';"},
				"X-Frame-Options":           []string{"DENY"},
				"X-Content-Type-Options":    []string{"nosniff"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
			},
			expectedBody: "failed to call autograph for signature\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(
				tt.method,
				fmt.Sprintf(testServer.URL+tt.path),
				ioutil.NopCloser(bytes.NewReader(tt.body)),
			)
			if err != nil {
				t.Fatal(err)
			}
			if tt.authHeader != "" {
				req.Header.Add("Authorization", tt.authHeader)
			}
			if tt.contentTypeHeader != "" {
				req.Header.Add("Content-Type", tt.contentTypeHeader)
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(res.Body)
			res.Body.Close()
			if err != nil {
				t.Fatal(err)
			}

			if res.StatusCode != tt.expectedStatus {
				t.Fatalf("returned unexpected status %v expected %v", res.StatusCode, tt.expectedStatus)
			}
			if !bytes.Equal([]byte(body), []byte(tt.expectedBody)) {
				t.Fatalf("returned unexpected body '%s' expected '%s'", string(body), tt.expectedBody)
			}

			// ignore headers that vary
			res.Header.Del("Date")
			res.Header.Del("Content-Length")

			if !reflect.DeepEqual(res.Header, tt.expectedHeaders) {
				t.Fatalf("returned unexpected headers %+v expected %+v", res.Header, tt.expectedHeaders)
			}

		})
	}
}
