package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	gomock "github.com/golang/mock/gomock"
	"github.com/mozilla-services/autograph-edge/mock_main"
)

func Test_heartbeatHandler(t *testing.T) {
	type args struct {
		baseURL string
		r       *http.Request
	}
	type expectedResponse struct {
		status      int
		body        []byte
		contentType string
	}
	tests := []struct {
		name             string
		args             args
		upstreamResponse *http.Response
		upstreamErr      error
		expectedResponse expectedResponse
	}{
		{
			name: "edge heartbeat OK when autograph app returns 200",
			args: args{
				baseURL: conf.BaseURL,
				r:       httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil),
			},
			upstreamResponse: &http.Response{
				Status:     http.StatusText(http.StatusOK),
				StatusCode: http.StatusOK,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte("{}"))),
			},
			upstreamErr: nil,
			expectedResponse: expectedResponse{
				status:      http.StatusOK,
				contentType: "application/json",
				body:        []byte("{\"status\":true,\"checks\":{\"check_autograph_heartbeat\":true},\"details\":\"\"}"),
			},
		},
		{
			name: "edge heartbeat 503 when autograph app returns 502",
			args: args{
				baseURL: conf.BaseURL,
				r:       httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil),
			},
			upstreamResponse: &http.Response{
				Status:     http.StatusText(http.StatusBadGateway),
				StatusCode: http.StatusBadGateway,
				Body:       ioutil.NopCloser(bytes.NewReader([]byte("{}"))),
			},
			upstreamErr: nil,
			expectedResponse: expectedResponse{
				status:      http.StatusServiceUnavailable,
				contentType: "application/json",
				body:        []byte("{\"status\":false,\"checks\":{\"check_autograph_heartbeat\":false},\"details\":\"upstream autograph returned heartbeat code 502 Bad Gateway\"}"),
			},
		},
		{
			name: "edge heartbeat 503 when autograph app is down",
			args: args{
				baseURL: conf.BaseURL,
				r:       httptest.NewRequest("GET", "http://localhost:8080/__heartbeat__", nil),
			},
			upstreamResponse: &http.Response{},
			upstreamErr:      fmt.Errorf("Get \"http://localhost:8000/__heartbeat__\": dial tcp 127.0.0.1:8000: connect: connection refused <nil>"),
			expectedResponse: expectedResponse{
				status:      http.StatusServiceUnavailable,
				contentType: "application/json",
				body:        []byte("{\"status\":false,\"checks\":{\"check_autograph_heartbeat\":false},\"details\":\"failed to request autograph heartbeat from http://localhost:8000/__heartbeat__: Get \\\"http://localhost:8000/__heartbeat__\\\": dial tcp 127.0.0.1:8000: connect: connection refused \\u003cnil\\u003e\"}"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var client heartbeatRequester
			if os.Getenv("MOCK_AUTOGRAPH_CALLS") == string("1") {
				ctrl := gomock.NewController(t)
				defer ctrl.Finish()

				clientMock := mock_main.NewMockheartbeatRequester(ctrl)
				clientMock.EXPECT().Get(tt.args.baseURL+"__heartbeat__").Return(tt.upstreamResponse, tt.upstreamErr)
				client = clientMock
			} else {
				client = &heartbeatClient{&http.Client{}}
			}

			w := httptest.NewRecorder()

			heartbeatHandler(tt.args.baseURL, client)(w, tt.args.r)

			resp := w.Result()
			body, _ := ioutil.ReadAll(resp.Body)

			if resp.StatusCode != tt.expectedResponse.status {
				t.Fatalf("heartbeatHandler() returned unexpected status %v expected %v", resp.StatusCode, tt.expectedResponse.status)
			}
			if !bytes.Equal(body, tt.expectedResponse.body) {
				t.Fatalf("heartbeatHandler() returned body:\n%s\nand expected:\n%s", body, tt.expectedResponse.body)
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

func TestNotFoundHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
	w := httptest.NewRecorder()
	notFoundHandler(w, req)

	resp := w.Result()
	body, _ := ioutil.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("returned unexpected status %v expected %v", resp.StatusCode, http.StatusOK)
	}
	if !bytes.Equal(body, []byte("404 page not found\n")) {
		t.Fatalf("failed to return 404 contents got %q and expected %q", body, "404 page not found\n")
	}
	if resp.Header.Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Fatalf("notFoundHandler returned unexpected content type: %q", resp.Header.Get("Content-Type"))
	}
}
