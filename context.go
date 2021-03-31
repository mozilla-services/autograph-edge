package main

import (
	"context"
	"net/http"
)

type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "github.com/mozilla-services/autograph-edge context value " + k.name }

var (
	// ctxReqID is the string identifier of a request ID in a context
	contextKeyRequestID = contextKey{name: "reqID"}
)

// addToContext add the given key value pair to the given request's context
func addToContext(r *http.Request, key contextKey, value interface{}) *http.Request {
	ctx := r.Context()
	return r.WithContext(context.WithValue(ctx, key, value))
}

// getRequestID retrieves an ID from the request context, or returns "-" is none is found
func getRequestID(r *http.Request) string {
	val, ok := r.Context().Value(contextKeyRequestID).(string)
	if ok {
		return val
	}
	return "-"
}
