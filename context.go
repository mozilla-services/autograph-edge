package main

import (
	"context"
	"net/http"
)

const contextKeyRequestID = "reqID"

// addToContext add the given key value pair to the given request's context
func addToContext(r *http.Request, key string, value interface{}) *http.Request {
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
