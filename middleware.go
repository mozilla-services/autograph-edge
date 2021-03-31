package main

import (
	"math/rand"
	"net/http"
)

// Middleware wraps an http.Handler with additional functionality
type Middleware func(http.Handler) http.Handler

// handleWithMiddleware returns a request handler wrapped with the
// provided middleware layers
func handleWithMiddleware(h http.Handler, adapters ...Middleware) http.Handler {
	// To make the middleware run in the order in which they are specified,
	// we reverse through them in the Middleware function, rather than just
	// ranging over them
	for i := len(adapters) - 1; i >= 0; i-- {
		h = adapters[i](h)
	}
	return h
}

func makeRequestID() string {
	rid := make([]rune, 16)
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	for i := range rid {
		rid[i] = letters[rand.Intn(len(letters))]
	}
	return string(rid)
}

// setRequestID is a middleware the generates a random ID for each request processed
// by the HTTP server. The request ID is added to the request context and used to
// track various information and correlate logs.
func setRequestID() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h.ServeHTTP(w, addToContext(r, contextKeyRequestID, makeRequestID()))
		})
	}
}

// setResponseHeaders adds web security headers suitable for API
// responses to an http.Handler
func setResponseHeaders() Middleware {
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-Security-Policy", "default-src 'none'; object-src 'none';")
			w.Header().Add("X-Frame-Options", "DENY")
			w.Header().Add("X-Content-Type-Options", "nosniff")
			w.Header().Add("Strict-Transport-Security", "max-age=31536000;")
			h.ServeHTTP(w, r)
		})
	}
}
