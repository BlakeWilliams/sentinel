package proxy

import (
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/blakewilliams/sentinel/radical"
	"github.com/golang-jwt/jwt/v5"
)

type Route struct {
	Pattern string
	Backend string
}

// type ServerOpt [T]func(*Server[T])
type ServerOpt[T IdentifiableClaims] func(*Server[T])

// WithAuthenticator sets the authenticator for the server.
func WithAuthenticator[T IdentifiableClaims](a Authenticator[T]) ServerOpt[T] {
	return func(s *Server[T]) {
		s.authenticator = a
	}
}

// WithHTTPClient sets the http client for the server.
func WithHTTPClient[T IdentifiableClaims](c *http.Client) ServerOpt[T] {
	return func(s *Server[T]) {
		s.httpClient = c
	}
}

// Server is a basic HTTP proxy server that matches routes based on regular expressions
// and forwards requests to the appropriate backend.
type Server[T IdentifiableClaims] struct {
	Addr          string
	Routes        *radical.Node[Route]
	httpClient    *http.Client
	authenticator Authenticator[T]
}

func New[T IdentifiableClaims](addr string, opts ...ServerOpt[T]) *Server[T] {
	s := &Server[T]{
		Addr:       addr,
		Routes:     radical.New[Route](),
		httpClient: http.DefaultClient,
	}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

func (s *Server[T]) AddRoute(pattern, backend string) {
	s.Routes.Add(strings.Split(pattern, "/"), Route{
		Pattern: pattern,
		Backend: backend,
	})
}

func (s *Server[T]) ListenAndServe() error {
	return http.ListenAndServe(s.Addr, s)
}

func (s *Server[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.Path, "/")

	// TODO run some pre-resolution middleware
	identifier := clientIP(r)
	headersToAdd := make(map[string]string)

	if s.authenticator != nil {
		isAuthed, payload, err := s.authenticator.Authenticate(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		if isAuthed {
			identifier = payload.IdentifierValue()
			unsignedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)

			signedToken, err := unsignedToken.SignedString([]byte("abc123"))
			fmt.Println(signedToken)
			if err != nil {
				// TODO, log instead of 500. This service should be resilient
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			headersToAdd["X-Sentinel-Token"] = signedToken
		}
	}

	fmt.Println(identifier) // todo use with rate limiting if defined

	ok, route := s.Routes.Value(path)

	if !ok {
		http.NotFound(w, r)
		return
	}

	// TODO remove irrelevant headers

	req, err := http.NewRequest(r.Method, route.Backend+r.URL.Path, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for k, v := range headersToAdd {
		req.Header.Set(k, v)
	}

	res, err := s.httpClient.Do(req)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for k, values := range res.Header {
		for _, v := range values {
			w.Header().Add(k, v)
		}
	}

	io.Copy(w, res.Body)
}

// clientIP returns the client IP address from the request
// headers to be used in rate limiting.
func clientIP(r *http.Request) string {
	forwarded := r.Header.Get("X-Forwarded-For")
	if forwarded != "" {
		return strings.SplitN(forwarded, " ", 2)[0]
	}

	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}

	return r.RemoteAddr
}
