package sentinel

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/blakewilliams/sentinel/internal/radical"
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

type Middleware func(http.Handler) http.Handler

// Server is a basic HTTP proxy server that matches routes based on regular expressions
// and forwards requests to the appropriate backend.
type Server[T IdentifiableClaims] struct {
	Addr               string
	Routes             *radical.Node[Route]
	signingKey         any
	httpClient         *http.Client
	authenticator      Authenticator[T]
	once               sync.Once
	handler            http.Handler
	preAuthMiddleware  []Middleware
	postAuthMiddleware []Middleware
}

func New[T IdentifiableClaims](addr string, signingKey any, opts ...ServerOpt[T]) *Server[T] {
	s := &Server[T]{
		Addr:       addr,
		Routes:     radical.New[Route](),
		signingKey: signingKey,
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

func (s *Server[T]) compileInnerHandler() http.Handler {
	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.Split(r.URL.Path, "/")

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

		if auth, ok := GetAuth[T](r.Context()); ok {
			// Set the JWT token in the header for the service to utilize
			unsignedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, auth)
			signedToken, err := unsignedToken.SignedString(s.signingKey)
			if err != nil {
				// TODO, log instead of 500. This service should be resilient
				// and continue even if the token signing fails.
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			req.Header.Set("X-Sentinel-Token", signedToken)
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

		_, _ = io.Copy(w, res.Body)
	})

	for i := len(s.postAuthMiddleware) - 1; i >= 0; i-- {
		existingHandler := handler
		handler = s.postAuthMiddleware[i](existingHandler)
	}

	return handler
}

// CompileHandler compiles the handler for the server. This is typically done lazily
// in the first request to the server but can be explicitly compiled with this method too.
func (s *Server[T]) CompileHandler() {
	innerHandler := s.compileInnerHandler()

	var handler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authenticator != nil {
			isAuthed, payload, err := s.authenticator.Authenticate(w, r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}

			if isAuthed {
				r = r.WithContext(context.WithValue(r.Context(), AuthContextKey{}, payload))
			}
		}

		// this is where we call the inner handler
		innerHandler.ServeHTTP(w, r)
	})

	for i := len(s.preAuthMiddleware) - 1; i >= 0; i-- {
		existingHandler := handler
		handler = s.preAuthMiddleware[i](existingHandler)
	}

	s.handler = handler
}

func (s *Server[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.once.Do(s.CompileHandler)
	s.handler.ServeHTTP(w, r)
}

// PreAuth adds a middleware that is run before the request is authenticated via
// the provided authenticator.
func (s *Server[T]) PreAuth(m Middleware) {
	s.preAuthMiddleware = append(s.preAuthMiddleware, m)
}

// PostAuth adds a middleware that is run after the request is authenticated via
// the provided authenticator.
func (s *Server[T]) PostAuth(m Middleware) {
	s.postAuthMiddleware = append(s.postAuthMiddleware, m)
}

type AuthContextKey struct{}

func GetAuth[T IdentifiableClaims](ctx context.Context) (T, bool) {
	if v, ok := ctx.Value(AuthContextKey{}).(T); ok {
		return v, true
	}

	var tType T
	return tType, false
}
