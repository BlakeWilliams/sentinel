package proxy

import (
	"io"
	"net/http"
	"strings"

	"github.com/blakewilliams/sentinel/radical"
)

type Route struct {
	Pattern string
	Backend string
}

// Server is a basic HTTP proxy server that matches routes based on regular expressions
// and forwards requests to the appropriate backend.
type Server struct {
	Addr       string
	Routes     *radical.Node[Route]
	httpClient *http.Client
}

func New(addr string) *Server {
	return &Server{
		Addr:       addr,
		Routes:     radical.New[Route](),
		httpClient: http.DefaultClient,
	}
}

func (s *Server) AddRoute(pattern, backend string) {
	s.Routes.Add(strings.Split(pattern, "/"), Route{
		Pattern: pattern,
		Backend: backend,
	})
}

func (s *Server) ListenAndServe() error {
	return http.ListenAndServe(s.Addr, s)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.Split(r.URL.Path, "/")

	// TODO run some pre-resolution middleware

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
