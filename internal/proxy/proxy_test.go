package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

var fakeBackend *httptest.Server

func TestMain(m *testing.M) {
	fakeBackend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		w.Write([]byte("Hello, World!"))
	}))
	defer fakeBackend.Close()

	m.Run()
}

func TestProxy(t *testing.T) {
	s := New(":8080")
	s.AddRoute("/", fakeBackend.URL)

	handler := httptest.NewServer(s)
	defer handler.Close()

	req, err := http.Get(handler.URL)
	require.Nil(t, err)

	body, err := io.ReadAll(req.Body)
	require.Nil(t, err)
	require.Equal(t, "Hello, World!", string(body))
}
