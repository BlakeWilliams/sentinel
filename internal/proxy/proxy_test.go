package proxy

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

var fakeBackend *httptest.Server

func TestMain(m *testing.M) {
	fakeBackend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		if r.URL.Path == "/whoami" {
			jwtHeader := r.Header.Get("X-Sentinel-Token")
			fmt.Println(jwtHeader)
			if jwtHeader == "" {
				_, _ = w.Write([]byte("no token"))
				return
			}

			token, err := jwt.ParseWithClaims(jwtHeader, &noopResult{}, func(token *jwt.Token) (interface{}, error) {
				// since we only use the one private key to sign the tokens,
				// we also only use its public counter part to verify
				return []byte("abc123"), nil
			})

			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}

			fmt.Println(token)
			if claims, ok := token.Claims.(IdentifiableClaims); ok && token.Valid {
				_, _ = w.Write([]byte(claims.IdentifierValue()))
				return
			}

			_, _ = w.Write([]byte("claims failed"))
			return
		}

		_, _ = w.Write([]byte("Hello, World!"))
	}))
	defer fakeBackend.Close()

	m.Run()
}

func TestProxy(t *testing.T) {
	s := New[noopResult](":8080")
	s.AddRoute("/", fakeBackend.URL)

	handler := httptest.NewServer(s)
	defer handler.Close()

	req, err := http.Get(handler.URL)
	require.Nil(t, err)

	body, err := io.ReadAll(req.Body)
	require.Nil(t, err)
	require.Equal(t, "Hello, World!", string(body))
}

func TestProxy_Auth(t *testing.T) {
	s := New[noopResult](":8080", WithAuthenticator(NoopeAuthenticator{
		authenticated: true,
		identifier:    "testuser",
	}))
	s.AddRoute("*", fakeBackend.URL)

	handler := httptest.NewServer(s)
	defer handler.Close()

	req, err := http.Get(handler.URL + "/whoami")
	require.Nil(t, err)

	body, err := io.ReadAll(req.Body)
	require.Nil(t, err)
	require.Equal(t, "testuser", string(body))
}
