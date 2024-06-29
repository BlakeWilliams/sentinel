package proxy

import (
	"crypto/x509"
	_ "embed"
	"encoding/pem"
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
			if jwtHeader == "" {
				_, _ = w.Write([]byte("no token"))
				return
			}

			token, err := jwt.ParseWithClaims(jwtHeader, &noopResult{}, func(token *jwt.Token) (interface{}, error) {
				return testPublicKey, nil
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
	s := New[noopResult](":8080", testSigningKey)
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
	s := New[noopResult](":8080", testSigningKey, WithAuthenticator(NoopeAuthenticator{
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

//go:embed rsatest.key
var rsaTestKey []byte
var rsaTestBlock, _ = pem.Decode(rsaTestKey)
var testSigningKey, _ = x509.ParsePKCS1PrivateKey(rsaTestBlock.Bytes)

//go:embed rsatest.key.pub
var rsaTestPubKey []byte
var rsaTestPubBlock, _ = pem.Decode(rsaTestPubKey)
var testPublicKey, _ = x509.ParsePKIXPublicKey(rsaTestPubBlock.Bytes)
