package proxy

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// IdentifiableClaims is a jwt.Claims that has an Identifier method that
// returns a unique identifier for the claims to be used for rate limiting
// and similar operations.
type IdentifiableClaims interface {
	IdentifierValue() string
	jwt.Claims
}

type Authenticator[T IdentifiableClaims] interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (bool, T, error)
}

type noopResult struct {
	Identifier string `json:"identifier"`
	jwt.RegisteredClaims
}

func (n noopResult) IdentifierValue() string {
	return n.Identifier
}

type NoopeAuthenticator struct {
	authenticated bool
	identifier    string
}

func (a NoopeAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (bool, noopResult, error) {
	res := noopResult{
		Identifier: a.identifier,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	return a.authenticated, res, nil
}
