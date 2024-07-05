package sentinel

import (
	"errors"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NotAuthenticated is an error that is returned when a request is not
// authenticated. It should be used by Authenticator implementations to
// indicate that a request is not authenticated instead of returning their
// own error.
var NotAuthenticated = errors.New("not authenticated")

// IdentifiableClaims is a jwt.Claims that has an Identifier method that
// returns a unique identifier for the claims to be used for rate limiting
// and similar operations.
type IdentifiableClaims interface {
	IdentifierValue() string
	jwt.Claims
}

type Authenticator[T IdentifiableClaims] interface {
	Authenticate(w http.ResponseWriter, r *http.Request) (T, error)
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
	error         error
	identifier    string
}

func (a NoopeAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (noopResult, error) {
	res := noopResult{
		Identifier: a.identifier,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}

	if a.authenticated {
		return res, nil
	}

	if a.error != nil {
		return res, a.error
	}

	return res, NotAuthenticated
}
