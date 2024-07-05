# Sentinel APi Gateway

Sentinel is a basic proof-of-concept API gateway that attempts to:

- Centralize opaque authentication through a single point of entry using JWTs
- Route requests to the appropriate back-end service
- Handle rate limiting requests through middleware
- Be extensible to customize or extend the behavior of the gateway

## Usage

There's some boilerplate required to get started for setting up the JWT type in
addition the communication with the auth server. You also likely want to include
and configure rate limiting middleware. Here's a basic (and rough) example of
how to get started:

```go
// Setup the type that will be encoded into a JWT and passed to subsequent back-ends
type AuthData struct {
	Identifier string
	Email string
	jwt.RegisteredClaims
}

// Implement the IdentifierValue method for the IdentifiableClaims interface that
// will be used to identify the user for add-ons like rate limiting,
func (a *AuthData) IdentifierValue() {
	return Identifier
}

type MyAuthenticator struct {
	// ... your fields here
}

func (a *MyAuthenticator) Authenticate(w http.ResponseWriter, r *http.Request) (AuthData, error) {
	data, err := MyAuthenticator.GetForCookie(r.Cookie("my-cookie"))
	if err != nil {
		return AuthData{}, err
	}

	return AuthData{
		Identifier: data.Identifier,
		Email: data.Email,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: "my-auth-server",
			Expiration: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}, nil
}

	s := New[AuthData](":8080", mySigningKey, WithAuthenticator(MyAuthenticator{}))

	s.PostAuth(ratelimit.RateLimiter{
		Redis: myRedis,
		MaxRequests: 100,
		Duration: time.Minute*10,
		Logger: myLogger
	}.Middleware)

	s.AddRoute("*", "http://some-service:8080")
	s.AddRoute("/foo/bar", "http://another-service:2047")

	s.ListenAndServe(":8080")
```
