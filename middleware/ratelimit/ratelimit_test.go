package ratelimit

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/blakewilliams/sentinel"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
)

func TestRateLimit(t *testing.T) {
	redis := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redis.FlushAll(context.TODO())

	rl := &RateLimiter{
		Redis:        redis,
		Window:       1 * time.Minute,
		MaxRequests:  3,
		KeyNamespace: "testratelimiter:v1",
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		require.Equal(t, http.StatusOK, res.Result().StatusCode)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusTooManyRequests, res.Result().StatusCode)

	redisRes := redis.ZCount(context.Background(), "testratelimiter:v1:192.0.2.1", "-inf", "+inf")
	require.Equal(t, int64(3), redisRes.Val())
}

type fakeClaims struct {
	Identifier string
	jwt.Claims
}

func (f fakeClaims) IdentifierValue() string {
	return f.Identifier
}

func TestRateLimit_AuthenticatedUsesIdentifier(t *testing.T) {
	redis := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
	})
	defer redis.FlushAll(context.TODO())

	rl := &RateLimiter{
		Redis:       redis,
		Window:      1 * time.Minute,
		MaxRequests: 3,
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	ctxWithAuth := context.WithValue(req.Context(), sentinel.AuthContextKey{}, fakeClaims{Identifier: "foxmulder"})
	handler.ServeHTTP(res, req.WithContext(ctxWithAuth))
	require.Equal(t, http.StatusOK, res.Result().StatusCode)

	redisRes := redis.ZCount(context.Background(), "sentinel:rate-limit:foxmulder", "-inf", "+inf")
	require.Equal(t, int64(1), redisRes.Val())
}

// RedisWithErrors is a mock redis client that returns errors on every call for
// lua scripts to test the failure scenario
type RedisWithErrors struct {
	calls int
	redis.Cmdable
}

func (r *RedisWithErrors) EvalSha(ctx context.Context, script string, keys []string, args ...interface{}) *redis.Cmd {
	r.calls += 1
	return redis.NewCmdResult(nil, errors.New("oops"))
}

func TestRateLimit_DisconnectedRedis(t *testing.T) {
	rl := &RateLimiter{
		Redis:        &RedisWithErrors{},
		Window:       1 * time.Minute,
		MaxRequests:  3,
		KeyNamespace: "testratelimiter:v1",
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello world"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Result().StatusCode)
}

func TestRateLimit_CircuitBreaker(t *testing.T) {
	b := new(bytes.Buffer)
	logger := slog.New(slog.NewJSONHandler(b, nil))
	badRedis := &RedisWithErrors{}
	rl := &RateLimiter{
		Redis:        badRedis,
		Window:       1 * time.Minute,
		MaxRequests:  3,
		KeyNamespace: "testratelimiter:v1",
		Logger:       logger,
		CircuitBreakerConfig: CircuitBreakerConfig{
			MaxRequests: 1,
			Interval:    time.Second * 5,
			Timeout:     time.Second * 15,
		},
	}

	handler := rl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("hello world"))
	}))

	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		require.Equal(t, http.StatusOK, res.Result().StatusCode)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	require.Equal(t, http.StatusOK, res.Result().StatusCode)
	require.Equal(t, "hello world", res.Body.String())

	require.Equal(t, 5, badRedis.calls)
	require.Contains(t, b.String(), "circuit breaker is open")
}
