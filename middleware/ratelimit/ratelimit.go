package ratelimit

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/blakewilliams/sentinel"
	"github.com/redis/go-redis/v9"
	"github.com/sony/gobreaker/v2"
)

var DefaultKeyNamespace = "sentinel:rate-limit"

// RateLimiter is a middleware for rate limiting requests via Sentinel. It is
// redis backed and uses a sliding window algorithm to count requests. It additionally
// includes a circuit breaker to prevent excessive requests from hitting the
// Redis backend.
type RateLimiter struct {
	Redis redis.Cmdable
	// Window is the time window for the rate limiter to count requests.
	// This is a sliding window that will expire after the duration has
	// passed.
	Window time.Duration
	// MaxRequests is the maximum number of requests that can be made
	// within the window.
	MaxRequests int
	// KeyNamespace is the namespace for the keys in Redis.
	KeyNamespace string
	// Logger is the logger to use for logging rate limit exceeded errors.
	Logger *slog.Logger
	// CircuitBreakerConfig is the configuration for the circuit breaker
	// used in the rate limiter middleware.
	CircuitBreakerConfig CircuitBreakerConfig
}

// CircuitBreakerConfig is a configuration struct for the circuit breaker
// used in the rate limiter middleware.
//
// This is a lightweight wrapper around gobreaker.Settings.
type CircuitBreakerConfig struct {
	// MaxRequests is the number of requests that can be made while the
	// circuit breaker is half-open
	MaxRequests uint32
	// Interval is the time interval for the circuit breaker to clear
	// the request count.
	Interval time.Duration
	// Timeout is the duration of time the circuit breaker will remain in the
	// open state before it becomes half-open
	Timeout time.Duration
}

var luaScript = redis.NewScript(`local key = KEYS[1]
local window = tonumber(ARGV[1])
local now = redis.call("TIME")
local window_start = tonumber(now[1]) - window
local max_requests = tonumber(ARGV[2])

redis.call('ZREMRANGEBYSCORE', key, '0', window_start)
local request_count = redis.call('ZCARD', key)

if request_count < tonumber(max_requests) then
	redis.call('ZADD', key, now[1], now[1] .. now[2])
	redis.call('EXPIRE', key, window)
	return 0
end

return 1
`)

// Middleware is the http.Handler middleware that can be used with
// Sentinel to rate limit requests.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if rl.KeyNamespace == "" {
		rl.KeyNamespace = DefaultKeyNamespace
	}

	if rl.Logger == nil {
		rl.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	if rl.Window == 0 {
		rl.Window = 1 * time.Minute
	}

	breakerSettings := gobreaker.Settings{
		Name:        "sentinel-rate-limiter",
		MaxRequests: 1,
		Interval:    30 * time.Second,
		Timeout:     5 * time.Second,
	}

	if rl.CircuitBreakerConfig.MaxRequests > 0 {
		breakerSettings.MaxRequests = uint32(rl.CircuitBreakerConfig.MaxRequests)
	}

	if rl.CircuitBreakerConfig.Interval > 0 {
		breakerSettings.Interval = rl.CircuitBreakerConfig.Interval
	}

	if rl.CircuitBreakerConfig.Timeout > 0 {
		breakerSettings.Timeout = rl.CircuitBreakerConfig.Timeout
	}

	breakerSettings.OnStateChange = func(name string, from gobreaker.State, to gobreaker.State) {
		rl.Logger.Info("circuit breaker state change", "name", name, "from", from, "to", to)
	}

	breakerSettings.ReadyToTrip = func(counts gobreaker.Counts) bool {
		ratio := float64(counts.TotalFailures) / float64(counts.Requests)
		return counts.Requests >= 5 && ratio >= 0.5
	}

	breakerSettings.IsSuccessful = func(err error) bool {
		return false
	}

	breaker := gobreaker.NewCircuitBreaker[bool](breakerSettings)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if auth, ok := sentinel.GetAuth[sentinel.IdentifiableClaims](r.Context()); ok {
			key = auth.IdentifierValue()
		}

		allowed, err := breaker.Execute(func() (bool, error) {
			res := luaScript.Run(
				r.Context(),
				rl.Redis,
				[]string{
					fmt.Sprintf("%s:%s", rl.KeyNamespace, key),
				},
				[]string{
					strconv.FormatFloat(rl.Window.Seconds(), 'f', -1, 64),
					strconv.Itoa(rl.MaxRequests),
				},
			)

			// If there was an error running the script, log it and continue
			// with the request. This fails closed so we don't disrupt access
			// to the underlying backends.
			if res.Err() != nil {
				return true, res.Err()
			}

			return res.Val().(int64) == 0, nil
		})

		// If there was an error running the script, log it and continue
		// with the request. This fails closed so we don't disrupt access
		// to the underlying backends.
		if err != nil {
			rl.Logger.Error("error running rate limit script", "error", err, "identifier", key)
			next.ServeHTTP(w, r)
			return
		}

		if allowed {
			next.ServeHTTP(w, r)
			return
		}

		rl.Logger.Error("rate limit exceeded", "identifier", key)
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	})
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

	ip := strings.Split(r.RemoteAddr, ":")[0]

	return ip
}
