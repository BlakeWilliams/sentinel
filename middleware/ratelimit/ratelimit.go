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
)

var DefaultKeyNamespace = "sentinel:rate-limit"

// RateLimiter is a middleware for rate limiting requests via Sentinel.
type RateLimiter struct {
	redis        redis.Cmdable
	Window       time.Duration
	MaxRequests  int
	KeyNamespace string
	Logger       *slog.Logger
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

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	if rl.KeyNamespace == "" {
		rl.KeyNamespace = DefaultKeyNamespace
	}

	if rl.Logger == nil {
		rl.Logger = slog.New(slog.NewJSONHandler(io.Discard, nil))
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := clientIP(r)
		if auth, ok := sentinel.GetAuth[sentinel.IdentifiableClaims](r.Context()); ok {
			key = auth.IdentifierValue()
		}

		res := luaScript.Run(
			r.Context(),
			rl.redis,
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
			rl.Logger.Error("error running rate limit script", "error", res.Err().Error())
			next.ServeHTTP(w, r)
			return
		}

		if res.Val().(int64) == 0 {
			next.ServeHTTP(w, r)
			return
		}

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
