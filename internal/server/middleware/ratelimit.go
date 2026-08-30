// Package middleware provides HTTP middleware for the Maigo server.
package middleware

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitConfig holds the settings for a Redis-backed rate limiter.
type RateLimitConfig struct {
	// Requests per window.
	Limit int
	// Window duration.
	Window time.Duration
	// Redis client.
	RedisClient *redis.Client
	// Key prefix for Redis.
	KeyPrefix string
	// FailOpen allows requests through when Redis is unavailable. The secure
	// default is false, so explicitly enabled distributed limiting cannot be
	// silently bypassed during a Redis outage.
	FailOpen bool
}

var fixedWindowScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {count, ttl}
`)

// RateLimiter creates an atomic fixed-window rate limiter backed by Redis.
// Requests are identified by the authenticated user when available and by
// client IP otherwise.
func RateLimiter(config RateLimitConfig) gin.HandlerFunc {
	if config.RedisClient == nil || config.Limit <= 0 || config.Window <= 0 {
		return passThrough()
	}
	if config.KeyPrefix == "" {
		config.KeyPrefix = "ratelimit"
	}

	return redisRateLimiter(config, func(c *gin.Context) string {
		return getClientID(c)
	})
}

func redisRateLimiter(config RateLimitConfig, identifier func(*gin.Context) string) gin.HandlerFunc {
	windowMillis := config.Window.Milliseconds()
	if windowMillis < 1 {
		windowMillis = 1
	}

	return func(c *gin.Context) {
		key := fmt.Sprintf("%s:%s", config.KeyPrefix, identifier(c))
		result, err := fixedWindowScript.Run(
			c.Request.Context(),
			config.RedisClient,
			[]string{key},
			windowMillis,
		).Result()
		if err != nil {
			if config.FailOpen {
				c.Next()
				return
			}
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "rate_limit_unavailable",
				"message": "Request protection is temporarily unavailable. Please try again later.",
			})
			c.Abort()
			return
		}

		count, ttl, err := parseRateLimitResult(result, config.Window)
		if err != nil {
			if config.FailOpen {
				c.Next()
				return
			}
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"error":   "rate_limit_unavailable",
				"message": "Request protection is temporarily unavailable. Please try again later.",
			})
			c.Abort()
			return
		}

		remaining := config.Limit - int(count)
		if remaining < 0 {
			remaining = 0
		}
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(ttl).Unix(), 10))

		if count > int64(config.Limit) {
			retryAfter := int(math.Ceil(ttl.Seconds()))
			if retryAfter < 1 {
				retryAfter = 1
			}
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
				"details": gin.H{
					"limit":       config.Limit,
					"window":      config.Window.String(),
					"retry_after": retryAfter,
				},
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func parseRateLimitResult(result interface{}, fallbackWindow time.Duration) (int64, time.Duration, error) {
	values, ok := result.([]interface{})
	if !ok || len(values) != 2 {
		return 0, 0, fmt.Errorf("unexpected Redis rate-limit result")
	}

	count, err := redisInt64(values[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid Redis rate-limit count: %w", err)
	}
	ttlMillis, err := redisInt64(values[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid Redis rate-limit TTL: %w", err)
	}

	ttl := time.Duration(ttlMillis) * time.Millisecond
	if ttlMillis <= 0 || ttl <= 0 {
		ttl = fallbackWindow
	}

	return count, ttl, nil
}

func redisInt64(value interface{}) (int64, error) {
	switch value := value.(type) {
	case int64:
		return value, nil
	case int:
		return int64(value), nil
	case string:
		return strconv.ParseInt(value, 10, 64)
	case []byte:
		return strconv.ParseInt(string(value), 10, 64)
	default:
		return 0, fmt.Errorf("unexpected value type %T", value)
	}
}

func passThrough() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}

// getClientID extracts a stable identifier for the client.
func getClientID(c *gin.Context) string {
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%v", userID)
	}

	return fmt.Sprintf("ip:%s", c.ClientIP())
}

// PerUserRateLimiter creates a rate limiter that only applies to authenticated users.
func PerUserRateLimiter(config RateLimitConfig) gin.HandlerFunc {
	config.KeyPrefix = "ratelimit:user"
	limiter := RateLimiter(config)

	return func(c *gin.Context) {
		if _, exists := c.Get("user_id"); exists {
			limiter(c)
			return
		}
		c.Next()
	}
}

// GlobalRateLimiter creates a rate limiter for all requests using one Redis key.
func GlobalRateLimiter(config RateLimitConfig) gin.HandlerFunc {
	config.KeyPrefix = "ratelimit:global"
	if config.RedisClient == nil || config.Limit <= 0 || config.Window <= 0 {
		return passThrough()
	}
	return redisRateLimiter(config, func(*gin.Context) string {
		return "all"
	})
}
