// Package middleware provides HTTP middleware for the Maigo server.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	// Requests per window
	Limit int
	// Window duration
	Window time.Duration
	// Redis client
	RedisClient *redis.Client
	// Key prefix for Redis
	KeyPrefix string
}

// RateLimiter creates a rate limiting middleware
func RateLimiter(config RateLimitConfig) gin.HandlerFunc {
	if config.RedisClient == nil {
		// If Redis is not configured, return a no-op middleware
		return func(c *gin.Context) {
			c.Next()
		}
	}

	if config.Limit == 0 {
		config.Limit = 100 // Default: 100 requests
	}

	if config.Window == 0 {
		config.Window = time.Minute // Default: per minute
	}

	if config.KeyPrefix == "" {
		config.KeyPrefix = "ratelimit"
	}

	return func(c *gin.Context) {
		// Get client identifier (IP or user ID)
		clientID := getClientID(c)
		key := fmt.Sprintf("%s:%s", config.KeyPrefix, clientID)

		ctx := context.Background()

		// Get current count
		count, err := config.RedisClient.Get(ctx, key).Int()
		if err != nil && err != redis.Nil {
			// Redis error - fail open (allow request)
			c.Next()
			return
		}

		// Check if limit exceeded
		if count >= config.Limit {
			// Get TTL to inform client when to retry
			ttl, _ := config.RedisClient.TTL(ctx, key).Result() //nolint:errcheck // TTL error is non-critical

			c.Header("X-RateLimit-Limit", strconv.Itoa(config.Limit))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(ttl).Unix(), 10))
			c.Header("Retry-After", strconv.Itoa(int(ttl.Seconds())))

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
				"details": gin.H{
					"limit":       config.Limit,
					"window":      config.Window.String(),
					"retry_after": int(ttl.Seconds()),
				},
			})
			c.Abort()
			return
		}

		// Increment counter
		pipe := config.RedisClient.Pipeline()
		incr := pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, config.Window)
		_, err = pipe.Exec(ctx)

		if err != nil {
			// Redis error - fail open (allow request)
			c.Next()
			return
		}

		newCount := int(incr.Val())
		remaining := config.Limit - newCount
		if remaining < 0 {
			remaining = 0
		}

		// Set rate limit headers
		c.Header("X-RateLimit-Limit", strconv.Itoa(config.Limit))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(config.Window).Unix(), 10))

		c.Next()
	}
}

// getClientID extracts a unique identifier for the client
func getClientID(c *gin.Context) string {
	// First, try to get user ID from context (if authenticated)
	if userID, exists := c.Get("user_id"); exists {
		return fmt.Sprintf("user:%v", userID)
	}

	// Fall back to IP address
	clientIP := c.ClientIP()
	return fmt.Sprintf("ip:%s", clientIP)
}

// PerUserRateLimiter creates a rate limiter that only applies to authenticated users
func PerUserRateLimiter(config RateLimitConfig) gin.HandlerFunc {
	config.KeyPrefix = "ratelimit:user"
	limiter := RateLimiter(config)

	return func(c *gin.Context) {
		// Only apply rate limiting if user is authenticated
		if _, exists := c.Get("user_id"); exists {
			limiter(c)
		} else {
			c.Next()
		}
	}
}

// GlobalRateLimiter creates a global rate limiter for all requests
func GlobalRateLimiter(config RateLimitConfig) gin.HandlerFunc {
	config.KeyPrefix = "ratelimit:global"

	return func(c *gin.Context) {
		// Use a fixed key for global rate limiting
		key := fmt.Sprintf("%s:all", config.KeyPrefix)
		ctx := context.Background()

		count, err := config.RedisClient.Get(ctx, key).Int()
		if err != nil && err != redis.Nil {
			c.Next()
			return
		}

		if count >= config.Limit {
			ttl, _ := config.RedisClient.TTL(ctx, key).Result() //nolint:errcheck // TTL error is non-critical

			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Global rate limit exceeded. Please try again later.",
				"details": gin.H{
					"limit":       config.Limit,
					"window":      config.Window.String(),
					"retry_after": int(ttl.Seconds()),
				},
			})
			c.Abort()
			return
		}

		pipe := config.RedisClient.Pipeline()
		pipe.Incr(ctx, key)
		pipe.Expire(ctx, key, config.Window)
		//nolint:errcheck // Pipeline errors are handled earlier
		_, _ = pipe.Exec(ctx)

		c.Next()
	}
}
