package middleware

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yukaii/maigo/internal/config"
	"golang.org/x/time/rate"
)

// RateLimit creates a rate limiting middleware
func RateLimit(rateLimitConfig config.RateLimitConfig) gin.HandlerFunc {
	// Create a rate limiter
	// This is a simple global rate limiter - in production you'd want per-IP limiting
	limiter := rate.NewLimiter(
		rate.Every(rateLimitConfig.Window/time.Duration(rateLimitConfig.Requests)),
		rateLimitConfig.Requests,
	)

	return func(c *gin.Context) {
		if !limiter.Allow() {
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "Rate Limit Exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}
