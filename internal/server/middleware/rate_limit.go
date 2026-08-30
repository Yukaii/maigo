// Package middleware provides Gin middleware for Maigo server.
package middleware

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/yukaii/maigo/internal/config"
)

type localRateLimitVisitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimit creates a rate limiting middleware
func RateLimit(rateLimitConfig config.RateLimitConfig) gin.HandlerFunc {
	if rateLimitConfig.Requests <= 0 || rateLimitConfig.Window <= 0 {
		// Treat a non-positive configuration as disabled instead of allowing
		// rate.Every to divide by zero or constructing an unusable limiter.
		return func(c *gin.Context) {
			c.Next()
		}
	}

	interval := rateLimitConfig.Window / time.Duration(rateLimitConfig.Requests)
	if interval <= 0 {
		interval = time.Nanosecond
	}

	// Keep a bounded per-client store. A single global bucket lets one caller
	// starve every other caller, while an unbounded map would be an easy memory
	// exhaustion target.
	const maxVisitors = 10_000
	visitors := make(map[string]*localRateLimitVisitor)
	var visitorsMu sync.Mutex

	return func(c *gin.Context) {
		clientID := getClientID(c)
		now := time.Now()

		visitorsMu.Lock()
		v, exists := visitors[clientID]
		if !exists {
			if len(visitors) >= maxVisitors {
				evictOldestVisitor(visitors)
			}
			v = &localRateLimitVisitor{
				limiter: rate.NewLimiter(
					rate.Every(interval),
					rateLimitConfig.Requests,
				),
			}
			visitors[clientID] = v
		}
		v.lastSeen = now
		allowed := v.limiter.Allow()
		visitorsMu.Unlock()

		if !allowed {
			c.Header("X-RateLimit-Limit", strconv.Itoa(rateLimitConfig.Requests))
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests. Please try again later.",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func evictOldestVisitor(visitors map[string]*localRateLimitVisitor) {
	var oldestKey string
	var oldest time.Time
	for key, visitor := range visitors {
		if oldestKey == "" || visitor.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = visitor.lastSeen
		}
	}
	if oldestKey != "" {
		delete(visitors, oldestKey)
	}
}
