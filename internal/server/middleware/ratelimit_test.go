package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRateLimiter_NoRedis(t *testing.T) {
	// Test that middleware works gracefully without Redis (fail-open)
	gin.SetMode(gin.TestMode)

	config := RateLimitConfig{
		Limit:       10,
		Window:      time.Minute,
		RedisClient: nil, // No Redis
		KeyPrefix:   "test",
	}

	middleware := RateLimiter(config)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// All requests should succeed when Redis is not configured
	for i := 0; i < 20; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Request %d should succeed without Redis", i)
	}
}

func TestGetClientID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		setupCtx   func(*gin.Context)
		expectedID string
	}{
		{
			name: "Authenticated user",
			setupCtx: func(c *gin.Context) {
				c.Set("user_id", int64(123))
			},
			expectedID: "user:123",
		},
		{
			name: "Unauthenticated user with IP",
			setupCtx: func(c *gin.Context) {
				// Don't set user_id
			},
			expectedID: "ip:192.0.2.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			c.Request.RemoteAddr = "192.0.2.1:1234"

			tt.setupCtx(c)

			clientID := getClientID(c)
			assert.Contains(t, clientID, tt.expectedID)
		})
	}
}

func TestRateLimitConfig_Defaults(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test that defaults are applied
	config := RateLimitConfig{
		RedisClient: nil,
	}

	middleware := RateLimiter(config)
	assert.NotNil(t, middleware)

	// Verify it returns a valid middleware function
	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPerUserRateLimiter_NoAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimitConfig{
		Limit:       5,
		Window:      time.Minute,
		RedisClient: nil,
	}

	middleware := PerUserRateLimiter(config)

	router := gin.New()
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// Without authentication, all requests should pass through
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Unauthenticated request %d should bypass user rate limiter", i)
	}
}

func TestPerUserRateLimiter_WithAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	config := RateLimitConfig{
		Limit:       5,
		Window:      time.Minute,
		RedisClient: nil, // Without Redis, should fail-open
	}

	middleware := PerUserRateLimiter(config)

	router := gin.New()
	router.Use(func(c *gin.Context) {
		// Simulate authentication
		c.Set("user_id", int64(456))
		c.Next()
	})
	router.Use(middleware)
	router.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "success"})
	})

	// With authentication but no Redis, should still pass through
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code, "Authenticated request %d should succeed without Redis", i)
	}
}
