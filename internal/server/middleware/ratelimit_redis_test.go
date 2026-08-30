package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRateLimiter_RedisAtomic(t *testing.T) {
	redisURL := os.Getenv("MAIGO_TEST_REDIS_URL")
	if redisURL == "" {
		t.Skip("set MAIGO_TEST_REDIS_URL to run the Redis-backed integration test")
	}

	options, err := redis.ParseURL(redisURL)
	require.NoError(t, err)
	client := redis.NewClient(options)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Ping(context.Background()).Err())

	keyPrefix := fmt.Sprintf("maigo:test:%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_ = client.Del(context.Background(), keyPrefix+":ip:192.0.2.1").Err()
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(RateLimiter(RateLimitConfig{
		Limit:       3,
		Window:      time.Minute,
		RedisClient: client,
		KeyPrefix:   keyPrefix,
	}))
	router.GET("/test", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	var accepted atomic.Int32
	var waitGroup sync.WaitGroup
	for i := 0; i < 20; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			request := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			request.RemoteAddr = "192.0.2.1:1000"
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code == http.StatusOK {
				accepted.Add(1)
			}
		}()
	}
	waitGroup.Wait()

	assert.Equal(t, int32(3), accepted.Load())
}

func TestRateLimiter_RedisFailurePolicy(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, test := range []struct {
		name     string
		failOpen bool
		status   int
	}{
		{name: "fail closed", status: http.StatusServiceUnavailable},
		{name: "fail open", failOpen: true, status: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
			require.NoError(t, client.Close())

			router := gin.New()
			router.Use(RateLimiter(RateLimitConfig{
				Limit:       10,
				Window:      time.Minute,
				RedisClient: client,
				KeyPrefix:   "maigo:test:failure",
				FailOpen:    test.failOpen,
			}))
			router.GET("/test", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			request := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)

			assert.Equal(t, test.status, response.Code)
		})
	}
}
