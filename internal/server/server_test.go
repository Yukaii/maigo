package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/server/middleware"
)

func TestHTTPServerCORSUsesConfiguredOrigins(t *testing.T) {
	log := logger.NewLogger(logger.Config{Level: "error", Format: "text"})
	cfg := &config.Config{
		App: config.AppConfig{
			CORSEnabled: true,
			CORSOrigins: "https://console.example.com, https://admin.example.com",
		},
	}
	server := NewHTTPServer(cfg, nil, log)

	allowedRequest := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	allowedRequest.Header.Set("Origin", "https://console.example.com")
	allowedResponse := httptest.NewRecorder()
	server.ServeHTTP(allowedResponse, allowedRequest)

	require.Equal(t, http.StatusOK, allowedResponse.Code)
	assert.Equal(t, "https://console.example.com", allowedResponse.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", allowedResponse.Header().Get("Access-Control-Allow-Credentials"))

	blockedRequest := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	blockedRequest.Header.Set("Origin", "https://untrusted.example.com")
	blockedResponse := httptest.NewRecorder()
	server.ServeHTTP(blockedResponse, blockedRequest)

	require.Equal(t, http.StatusForbidden, blockedResponse.Code)
	assert.Empty(t, blockedResponse.Header().Get("Access-Control-Allow-Origin"))
}

func TestHTTPServerCORSAllowsWildcardOnlyInDebug(t *testing.T) {
	log := logger.NewLogger(logger.Config{Level: "error", Format: "text"})
	cfg := &config.Config{
		App: config.AppConfig{
			Debug:       true,
			CORSEnabled: true,
		},
	}
	server := NewHTTPServer(cfg, nil, log)

	request := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	request.Header.Set("Origin", "https://localhost.example")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, response.Header().Get("Access-Control-Allow-Credentials"))
}

func TestHTTPServerDoesNotTrustForwardedIPByDefault(t *testing.T) {
	log := logger.NewLogger(logger.Config{Level: "error", Format: "text"})
	cfg := &config.Config{
		App: config.AppConfig{
			RateLimit: config.RateLimitConfig{Requests: 1, Window: time.Hour},
		},
	}
	server := NewHTTPServer(cfg, nil, log)
	server.engine.GET("/proxy-test/limit", middleware.RateLimit(cfg.App.RateLimit), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	first := serveProxyTestRequest(server, "198.51.100.1")
	second := serveProxyTestRequest(server, "198.51.100.2")

	assert.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
}

func TestHTTPServerUsesConfiguredTrustedProxy(t *testing.T) {
	log := logger.NewLogger(logger.Config{Level: "error", Format: "text"})
	cfg := &config.Config{
		App: config.AppConfig{
			TrustedProxies: "10.0.0.0/8",
			RateLimit:      config.RateLimitConfig{Requests: 1, Window: time.Hour},
		},
	}
	server := NewHTTPServer(cfg, nil, log)
	server.engine.GET("/proxy-test/limit", middleware.RateLimit(cfg.App.RateLimit), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	first := serveProxyTestRequest(server, "198.51.100.1")
	second := serveProxyTestRequest(server, "198.51.100.2")

	assert.Equal(t, http.StatusOK, first.Code)
	assert.Equal(t, http.StatusOK, second.Code)
}

func serveProxyTestRequest(server *HTTPServer, forwardedFor string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodGet, "/proxy-test/limit", http.NoBody)
	request.RemoteAddr = "10.0.0.1:1000"
	request.Header.Set("X-Forwarded-For", forwardedFor)
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	return response
}
