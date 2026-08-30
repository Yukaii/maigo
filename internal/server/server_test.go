package server

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
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

	allowedRequest := httptest.NewRequest(http.MethodGet, "/health", nil)
	allowedRequest.Header.Set("Origin", "https://console.example.com")
	allowedResponse := httptest.NewRecorder()
	server.ServeHTTP(allowedResponse, allowedRequest)

	require.Equal(t, http.StatusOK, allowedResponse.Code)
	assert.Equal(t, "https://console.example.com", allowedResponse.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", allowedResponse.Header().Get("Access-Control-Allow-Credentials"))

	blockedRequest := httptest.NewRequest(http.MethodGet, "/health", nil)
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

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set("Origin", "https://localhost.example")
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "*", response.Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, response.Header().Get("Access-Control-Allow-Credentials"))
}
