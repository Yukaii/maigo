package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
)

func TestHTTPServerCoreRoutes(t *testing.T) {
	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "maigo.db")},
		Server:   config.ServerConfig{Host: "127.0.0.1", Port: 8080, ReadTimeout: 30, WriteTimeout: 30, IdleTimeout: 120},
		Auth:     config.AuthConfig{APIKey: "test-api-key"},
		App:      config.AppConfig{Environment: "test", PublicURL: "http://localhost:8080", ShortCodeLength: 6},
	}
	db, err := database.Connect(cfg)
	require.NoError(t, err)
	defer func() { require.NoError(t, db.Close()) }()

	log := logger.NewLogger(logger.Config{Level: "error", Format: "text"})
	handler := NewHTTPServer(cfg, db, log)

	request := httptest.NewRequest(http.MethodGet, "/health", http.NoBody)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)

	createBody := bytes.NewBufferString(`{"url":"https://example.com","custom":"demo"}`)
	request = httptest.NewRequest(http.MethodPost, "/api/v1/urls", createBody)
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusUnauthorized, response.Code)

	request = httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBufferString(`{"url":"https://example.com","custom":"demo"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Maigo-API-Key", "test-api-key")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	require.Equal(t, http.StatusCreated, response.Code)

	var created map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &created))
	assert.Equal(t, "demo", created["short_code"])

	request = httptest.NewRequest(http.MethodGet, "/demo", http.NoBody)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusFound, response.Code)
	assert.Equal(t, "https://example.com", response.Header().Get("Location"))

	request = httptest.NewRequest(http.MethodGet, "/api/v1/urls/demo/stats", http.NoBody)
	request.Header.Set("Authorization", "Bearer test-api-key")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
	assert.Contains(t, response.Body.String(), `"hits":1`)
}
