package tests

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/server"
)

type testApp struct {
	handler http.Handler
	db      *sql.DB
	key     string
}

func newTestApp(t *testing.T) testApp {
	t.Helper()
	cfg := &config.Config{
		Database: config.DatabaseConfig{Path: filepath.Join(t.TempDir(), "maigo.db")},
		Server:   config.ServerConfig{Host: "127.0.0.1", Port: 8080, ReadTimeout: 30, WriteTimeout: 30, IdleTimeout: 120},
		Auth:     config.AuthConfig{APIKey: "integration-api-key"},
		App:      config.AppConfig{Environment: "test", PublicURL: "http://localhost:8080", ShortCodeLength: 6},
	}
	db, err := database.Connect(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return testApp{
		handler: server.NewHTTPServer(cfg, db, logger.NewLogger(logger.Config{Level: "error", Format: "text"})),
		db:      db,
		key:     cfg.Auth.APIKey,
	}
}

func doRequest(app testApp, method, path string, body []byte, authenticated bool) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if len(body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	if authenticated {
		request.Header.Set("X-Maigo-API-Key", app.key)
	}
	response := httptest.NewRecorder()
	app.handler.ServeHTTP(response, request)
	return response
}

func TestCoreURLLifecycle(t *testing.T) {
	app := newTestApp(t)

	unauthorized := doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://example.com"}`), false)
	assert.Equal(t, http.StatusUnauthorized, unauthorized.Code)

	created := doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://example.com/path","custom":"docs"}`), true)
	require.Equal(t, http.StatusCreated, created.Code)
	var createdPayload map[string]any
	require.NoError(t, json.Unmarshal(created.Body.Bytes(), &createdPayload))
	assert.Equal(t, "docs", createdPayload["short_code"])
	assert.Equal(t, "http://localhost:8080/docs", createdPayload["short_url"])

	duplicate := doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://other.example","custom":"docs"}`), true)
	assert.Equal(t, http.StatusConflict, duplicate.Code)

	metadata := doRequest(app, http.MethodGet, "/api/v1/urls/docs", nil, false)
	require.Equal(t, http.StatusOK, metadata.Code)
	assert.Contains(t, metadata.Body.String(), `"target_url":"https://example.com/path"`)

	redirect := doRequest(app, http.MethodGet, "/docs", nil, false)
	assert.Equal(t, http.StatusFound, redirect.Code)
	assert.Equal(t, "https://example.com/path", redirect.Header().Get("Location"))

	stats := doRequest(app, http.MethodGet, "/api/v1/urls/docs/stats", nil, true)
	require.Equal(t, http.StatusOK, stats.Code)
	assert.Contains(t, stats.Body.String(), `"hits":1`)

	list := doRequest(app, http.MethodGet, "/api/v1/urls?page=1&page_size=10", nil, true)
	require.Equal(t, http.StatusOK, list.Code)
	assert.Contains(t, list.Body.String(), `"total":1`)

	deleted := doRequest(app, http.MethodDelete, "/api/v1/urls/docs", nil, true)
	assert.Equal(t, http.StatusOK, deleted.Code)
	missing := doRequest(app, http.MethodGet, "/docs", nil, false)
	assert.Equal(t, http.StatusNotFound, missing.Code)
}

func TestCoreURLExpiration(t *testing.T) {
	app := newTestApp(t)
	created := doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://example.com","custom":"soon","ttl":60}`), true)
	require.Equal(t, http.StatusCreated, created.Code)
	_, err := app.db.Exec(`UPDATE urls SET expires_at = ? WHERE short_code = ?`, time.Now().Add(-time.Second).UTC().Format(time.RFC3339Nano), "soon")
	require.NoError(t, err)
	expired := doRequest(app, http.MethodGet, "/soon", nil, false)
	assert.Equal(t, http.StatusGone, expired.Code)
	stats := doRequest(app, http.MethodGet, "/api/v1/urls/soon/stats", nil, true)
	require.Equal(t, http.StatusOK, stats.Code)
	assert.Contains(t, stats.Body.String(), `"hits":0`)

	invalid := doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://example.com","ttl":1}`), true)
	assert.Equal(t, http.StatusBadRequest, invalid.Code)

	future := time.Now().Add(-time.Second).UTC().Format(time.RFC3339)
	created = doRequest(app, http.MethodPost, "/api/v1/urls", []byte(`{"url":"https://example.com","custom":"past","expires_at":"`+future+`"}`), true)
	assert.Equal(t, http.StatusBadRequest, created.Code)
}
