package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
)

func TestAPIClientUsesCoreAPIKeyAndDecodesResponses(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		assert.Equal(t, "Bearer client-secret", request.Header.Get("Authorization"))
		assert.Equal(t, "/api/v1/urls", request.URL.Path)
		assert.Equal(t, http.MethodPost, request.Method)
		writer.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(writer).Encode(map[string]any{
			"short_code": "demo", "short_url": "http://sho.rt/demo",
			"target_url": "https://example.com", "hits": 0,
		}); err != nil {
			t.Errorf("encode test response: %v", err)
		}
	}))
	defer server.Close()

	cfg := &config.Config{App: config.AppConfig{PublicURL: server.URL}, Auth: config.AuthConfig{APIKey: "client-secret"}}
	response, err := NewAPIClient(cfg).CreateShortURL("https://example.com", "demo", 0)
	require.NoError(t, err)
	assert.Equal(t, "demo", response["short_code"])
	assert.Equal(t, "https://example.com", response["target_url"])
}
