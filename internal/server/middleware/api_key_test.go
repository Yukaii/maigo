package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/yukaii/maigo/internal/config"
)

func TestAPIKeyAcceptsSupportedHeadersAndRejectsInvalidKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := &config.Config{Auth: config.AuthConfig{APIKey: "secret"}}
	engine := gin.New()
	engine.GET("/protected", APIKey(cfg), func(c *gin.Context) { c.Status(http.StatusNoContent) })

	tests := []struct {
		name   string
		header string
		value  string
		status int
	}{
		{name: "x maigo api key", header: "X-Maigo-API-Key", value: "secret", status: http.StatusNoContent},
		{name: "bearer api key", header: "Authorization", value: "Bearer secret", status: http.StatusNoContent},
		{name: "wrong key", header: "X-Maigo-API-Key", value: "wrong", status: http.StatusUnauthorized},
		{name: "missing key", status: http.StatusUnauthorized},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			if test.header != "" {
				request.Header.Set(test.header, test.value)
			}
			response := httptest.NewRecorder()
			engine.ServeHTTP(response, request)
			assert.Equal(t, test.status, response.Code)
		})
	}
}
