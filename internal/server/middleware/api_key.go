// Package middleware provides Gin middleware for Maigo Core.
package middleware

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/config"
)

// APIKey protects management endpoints with the installation's single API
// key. Both Authorization: Bearer <key> and X-Maigo-API-Key are supported so
// shell scripts and ordinary HTTP clients can use the same API.
func APIKey(cfg *config.Config) gin.HandlerFunc {
	expected := ""
	if cfg != nil {
		expected = cfg.Auth.APIKey
	}

	return func(c *gin.Context) {
		provided := c.GetHeader("X-Maigo-API-Key")
		if provided == "" {
			provided = bearerValue(c.GetHeader("Authorization"))
		}

		providedHash := sha256.Sum256([]byte(provided))
		expectedHash := sha256.Sum256([]byte(expected))
		if expected == "" || subtle.ConstantTimeCompare(providedHash[:], expectedHash[:]) != 1 {
			c.Header("WWW-Authenticate", `Bearer realm="maigo"`)
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "A valid Maigo API key is required",
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

func bearerValue(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}
