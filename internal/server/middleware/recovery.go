// Package middleware provides Gin middleware for Maigo server.
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/logger"
)

// Recovery returns a middleware that recovers from any panics and writes a 500 if there was one.
func Recovery(log *logger.Logger) gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered interface{}) {
		log.Error("Panic recovered",
			"error", recovered,
			"path", c.Request.URL.Path,
			"method", c.Request.Method,
		)

		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "Internal Server Error",
			"message": "An unexpected error occurred",
		})
		c.Abort()
	})
}
