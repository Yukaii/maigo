package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const RequestIDHeader = "X-Request-ID"

// RequestID is a middleware that adds a unique request ID to each request
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID already exists in header
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			// Generate new UUID if not present
			requestID = uuid.New().String()
		}

		// Set request ID in context and response header
		c.Set("request_id", requestID)
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
}
