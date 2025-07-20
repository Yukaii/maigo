// Package handlers provides HTTP error helpers for Maigo API endpoints.
package handlers

import (
	"github.com/gin-gonic/gin"
)

// SendAPIError sends a standardized JSON error response.
func SendAPIError(c *gin.Context, httpStatus int, code, message string, details interface{}) {
	resp := gin.H{
		"error":   code,
		"message": message,
		"details": details,
	}
	c.JSON(httpStatus, resp)
}
