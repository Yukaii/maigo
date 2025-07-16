// Package middleware provides Gin middleware for Maigo server.
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/yukaii/maigo/internal/config"
)

// Auth is a middleware that validates JWT tokens
func Auth(cfg *config.Config) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Debug log
		c.Header("X-Debug-Auth", "called")

		tokenString, err := extractBearerToken(c)
		if err != nil {
			respondUnauthorized(c, err.Error())
			return
		}

		token, err := validateJWTToken(tokenString, cfg.JWT.Secret)
		if err != nil {
			respondUnauthorized(c, "Invalid or expired token")
			return
		}

		setUserContextFromClaims(c, token)
		c.Next()
	}
}

func extractBearerToken(c *gin.Context) (string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", fmt.Errorf("authorization header is required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func validateJWTToken(tokenString, secret string) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
}

func respondUnauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, gin.H{
		"error":   "Unauthorized",
		"message": message,
	})
	c.Abort()
}

func setUserContextFromClaims(c *gin.Context, token *jwt.Token) {
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return
	}

	if userID, exists := claims["user_id"]; exists {
		setUserID(c, userID)
	}
	if username, exists := claims["username"]; exists {
		c.Set("username", username)
	}
}

func setUserID(c *gin.Context, userID interface{}) {
	switch v := userID.(type) {
	case float64:
		c.Set("user_id", int64(v))
	case int64:
		c.Set("user_id", v)
	}
}
