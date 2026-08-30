// Package middleware provides Gin middleware for Maigo server.
package middleware

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/security/jwtkeys"
)

// Auth is a middleware that validates JWT tokens
func Auth(cfg *config.Config) gin.HandlerFunc {
	var keyRing *jwtkeys.KeyRing
	var keyRingErr error
	if cfg == nil {
		keyRingErr = fmt.Errorf("jwt configuration is not available")
	} else {
		keyRing, keyRingErr = jwtkeys.NewKeyRing(cfg.JWT)
	}

	return func(c *gin.Context) {
		tokenString, err := extractBearerToken(c)
		if err != nil {
			respondUnauthorized(c, err.Error())
			return
		}

		if keyRingErr != nil {
			respondUnauthorized(c, "Invalid or expired token")
			return
		}

		token, err := validateJWTToken(tokenString, keyRing)
		if err != nil {
			respondUnauthorized(c, "Invalid or expired token")
			return
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			respondUnauthorized(c, "Invalid or expired token")
			return
		}
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
			respondUnauthorized(c, "Access token required")
			return
		}
		if userID, ok := claims["user_id"].(float64); !ok || userID <= 0 || userID != float64(int64(userID)) {
			respondUnauthorized(c, "Invalid token subject")
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

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", fmt.Errorf("invalid authorization header format")
	}

	return parts[1], nil
}

func validateJWTToken(tokenString string, keyRing *jwtkeys.KeyRing) (*jwt.Token, error) {
	return keyRing.Parse(tokenString, jwt.WithIssuer("maigo-oauth2"), jwt.WithAudience("maigo-api"))
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
