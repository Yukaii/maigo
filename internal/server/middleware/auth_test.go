package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/security/jwtkeys"
)

const (
	previousAuthKey = "previous-auth-key-that-is-long-enough-123456"
	currentAuthKey  = "current-auth-key-that-is-long-enough-123456"
)

func TestAuthAcceptsTokenSignedByRetainedKey(t *testing.T) {
	previousRing, err := jwtkeys.NewKeyRing(config.JWTConfig{
		ActiveKeyID: "previous",
		Keys: []config.JWTKeyConfig{
			{ID: "previous", Secret: previousAuthKey},
		},
	})
	require.NoError(t, err)
	tokenString, err := previousRing.Sign(jwt.MapClaims{
		"user_id": 7,
		"type":    "access",
		"iss":     "maigo-oauth2",
		"aud":     "maigo-api",
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(Auth(&config.Config{JWT: config.JWTConfig{
		ActiveKeyID: "current",
		Keys: []config.JWTKeyConfig{
			{ID: "current", Secret: currentAuthKey},
			{ID: "previous", Secret: previousAuthKey},
		},
	}}))
	router.GET("/protected", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusNoContent, response.Code)
}

func TestAuthRejectsTokenSignedByRetiredKey(t *testing.T) {
	retiredRing, err := jwtkeys.NewKeyRing(config.JWTConfig{
		ActiveKeyID: "retired",
		Keys: []config.JWTKeyConfig{
			{ID: "retired", Secret: previousAuthKey},
		},
	})
	require.NoError(t, err)
	tokenString, err := retiredRing.Sign(jwt.MapClaims{
		"user_id": 7,
		"type":    "access",
		"iss":     "maigo-oauth2",
		"aud":     "maigo-api",
	})
	require.NoError(t, err)

	router := gin.New()
	router.Use(Auth(&config.Config{JWT: config.JWTConfig{
		ActiveKeyID: "current",
		Keys: []config.JWTKeyConfig{
			{ID: "current", Secret: currentAuthKey},
		},
	}}))
	router.GET("/protected", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	request := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	request.Header.Set("Authorization", "Bearer "+tokenString)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	assert.Equal(t, http.StatusUnauthorized, response.Code)
}
