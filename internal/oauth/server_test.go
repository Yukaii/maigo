package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/security/jwtkeys"
)

func TestGenerateTokenPairUsesActiveSigningKey(t *testing.T) {
	cfg := &config.Config{JWT: config.JWTConfig{
		ActiveKeyID: "primary-2026",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2026", Secret: "primary-oauth-key-that-is-long-enough-123456"},
			{ID: "primary-2025", Secret: "previous-oauth-key-that-is-long-enough-123456"},
		},
		Expiration: time.Hour,
	}}
	server := NewServer(nil, cfg, nil)

	pair, err := server.GenerateTokenPair(context.Background(), &models.User{
		ID:       42,
		Username: "test-user",
		Email:    "test@example.com",
	})
	require.NoError(t, err)

	keyRing, err := jwtkeys.NewKeyRing(cfg.JWT)
	require.NoError(t, err)
	accessToken, err := keyRing.Parse(
		pair.AccessToken,
		jwt.WithIssuer("maigo-oauth2"),
		jwt.WithAudience("maigo-api"),
	)
	require.NoError(t, err)
	assert.True(t, accessToken.Valid)
	assert.Equal(t, "primary-2026", accessToken.Header["kid"])

	refreshToken, err := keyRing.Parse(pair.RefreshToken, jwt.WithIssuer("maigo-oauth2"))
	require.NoError(t, err)
	assert.True(t, refreshToken.Valid)
	assert.Equal(t, "primary-2026", refreshToken.Header["kid"])
}
