package jwtkeys

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/config"
)

const (
	oldJWTKeySecret = "old-key-secret-that-is-long-enough-123456"
	newJWTKeySecret = "new-key-secret-that-is-long-enough-123456"
)

func TestKeyRingSignsWithActiveKeyID(t *testing.T) {
	ring, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "primary-2026",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2026", Secret: newJWTKeySecret},
			{ID: "primary-2025", Secret: oldJWTKeySecret},
		},
	})
	require.NoError(t, err)

	tokenString, err := ring.Sign(jwt.MapClaims{"subject": "test"})
	require.NoError(t, err)

	parsed, err := ring.Parse(tokenString)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Equal(t, "primary-2026", parsed.Header["kid"])
	assert.Equal(t, "primary-2026", ring.ActiveKeyID())
}

func TestKeyRingRetainsOldKeyDuringRotation(t *testing.T) {
	oldRing, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "primary-2025",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2025", Secret: oldJWTKeySecret},
		},
	})
	require.NoError(t, err)
	oldToken, err := oldRing.Sign(jwt.MapClaims{"subject": "before-rotation"})
	require.NoError(t, err)

	rotatedRing, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "primary-2026",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2026", Secret: newJWTKeySecret},
			{ID: "primary-2025", Secret: oldJWTKeySecret},
		},
	})
	require.NoError(t, err)

	parsed, err := rotatedRing.Parse(oldToken)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	newToken, err := rotatedRing.Sign(jwt.MapClaims{"subject": "after-rotation"})
	require.NoError(t, err)
	assert.NotEqual(t, oldToken, newToken)
	assert.Equal(t, "primary-2026", mustParseHeaderKeyID(t, newToken, rotatedRing))
}

func TestKeyRingSupportsLegacyNoKeyIDTokensOnlyWithExplicitSecret(t *testing.T) {
	legacyToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"subject": "legacy"})
	legacyTokenString, err := legacyToken.SignedString([]byte(oldJWTKeySecret))
	require.NoError(t, err)

	withLegacySecret, err := NewKeyRing(config.JWTConfig{
		Secret:      oldJWTKeySecret,
		ActiveKeyID: "primary-2026",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2026", Secret: newJWTKeySecret},
		},
	})
	require.NoError(t, err)
	parsed, err := withLegacySecret.Parse(legacyTokenString)
	require.NoError(t, err)
	assert.True(t, parsed.Valid)

	withoutLegacySecret, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "primary-2026",
		Keys: []config.JWTKeyConfig{
			{ID: "primary-2026", Secret: newJWTKeySecret},
		},
	})
	require.NoError(t, err)
	_, err = withoutLegacySecret.Parse(legacyTokenString)
	assert.Error(t, err)
}

func TestKeyRingRejectsUnknownKeyID(t *testing.T) {
	retiredRing, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "retired",
		Keys: []config.JWTKeyConfig{
			{ID: "retired", Secret: oldJWTKeySecret},
		},
	})
	require.NoError(t, err)
	retiredToken, err := retiredRing.Sign(jwt.MapClaims{"subject": "retired"})
	require.NoError(t, err)

	currentRing, err := NewKeyRing(config.JWTConfig{
		ActiveKeyID: "current",
		Keys: []config.JWTKeyConfig{
			{ID: "current", Secret: newJWTKeySecret},
		},
	})
	require.NoError(t, err)
	_, err = currentRing.Parse(retiredToken)
	assert.Error(t, err)
}

func mustParseHeaderKeyID(t *testing.T, tokenString string, ring *KeyRing) string {
	t.Helper()
	parsed, err := ring.Parse(tokenString)
	require.NoError(t, err)
	keyID, ok := parsed.Header["kid"].(string)
	require.True(t, ok)
	return keyID
}
