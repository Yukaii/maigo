// Package jwtkeys manages Maigo's rotating HMAC signing keys.
package jwtkeys

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/yukaii/maigo/internal/config"
)

const legacyKeyID = "legacy"

// KeyRing signs new tokens with one active key and verifies tokens with the
// active key plus any retained keys from the rotation window.
type KeyRing struct {
	activeKeyID  string
	keys         map[string][]byte
	legacySecret []byte
}

// NewKeyRing builds a key ring from JWT configuration. When no explicit key
// ring is configured, the legacy Secret is used under a stable key ID and
// tokens without a kid remain valid for backwards compatibility.
func NewKeyRing(jwtConfig config.JWTConfig) (*KeyRing, error) {
	if len(jwtConfig.Keys) == 0 {
		secret := strings.TrimSpace(jwtConfig.Secret)
		if secret == "" {
			return nil, fmt.Errorf("jwt secret is not configured")
		}

		return &KeyRing{
			activeKeyID:  legacyKeyID,
			keys:         map[string][]byte{legacyKeyID: []byte(secret)},
			legacySecret: []byte(secret),
		}, nil
	}

	activeKeyID := strings.TrimSpace(jwtConfig.ActiveKeyID)
	if activeKeyID == "" {
		return nil, fmt.Errorf("jwt active key ID is not configured")
	}

	ring := &KeyRing{
		activeKeyID: activeKeyID,
		keys:        make(map[string][]byte, len(jwtConfig.Keys)),
	}
	for _, configuredKey := range jwtConfig.Keys {
		keyID := strings.TrimSpace(configuredKey.ID)
		secret := strings.TrimSpace(configuredKey.Secret)
		if keyID == "" || secret == "" {
			return nil, fmt.Errorf("jwt key ID and secret are required")
		}
		if _, exists := ring.keys[keyID]; exists {
			return nil, fmt.Errorf("jwt key ID %q is duplicated", keyID)
		}
		ring.keys[keyID] = []byte(secret)
	}
	if _, exists := ring.keys[activeKeyID]; !exists {
		return nil, fmt.Errorf("jwt active key ID %q is not configured", activeKeyID)
	}

	// Retain the legacy secret only when it is explicitly configured. This
	// allows a rolling migration from tokens without kid while keeping an
	// explicit key-ring deployment independent of the development fallback.
	if secret := strings.TrimSpace(jwtConfig.Secret); secret != "" {
		ring.legacySecret = []byte(secret)
	}

	return ring, nil
}

// ActiveKeyID returns the key ID used for newly issued tokens.
func (r *KeyRing) ActiveKeyID() string {
	if r == nil {
		return ""
	}
	return r.activeKeyID
}

// Sign creates an HS256 token with the active key and includes its key ID.
func (r *KeyRing) Sign(claims jwt.Claims) (string, error) {
	if r == nil {
		return "", fmt.Errorf("jwt key ring is not configured")
	}
	secret, exists := r.keys[r.activeKeyID]
	if !exists {
		return "", fmt.Errorf("jwt active key ID %q is not configured", r.activeKeyID)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token.Header["kid"] = r.activeKeyID
	return token.SignedString(secret)
}

// Parse validates a token using the key selected by its kid. Tokens without a
// kid are accepted only with the explicitly retained legacy secret.
func (r *KeyRing) Parse(tokenString string, options ...jwt.ParserOption) (*jwt.Token, error) {
	if r == nil {
		return nil, fmt.Errorf("jwt key ring is not configured")
	}

	return jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		keyID, hasKeyID := token.Header["kid"].(string)
		if hasKeyID {
			if strings.TrimSpace(keyID) == "" {
				return nil, fmt.Errorf("jwt key ID cannot be empty")
			}
			secret, exists := r.keys[keyID]
			if !exists {
				return nil, fmt.Errorf("unknown jwt key ID %q", keyID)
			}
			return secret, nil
		}
		if len(r.legacySecret) > 0 {
			return r.legacySecret, nil
		}

		return nil, fmt.Errorf("jwt key ID is required")
	}, options...)
}
