package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
)

// PKCEParams holds PKCE parameters for OAuth 2.0 authorization code flow
type PKCEParams struct {
	CodeVerifier        string `json:"code_verifier"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
}

const (
	// PKCEMethodS256 uses SHA256 for code challenge (recommended)
	PKCEMethodS256 = "S256"
	// PKCEMethodPlain uses plain text for code challenge (not recommended)
	PKCEMethodPlain = "plain"
	
	// CodeVerifierMinLength minimum length for code verifier
	CodeVerifierMinLength = 43
	// CodeVerifierMaxLength maximum length for code verifier  
	CodeVerifierMaxLength = 128
)

// GeneratePKCEParams generates PKCE parameters for OAuth 2.0 authorization code flow
func GeneratePKCEParams() (*PKCEParams, error) {
	// Generate cryptographically random code verifier
	codeVerifier, err := generateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}
	
	// Create code challenge using S256 method
	codeChallenge, err := createCodeChallenge(codeVerifier, PKCEMethodS256)
	if err != nil {
		return nil, fmt.Errorf("failed to create code challenge: %w", err)
	}
	
	return &PKCEParams{
		CodeVerifier:        codeVerifier,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: PKCEMethodS256,
	}, nil
}

// generateCodeVerifier creates a cryptographically random code verifier
// Following RFC 7636 recommendations: 32-octet sequence base64url-encoded = 43 chars
func generateCodeVerifier() (string, error) {
	// Create 32-byte random sequence for high entropy (256 bits)
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	
	// Base64url encode to create URL-safe string
	codeVerifier := base64.RawURLEncoding.EncodeToString(randomBytes)
	
	// Ensure length is within RFC 7636 requirements
	if len(codeVerifier) < CodeVerifierMinLength || len(codeVerifier) > CodeVerifierMaxLength {
		return "", fmt.Errorf("generated code verifier length %d is outside valid range [%d, %d]",
			len(codeVerifier), CodeVerifierMinLength, CodeVerifierMaxLength)
	}
	
	return codeVerifier, nil
}

// createCodeChallenge creates code challenge from code verifier using specified method
func createCodeChallenge(codeVerifier, method string) (string, error) {
	switch method {
	case PKCEMethodS256:
		// SHA256 hash the code verifier and base64url encode
		hash := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(hash[:]), nil
		
	case PKCEMethodPlain:
		// Plain method: code challenge = code verifier
		return codeVerifier, nil
		
	default:
		return "", fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// VerifyCodeChallenge verifies that code verifier matches the stored code challenge
func VerifyCodeChallenge(codeVerifier, codeChallenge, method string) bool {
	if codeVerifier == "" || codeChallenge == "" {
		return false
	}
	
	// Recreate code challenge from verifier
	computedChallenge, err := createCodeChallenge(codeVerifier, method)
	if err != nil {
		return false
	}
	
	// Compare with stored challenge
	return computedChallenge == codeChallenge
}

// ValidateCodeVerifier validates code verifier format according to RFC 7636
func ValidateCodeVerifier(codeVerifier string) error {
	if len(codeVerifier) < CodeVerifierMinLength {
		return fmt.Errorf("code verifier too short: %d < %d", len(codeVerifier), CodeVerifierMinLength)
	}
	
	if len(codeVerifier) > CodeVerifierMaxLength {
		return fmt.Errorf("code verifier too long: %d > %d", len(codeVerifier), CodeVerifierMaxLength)
	}
	
	// Check if contains only unreserved characters: A-Z / a-z / 0-9 / "-" / "." / "_" / "~"
	for _, char := range codeVerifier {
		if !isUnreservedChar(char) {
			return fmt.Errorf("code verifier contains invalid character: %c", char)
		}
	}
	
	return nil
}

// ValidateCodeChallenge validates code challenge format
func ValidateCodeChallenge(codeChallenge string) error {
	if len(codeChallenge) < CodeVerifierMinLength {
		return fmt.Errorf("code challenge too short: %d < %d", len(codeChallenge), CodeVerifierMinLength)
	}
	
	if len(codeChallenge) > CodeVerifierMaxLength {
		return fmt.Errorf("code challenge too long: %d > %d", len(codeChallenge), CodeVerifierMaxLength)
	}
	
	// Check if contains only unreserved characters
	for _, char := range codeChallenge {
		if !isUnreservedChar(char) {
			return fmt.Errorf("code challenge contains invalid character: %c", char)
		}
	}
	
	return nil
}

// ValidateCodeChallengeMethod validates the code challenge method
func ValidateCodeChallengeMethod(method string) error {
	switch method {
	case PKCEMethodS256, PKCEMethodPlain:
		return nil
	case "":
		return fmt.Errorf("code challenge method is required")
	default:
		return fmt.Errorf("unsupported code challenge method: %s", method)
	}
}

// isUnreservedChar checks if character is unreserved according to RFC 3986
// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
func isUnreservedChar(char rune) bool {
	return (char >= 'A' && char <= 'Z') ||
		(char >= 'a' && char <= 'z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '.' || char == '_' || char == '~'
}

// GenerateAuthorizationCode generates a secure authorization code
func GenerateAuthorizationCode() (string, error) {
	// Generate 32 bytes of random data for authorization code
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate authorization code: %w", err)
	}
	
	// Base64url encode for URL safety
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// ValidateRedirectURI validates the redirect URI according to OAuth 2.0 specs
func ValidateRedirectURI(redirectURI string) error {
	if redirectURI == "" {
		return fmt.Errorf("redirect URI is required")
	}
	
	// Must be absolute URI
	if !strings.HasPrefix(redirectURI, "http://") && !strings.HasPrefix(redirectURI, "https://") {
		return fmt.Errorf("redirect URI must be absolute (http:// or https://)")
	}
	
	// Should not contain fragment
	if strings.Contains(redirectURI, "#") {
		return fmt.Errorf("redirect URI must not contain fragment")
	}
	
	return nil
}
