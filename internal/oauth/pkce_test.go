package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCEParams(t *testing.T) {
	params, err := GeneratePKCEParams()
	require.NoError(t, err)
	require.NotNil(t, params)

	// Verify code verifier
	assert.NotEmpty(t, params.CodeVerifier)
	assert.GreaterOrEqual(t, len(params.CodeVerifier), CodeVerifierMinLength)
	assert.LessOrEqual(t, len(params.CodeVerifier), CodeVerifierMaxLength)

	// Verify code challenge
	assert.NotEmpty(t, params.CodeChallenge)
	assert.Equal(t, PKCEMethodS256, params.CodeChallengeMethod)

	// Verify code challenge is properly generated from verifier
	hash := sha256.Sum256([]byte(params.CodeVerifier))
	expectedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	assert.Equal(t, expectedChallenge, params.CodeChallenge)

	// Verify uniqueness by generating multiple params
	params2, err := GeneratePKCEParams()
	require.NoError(t, err)
	assert.NotEqual(t, params.CodeVerifier, params2.CodeVerifier)
	assert.NotEqual(t, params.CodeChallenge, params2.CodeChallenge)
}

func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("Valid code verifier generation", func(t *testing.T) {
		verifier, err := generateCodeVerifier()
		require.NoError(t, err)

		// Check length
		assert.GreaterOrEqual(t, len(verifier), CodeVerifierMinLength)
		assert.LessOrEqual(t, len(verifier), CodeVerifierMaxLength)

		// Check all characters are valid (base64url characters)
		for _, char := range verifier {
			assert.True(t, isUnreservedChar(char) || char == '-' || char == '_',
				"Invalid character in code verifier: %c", char)
		}
	})

	t.Run("Uniqueness", func(t *testing.T) {
		verifiers := make(map[string]bool)

		// Generate multiple verifiers and check uniqueness
		for i := 0; i < 100; i++ {
			verifier, err := generateCodeVerifier()
			require.NoError(t, err)
			assert.False(t, verifiers[verifier], "Duplicate verifier generated: %s", verifier)
			verifiers[verifier] = true
		}
	})
}

func TestCreateCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	t.Run("S256 method", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, PKCEMethodS256)
		require.NoError(t, err)

		// Manually compute expected challenge
		hash := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(hash[:])

		assert.Equal(t, expected, challenge)
		assert.NotEqual(t, verifier, challenge) // Should be different from verifier
	})

	t.Run("Plain method", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, PKCEMethodPlain)
		require.NoError(t, err)

		assert.Equal(t, verifier, challenge) // Should be same as verifier
	})

	t.Run("Invalid method", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, "invalid")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported code challenge method")
		assert.Empty(t, challenge)
	})
}

func TestVerifyCodeChallenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	t.Run("Valid S256 verification", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, PKCEMethodS256)
		require.NoError(t, err)

		result := VerifyCodeChallenge(verifier, challenge, PKCEMethodS256)
		assert.True(t, result)
	})

	t.Run("Valid plain verification", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, PKCEMethodPlain)
		require.NoError(t, err)

		result := VerifyCodeChallenge(verifier, challenge, PKCEMethodPlain)
		assert.True(t, result)
	})

	t.Run("Invalid verifier", func(t *testing.T) {
		challenge, err := createCodeChallenge(verifier, PKCEMethodS256)
		require.NoError(t, err)

		result := VerifyCodeChallenge("wrong-verifier", challenge, PKCEMethodS256)
		assert.False(t, result)
	})

	t.Run("Empty verifier", func(t *testing.T) {
		challenge := "some-challenge"
		result := VerifyCodeChallenge("", challenge, PKCEMethodS256)
		assert.False(t, result)
	})

	t.Run("Empty challenge", func(t *testing.T) {
		result := VerifyCodeChallenge(verifier, "", PKCEMethodS256)
		assert.False(t, result)
	})

	t.Run("Invalid method", func(t *testing.T) {
		challenge := "some-challenge"
		result := VerifyCodeChallenge(verifier, challenge, "invalid")
		assert.False(t, result)
	})
}

func TestValidateCodeVerifier(t *testing.T) {
	tests := []struct {
		name          string
		verifier      string
		expectedError bool
		errorContains string
	}{
		{
			name:     "Valid verifier",
			verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		},
		{
			name:     "Valid minimum length",
			verifier: strings.Repeat("a", CodeVerifierMinLength),
		},
		{
			name:     "Valid maximum length",
			verifier: strings.Repeat("a", CodeVerifierMaxLength),
		},
		{
			name:          "Too short",
			verifier:      strings.Repeat("a", CodeVerifierMinLength-1),
			expectedError: true,
			errorContains: "too short",
		},
		{
			name:          "Too long",
			verifier:      strings.Repeat("a", CodeVerifierMaxLength+1),
			expectedError: true,
			errorContains: "too long",
		},
		{
			name:          "Invalid character space",
			verifier:      strings.Repeat("a", CodeVerifierMinLength-5) + " with space",
			expectedError: true,
			errorContains: "invalid character",
		},
		{
			name:          "Invalid character special",
			verifier:      strings.Repeat("a", CodeVerifierMinLength-1) + "@",
			expectedError: true,
			errorContains: "invalid character",
		},
		{
			name:     "Valid with hyphens and underscores",
			verifier: "valid-verifier_with.tildes~and123NUMBERS" + strings.Repeat("a", CodeVerifierMinLength-40),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeVerifier(tt.verifier)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCodeChallenge(t *testing.T) {
	tests := []struct {
		name          string
		challenge     string
		expectedError bool
		errorContains string
	}{
		{
			name:      "Valid challenge",
			challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		},
		{
			name:      "Valid minimum length",
			challenge: strings.Repeat("a", CodeVerifierMinLength),
		},
		{
			name:      "Valid maximum length",
			challenge: strings.Repeat("a", CodeVerifierMaxLength),
		},
		{
			name:          "Too short",
			challenge:     strings.Repeat("a", CodeVerifierMinLength-1),
			expectedError: true,
			errorContains: "too short",
		},
		{
			name:          "Too long",
			challenge:     strings.Repeat("a", CodeVerifierMaxLength+1),
			expectedError: true,
			errorContains: "too long",
		},
		{
			name:          "Invalid character",
			challenge:     strings.Repeat("a", CodeVerifierMinLength-1) + "@",
			expectedError: true,
			errorContains: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeChallenge(tt.challenge)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateCodeChallengeMethod(t *testing.T) {
	tests := []struct {
		name          string
		method        string
		expectedError bool
		errorContains string
	}{
		{
			name:   "Valid S256",
			method: PKCEMethodS256,
		},
		{
			name:   "Valid plain",
			method: PKCEMethodPlain,
		},
		{
			name:          "Empty method",
			method:        "",
			expectedError: true,
			errorContains: "is required",
		},
		{
			name:          "Invalid method",
			method:        "invalid",
			expectedError: true,
			errorContains: "unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCodeChallengeMethod(tt.method)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsUnreservedChar(t *testing.T) {
	tests := []struct {
		name     string
		char     rune
		expected bool
	}{
		// Valid characters
		{name: "Letter A", char: 'A', expected: true},
		{name: "Letter z", char: 'z', expected: true},
		{name: "Digit 0", char: '0', expected: true},
		{name: "Digit 9", char: '9', expected: true},
		{name: "Hyphen", char: '-', expected: true},
		{name: "Period", char: '.', expected: true},
		{name: "Underscore", char: '_', expected: true},
		{name: "Tilde", char: '~', expected: true},

		// Invalid characters
		{name: "Space", char: ' ', expected: false},
		{name: "At sign", char: '@', expected: false},
		{name: "Hash", char: '#', expected: false},
		{name: "Plus", char: '+', expected: false},
		{name: "Slash", char: '/', expected: false},
		{name: "Equal", char: '=', expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isUnreservedChar(tt.char)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateAuthorizationCode(t *testing.T) {
	t.Run("Valid authorization code generation", func(t *testing.T) {
		code, err := GenerateAuthorizationCode()
		require.NoError(t, err)
		assert.NotEmpty(t, code)

		// Verify it's base64url encoded (no padding, URL-safe)
		assert.NotContains(t, code, "=") // No padding
		assert.NotContains(t, code, "+") // No + character
		assert.NotContains(t, code, "/") // No / character

		// Should be able to decode it
		decoded, err := base64.RawURLEncoding.DecodeString(code)
		require.NoError(t, err)
		assert.Len(t, decoded, 32) // 32 bytes of random data
	})

	t.Run("Uniqueness", func(t *testing.T) {
		codes := make(map[string]bool)

		// Generate multiple codes and check uniqueness
		for i := 0; i < 100; i++ {
			code, err := GenerateAuthorizationCode()
			require.NoError(t, err)
			assert.False(t, codes[code], "Duplicate authorization code generated: %s", code)
			codes[code] = true
		}
	})
}

func TestValidateRedirectURI(t *testing.T) {
	tests := []struct {
		name          string
		redirectURI   string
		expectedError bool
		errorContains string
	}{
		{
			name:        "Valid HTTPS URI",
			redirectURI: "https://example.com/callback",
		},
		{
			name:        "Valid HTTP URI",
			redirectURI: "http://localhost:8080/callback",
		},
		{
			name:        "Valid with query parameters",
			redirectURI: "https://example.com/callback?state=123",
		},
		{
			name:          "Empty URI",
			redirectURI:   "",
			expectedError: true,
			errorContains: "is required",
		},
		{
			name:          "Relative URI",
			redirectURI:   "/callback",
			expectedError: true,
			errorContains: "must be absolute",
		},
		{
			name:          "No protocol",
			redirectURI:   "example.com/callback",
			expectedError: true,
			errorContains: "must be absolute",
		},
		{
			name:          "With fragment",
			redirectURI:   "https://example.com/callback#fragment",
			expectedError: true,
			errorContains: "must not contain fragment",
		},
		{
			name:          "FTP protocol",
			redirectURI:   "ftp://example.com/callback",
			expectedError: true,
			errorContains: "must be absolute",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateRedirectURI(tt.redirectURI)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Benchmark tests
func BenchmarkGeneratePKCEParams(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GeneratePKCEParams()
	}
}

func BenchmarkGenerateCodeVerifier(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateCodeVerifier()
	}
}

func BenchmarkCreateCodeChallenge_S256(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		createCodeChallenge(verifier, PKCEMethodS256)
	}
}

func BenchmarkVerifyCodeChallenge_S256(b *testing.B) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge, _ := createCodeChallenge(verifier, PKCEMethodS256)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		VerifyCodeChallenge(verifier, challenge, PKCEMethodS256)
	}
}

func BenchmarkGenerateAuthorizationCode(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateAuthorizationCode()
	}
}
