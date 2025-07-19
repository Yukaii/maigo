package shortener

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEncoder(t *testing.T) {
	tests := []struct {
		name           string
		length         int
		expectedLength int
	}{
		{
			name:           "Valid length",
			length:         8,
			expectedLength: 8,
		},
		{
			name:           "Zero length uses default",
			length:         0,
			expectedLength: defaultLength,
		},
		{
			name:           "Negative length uses default",
			length:         -5,
			expectedLength: defaultLength,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewEncoder(tt.length)
			assert.Equal(t, tt.expectedLength, encoder.length)
			assert.Equal(t, base62Alphabet, encoder.alphabet)
		})
	}
}

func TestEncoder_Encode(t *testing.T) {
	encoder := NewEncoder(defaultLength)

	tests := []struct {
		name     string
		input    int64
		expected string
	}{
		{
			name:     "Zero",
			input:    0,
			expected: "0",
		},
		{
			name:     "Small number",
			input:    1,
			expected: "1",
		},
		{
			name:     "Base62 alphabet index 61",
			input:    61,
			expected: "z",
		},
		{
			name:     "Larger number",
			input:    62, // 62 in base62 is "10"
			expected: "10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encoder.Encode(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncoder_Decode(t *testing.T) {
	encoder := NewEncoder(defaultLength)

	tests := []struct {
		name          string
		input         string
		expected      int64
		expectedError bool
	}{
		{
			name:     "Zero",
			input:    "0",
			expected: 0,
		},
		{
			name:     "Small number",
			input:    "1",
			expected: 1,
		},
		{
			name:     "Base62 alphabet last character",
			input:    "z",
			expected: 61,
		},
		{
			name:     "Two character string",
			input:    "10",
			expected: 62,
		},
		{
			name:          "Invalid character",
			input:         "!@#",
			expectedError: true,
		},
		{
			name:          "Mixed valid and invalid",
			input:         "a!b",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encoder.Decode(tt.input)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "invalid character")
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestEncoder_EncodeDecodeRoundtrip(t *testing.T) {
	encoder := NewEncoder(defaultLength)

	testNumbers := []int64{0, 1, 10, 100, 1000, 10000, 123456789}

	for _, num := range testNumbers {
		t.Run(string(rune(num)), func(t *testing.T) {
			encoded := encoder.Encode(num)
			decoded, err := encoder.Decode(encoded)
			assert.NoError(t, err)
			assert.Equal(t, num, decoded)
		})
	}
}

func TestEncoder_GenerateRandom(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{
			name:   "Default length",
			length: defaultLength,
		},
		{
			name:   "Custom length",
			length: 10,
		},
		{
			name:   "Small length (more collisions expected)",
			length: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoder := NewEncoder(tt.length)

			// Generate multiple codes to test uniqueness
			codes := make(map[string]bool)
			iterations := 100
			if tt.length <= 2 {
				// For very short codes, use fewer iterations to reduce collision chance
				iterations = 20
			}

			for i := 0; i < iterations; i++ {
				code, err := encoder.GenerateRandom()
				assert.NoError(t, err)
				assert.Len(t, code, tt.length)

				// Verify all characters are valid
				for _, char := range code {
					assert.Contains(t, base62Alphabet, string(char))
				}

				// For short codes, duplicates are expected due to limited space
				if tt.length > 2 {
					assert.False(t, codes[code], "Duplicate code generated: %s", code)
				}
				codes[code] = true
			}
		})
	}
}

func TestEncoder_GenerateCustom(t *testing.T) {
	encoder := NewEncoder(defaultLength)

	tests := []struct {
		name          string
		custom        string
		expectedError bool
		errorContains string
	}{
		{
			name:   "Valid custom code",
			custom: "github",
		},
		{
			name:   "Valid alphanumeric",
			custom: "abc123XYZ",
		},
		{
			name:          "Empty string",
			custom:        "",
			expectedError: true,
			errorContains: "cannot be empty",
		},
		{
			name:          "Too long",
			custom:        strings.Repeat("a", 51),
			expectedError: true,
			errorContains: "too long",
		},
		{
			name:          "Invalid characters",
			custom:        "invalid-code!",
			expectedError: true,
			errorContains: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := encoder.GenerateCustom(tt.custom)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.custom, result)
			}
		})
	}
}

func TestEncoder_ValidateShortCode(t *testing.T) {
	encoder := NewEncoder(defaultLength)

	tests := []struct {
		name          string
		shortCode     string
		expectedError bool
		errorContains string
	}{
		{
			name:      "Valid short code",
			shortCode: "abc123",
		},
		{
			name:      "Valid long code",
			shortCode: "verylongcodebutvalid123456789",
		},
		{
			name:          "Empty code",
			shortCode:     "",
			expectedError: true,
			errorContains: "cannot be empty",
		},
		{
			name:          "Too long",
			shortCode:     strings.Repeat("a", 51),
			expectedError: true,
			errorContains: "too long",
		},
		{
			name:          "Invalid characters",
			shortCode:     "invalid@code",
			expectedError: true,
			errorContains: "invalid character",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := encoder.ValidateShortCode(tt.shortCode)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsValidURL(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		expected bool
	}{
		{
			name:     "Valid HTTP URL",
			url:      "http://example.com",
			expected: true,
		},
		{
			name:     "Valid HTTPS URL",
			url:      "https://github.com",
			expected: true,
		},
		{
			name:     "Valid HTTPS with path",
			url:      "https://github.com/user/repo",
			expected: true,
		},
		{
			name:     "Empty URL",
			url:      "",
			expected: false,
		},
		{
			name:     "No protocol",
			url:      "example.com",
			expected: false,
		},
		{
			name:     "FTP protocol",
			url:      "ftp://example.com",
			expected: false,
		},
		{
			name:     "Invalid protocol",
			url:      "invalid://example.com",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsValidURL(tt.url)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeURL(t *testing.T) {
	tests := []struct {
		name          string
		url           string
		expected      string
		expectedError bool
		errorContains string
	}{
		{
			name:     "Valid HTTPS URL",
			url:      "https://example.com",
			expected: "https://example.com",
		},
		{
			name:     "Valid HTTP URL",
			url:      "http://example.com",
			expected: "http://example.com",
		},
		{
			name:     "URL with whitespace",
			url:      "  https://example.com  ",
			expected: "https://example.com",
		},
		{
			name:     "URL without protocol",
			url:      "example.com",
			expected: "https://example.com",
		},
		{
			name:     "Domain with path without protocol",
			url:      "example.com/path",
			expected: "https://example.com/path",
		},
		{
			name:          "Empty URL",
			url:           "",
			expectedError: true,
			errorContains: "cannot be empty",
		},
		{
			name:     "Whitespace only becomes https://",
			url:      "   ",
			expected: "https://",
		},
		{
			name:          "Too long URL",
			url:           "https://" + strings.Repeat("a", 2050),
			expectedError: true,
			errorContains: "too long",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := SanitizeURL(tt.url)
			if tt.expectedError {
				assert.Error(t, err)
				if err != nil {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestPow(t *testing.T) {
	tests := []struct {
		name     string
		base     int64
		exp      int64
		expected int64
	}{
		{
			name:     "Base^0 = 1",
			base:     5,
			exp:      0,
			expected: 1,
		},
		{
			name:     "Base^1 = Base",
			base:     7,
			exp:      1,
			expected: 7,
		},
		{
			name:     "2^3 = 8",
			base:     2,
			exp:      3,
			expected: 8,
		},
		{
			name:     "10^2 = 100",
			base:     10,
			exp:      2,
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := pow(tt.base, tt.exp)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShortenerService_GenerateShortCode(t *testing.T) {
	// Mock existence checker
	existingCodes := make(map[string]bool)
	existenceChecker := func(code string) (bool, error) {
		return existingCodes[code], nil
	}

	service := NewShortenerService(defaultLength, existenceChecker)

	t.Run("Generate random short code", func(t *testing.T) {
		code, err := service.GenerateShortCode("")
		assert.NoError(t, err)
		assert.Len(t, code, defaultLength)
		assert.Regexp(t, "^[a-zA-Z0-9]+$", code)
	})

	t.Run("Generate custom short code", func(t *testing.T) {
		custom := "github"
		code, err := service.GenerateShortCode(custom)
		assert.NoError(t, err)
		assert.Equal(t, custom, code)
	})

	t.Run("Custom code already exists", func(t *testing.T) {
		custom := "existing"
		existingCodes[custom] = true

		code, err := service.GenerateShortCode(custom)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
		assert.Empty(t, code)
	})

	t.Run("Invalid custom code", func(t *testing.T) {
		custom := "invalid@code"
		code, err := service.GenerateShortCode(custom)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid custom short code")
		assert.Empty(t, code)
	})
}

func TestShortenerService_GenerateShortCodeCollisionDetection(t *testing.T) {
	// Mock existence checker that says all codes exist (forcing collision)
	existenceChecker := func(code string) (bool, error) {
		return true, nil // All codes "exist"
	}

	service := NewShortenerService(defaultLength, existenceChecker)

	t.Run("Max attempts reached", func(t *testing.T) {
		code, err := service.GenerateShortCode("")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to generate unique short code")
		assert.Empty(t, code)
	})
}

func TestShortenerService_ValidateShortCode(t *testing.T) {
	existenceChecker := func(code string) (bool, error) {
		return false, nil
	}

	service := NewShortenerService(defaultLength, existenceChecker)

	tests := []struct {
		name          string
		shortCode     string
		expectedError bool
	}{
		{
			name:      "Valid code",
			shortCode: "abc123",
		},
		{
			name:          "Empty code",
			shortCode:     "",
			expectedError: true,
		},
		{
			name:          "Invalid characters",
			shortCode:     "invalid@",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.ValidateShortCode(tt.shortCode)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewShortenerService(t *testing.T) {
	existenceChecker := func(code string) (bool, error) {
		return false, nil
	}

	t.Run("Valid length", func(t *testing.T) {
		service := NewShortenerService(8, existenceChecker)
		assert.NotNil(t, service)
		assert.NotNil(t, service.encoder)
		assert.NotNil(t, service.existenceChecker)
		assert.Equal(t, 8, service.encoder.length)
	})

	t.Run("Invalid length uses default", func(t *testing.T) {
		service := NewShortenerService(0, existenceChecker)
		assert.NotNil(t, service)
		assert.Equal(t, defaultLength, service.encoder.length)
	})
}

// Benchmark tests
func BenchmarkEncoder_Encode(b *testing.B) {
	encoder := NewEncoder(defaultLength)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		encoder.Encode(int64(i))
	}
}

func BenchmarkEncoder_Decode(b *testing.B) {
	encoder := NewEncoder(defaultLength)
	encoded := encoder.Encode(123456)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck // benchmark doesn't need error checking
		encoder.Decode(encoded)
	}
}

func BenchmarkEncoder_GenerateRandom(b *testing.B) {
	encoder := NewEncoder(defaultLength)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		//nolint:errcheck // benchmark doesn't need error checking
		encoder.GenerateRandom()
	}
}
