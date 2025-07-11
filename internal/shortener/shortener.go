package shortener

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
)

const (
	// Base62 alphabet for encoding
	base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	
	// Default short code length
	defaultLength = 6
	
	// Maximum attempts to generate a unique short code
	maxAttempts = 10
)

// Encoder handles URL shortening operations
type Encoder struct {
	alphabet string
	length   int
}

// NewEncoder creates a new URL encoder
func NewEncoder(length int) *Encoder {
	if length <= 0 {
		length = defaultLength
	}
	
	return &Encoder{
		alphabet: base62Alphabet,
		length:   length,
	}
}

// Encode converts an integer to a base62 string
func (e *Encoder) Encode(num int64) string {
	if num == 0 {
		return string(e.alphabet[0])
	}

	base := int64(len(e.alphabet))
	var result strings.Builder
	
	for num > 0 {
		remainder := num % base
		result.WriteByte(e.alphabet[remainder])
		num = num / base
	}

	// Reverse the string
	encoded := result.String()
	runes := []rune(encoded)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}

	return string(runes)
}

// Decode converts a base62 string back to an integer
func (e *Encoder) Decode(encoded string) (int64, error) {
	base := int64(len(e.alphabet))
	var result int64
	
	for i, char := range encoded {
		pos := strings.IndexRune(e.alphabet, char)
		if pos == -1 {
			return 0, fmt.Errorf("invalid character '%c' in encoded string", char)
		}
		
		power := int64(len(encoded) - i - 1)
		result += int64(pos) * pow(base, power)
	}
	
	return result, nil
}

// GenerateRandom generates a random short code of the specified length
func (e *Encoder) GenerateRandom() (string, error) {
	alphabetLen := big.NewInt(int64(len(e.alphabet)))
	var result strings.Builder
	
	for i := 0; i < e.length; i++ {
		randomIndex, err := rand.Int(rand.Reader, alphabetLen)
		if err != nil {
			return "", fmt.Errorf("failed to generate random number: %w", err)
		}
		result.WriteByte(e.alphabet[randomIndex.Int64()])
	}
	
	return result.String(), nil
}

// GenerateCustom validates and formats a custom short code
func (e *Encoder) GenerateCustom(custom string) (string, error) {
	if len(custom) == 0 {
		return "", fmt.Errorf("custom short code cannot be empty")
	}
	
	if len(custom) > 50 {
		return "", fmt.Errorf("custom short code too long (max 50 characters)")
	}
	
	// Validate characters
	for _, char := range custom {
		if !strings.ContainsRune(e.alphabet, char) {
			return "", fmt.Errorf("invalid character '%c' in custom short code", char)
		}
	}
	
	return custom, nil
}

// ValidateShortCode checks if a short code is valid
func (e *Encoder) ValidateShortCode(shortCode string) error {
	if len(shortCode) == 0 {
		return fmt.Errorf("short code cannot be empty")
	}
	
	if len(shortCode) > 50 {
		return fmt.Errorf("short code too long (max 50 characters)")
	}
	
	for _, char := range shortCode {
		if !strings.ContainsRune(e.alphabet, char) {
			return fmt.Errorf("invalid character '%c' in short code", char)
		}
	}
	
	return nil
}

// IsValidURL performs basic URL validation
func IsValidURL(url string) bool {
	if len(url) == 0 {
		return false
	}
	
	// Basic validation - starts with http:// or https://
	return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
}

// SanitizeURL cleans and validates a URL
func SanitizeURL(url string) (string, error) {
	if len(url) == 0 {
		return "", fmt.Errorf("URL cannot be empty")
	}
	
	// Trim whitespace
	url = strings.TrimSpace(url)
	
	// Add https:// if no protocol specified
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		url = "https://" + url
	}
	
	// Basic validation
	if !IsValidURL(url) {
		return "", fmt.Errorf("invalid URL format")
	}
	
	if len(url) > 2048 {
		return "", fmt.Errorf("URL too long (max 2048 characters)")
	}
	
	return url, nil
}

// Helper function to calculate power
func pow(base, exp int64) int64 {
	result := int64(1)
	for exp > 0 {
		if exp%2 == 1 {
			result *= base
		}
		base *= base
		exp /= 2
	}
	return result
}

// ShortenerService combines encoding with collision detection
type ShortenerService struct {
	encoder           *Encoder
	existenceChecker  func(string) (bool, error)
}

// NewShortenerService creates a new shortener service
func NewShortenerService(length int, existenceChecker func(string) (bool, error)) *ShortenerService {
	return &ShortenerService{
		encoder:          NewEncoder(length),
		existenceChecker: existenceChecker,
	}
}

// GenerateShortCode generates a unique short code
func (s *ShortenerService) GenerateShortCode(custom string) (string, error) {
	// If custom code provided, validate and check existence
	if custom != "" {
		shortCode, err := s.encoder.GenerateCustom(custom)
		if err != nil {
			return "", fmt.Errorf("invalid custom short code: %w", err)
		}
		
		exists, err := s.existenceChecker(shortCode)
		if err != nil {
			return "", fmt.Errorf("failed to check short code existence: %w", err)
		}
		
		if exists {
			return "", fmt.Errorf("custom short code already exists")
		}
		
		return shortCode, nil
	}
	
	// Generate random short code with collision detection
	for attempt := 0; attempt < maxAttempts; attempt++ {
		shortCode, err := s.encoder.GenerateRandom()
		if err != nil {
			return "", fmt.Errorf("failed to generate random short code: %w", err)
		}
		
		exists, err := s.existenceChecker(shortCode)
		if err != nil {
			return "", fmt.Errorf("failed to check short code existence: %w", err)
		}
		
		if !exists {
			return shortCode, nil
		}
	}
	
	return "", fmt.Errorf("failed to generate unique short code after %d attempts", maxAttempts)
}

// ValidateShortCode validates a short code
func (s *ShortenerService) ValidateShortCode(shortCode string) error {
	return s.encoder.ValidateShortCode(shortCode)
}
