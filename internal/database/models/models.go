// Package models defines database models for Maigo.
package models

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           int64     `json:"id" db:"id"`
	Username     string    `json:"username" db:"username" validate:"required,min=3,max=50,alphanum"`
	Email        string    `json:"email" db:"email" validate:"required,email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// URL represents a shortened URL
type URL struct {
	ID        int64      `json:"id" db:"id"`
	ShortCode string     `json:"short_code" db:"short_code" validate:"required,min=1,max=50,alphanum"`
	TargetURL string     `json:"target_url" db:"target_url" validate:"required,url"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	Hits      int64      `json:"hits" db:"hits"`
	UserID    *int64     `json:"user_id,omitempty" db:"user_id"`
}

// IsExpired checks if the URL has expired
func (u *URL) IsExpired() bool {
	if u.ExpiresAt == nil {
		return false // URLs without expiration never expire
	}
	return time.Now().After(*u.ExpiresAt)
}

// TimeUntilExpiry returns the duration until the URL expires
func (u *URL) TimeUntilExpiry() *time.Duration {
	if u.ExpiresAt == nil {
		return nil // URL doesn't expire
	}
	if u.IsExpired() {
		return nil // Already expired
	}
	duration := time.Until(*u.ExpiresAt)
	return &duration
}

// OAuthClient represents an OAuth2 client
type OAuthClient struct {
	ID          string    `json:"id" db:"id" validate:"required"`
	Secret      string    `json:"-" db:"secret"`
	Name        string    `json:"name" db:"name" validate:"required"`
	RedirectURI string    `json:"redirect_uri" db:"redirect_uri" validate:"required,url"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// AuthorizationCode represents an OAuth2 authorization code
type AuthorizationCode struct {
	Code                string    `json:"code" db:"code" validate:"required"`
	ClientID            string    `json:"client_id" db:"client_id" validate:"required"`
	UserID              int64     `json:"user_id" db:"user_id" validate:"required"`
	RedirectURI         string    `json:"redirect_uri" db:"redirect_uri" validate:"required,url"`
	Scope               string    `json:"scope" db:"scope"`
	CodeChallenge       string    `json:"code_challenge,omitempty" db:"code_challenge"`
	CodeChallengeMethod string    `json:"code_challenge_method,omitempty" db:"code_challenge_method"`
	ExpiresAt           time.Time `json:"expires_at" db:"expires_at"`
	Used                bool      `json:"used" db:"used"`
	CreatedAt           time.Time `json:"created_at" db:"created_at"`
}

// AccessToken represents an OAuth2 access token
type AccessToken struct {
	Token        string    `json:"token" db:"token" validate:"required"`
	RefreshToken *string   `json:"refresh_token,omitempty" db:"refresh_token"`
	ClientID     string    `json:"client_id" db:"client_id" validate:"required"`
	UserID       int64     `json:"user_id" db:"user_id" validate:"required"`
	Scope        string    `json:"scope" db:"scope"`
	ExpiresAt    time.Time `json:"expires_at" db:"expires_at"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
}

// Domain represents a custom domain
type Domain struct {
	ID        int64     `json:"id" db:"id"`
	Domain    string    `json:"domain" db:"domain" validate:"required,fqdn"`
	UserID    int64     `json:"user_id" db:"user_id" validate:"required"`
	SSLCert   *string   `json:"-" db:"ssl_cert"`
	SSLKey    *string   `json:"-" db:"ssl_key"`
	Verified  bool      `json:"verified" db:"verified"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

// CreateUserRequest represents a user creation request
type CreateUserRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50,alphanum"`
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// CreateURLRequest represents a URL creation request
type CreateURLRequest struct {
	URL       string     `json:"url" validate:"required,url"`
	Custom    string     `json:"custom,omitempty" validate:"omitempty,min=3,max=50,alphanum"`
	TTL       *int64     `json:"ttl,omitempty" validate:"omitempty,min=60"` // TTL in seconds, minimum 1 minute
	ExpiresAt *time.Time `json:"expires_at,omitempty"`                      // Alternative to TTL - exact expiration time
}

// UpdateURLRequest represents a URL update request
type UpdateURLRequest struct {
	TargetURL *string `json:"target_url,omitempty" validate:"omitempty,url"`
}

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code,omitempty"`
}

// SuccessResponse represents a generic success response
type SuccessResponse struct {
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// PaginationResponse represents pagination metadata
type PaginationResponse struct {
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Total    int64 `json:"total"`
	Pages    int   `json:"pages"`
}

// URLListResponse represents a paginated list of URLs
type URLListResponse struct {
	URLs       []URL              `json:"urls"`
	Pagination PaginationResponse `json:"pagination"`
}
