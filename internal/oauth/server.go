// Package oauth implements OAuth 2.0 and PKCE logic for Maigo.
package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/security/jwtkeys"
)

// Default CLI client constants - must match CLI package constants
const (
	DefaultCLIClientID     = "maigo-cli"
	DefaultCLIClientSecret = "cli-client-secret-not-used-with-pkce" //nolint:gosec // test secret for CLI client
	DefaultCLIClientName   = "Maigo CLI Application"
	DefaultCLIRedirectURI  = "http://localhost:8000/callback"
)

// Server handles OAuth2 operations
type Server struct {
	db      *pgxpool.Pool
	config  *config.Config
	logger  *slog.Logger
	keyRing *jwtkeys.KeyRing
}

// NewServer creates a new OAuth2 server
func NewServer(db *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) *Server {
	var keyRing *jwtkeys.KeyRing
	if cfg != nil {
		var err error
		keyRing, err = jwtkeys.NewKeyRing(cfg.JWT)
		if err != nil && logger != nil {
			logger.Error("Invalid JWT key configuration", "error", err)
		}
	}

	return &Server{
		db:      db,
		config:  cfg,
		logger:  logger,
		keyRing: keyRing,
	}
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Type     string `json:"type"` // "access" or "refresh"
	jwt.RegisteredClaims
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// AuthorizationRequest represents an OAuth 2.0 authorization request
type AuthorizationRequest struct {
	ResponseType        string `form:"response_type" binding:"required"`
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

// TokenRequest represents an OAuth 2.0 token request
type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"`
	RedirectURI  string `form:"redirect_uri"`
	ClientID     string `form:"client_id" binding:"required"`
	CodeVerifier string `form:"code_verifier"`
	RefreshToken string `form:"refresh_token"`
}

// AuthorizeResponse represents the authorization response
type AuthorizeResponse struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// TokenError represents an OAuth 2.0 error response
type TokenError struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface for TokenError
func (e *TokenError) Error() string {
	if e.ErrorDescription != "" {
		return fmt.Sprintf("%s: %s", e.ErrorCode, e.ErrorDescription)
	}
	return e.ErrorCode
}

// OAuth 2.0 grant types
const (
	GrantTypeAuthorizationCode = "authorization_code"
	GrantTypeRefreshToken      = "refresh_token"
)

const (
	authorizationCodeLifetime = 10 * time.Minute
	accessTokenLifetime       = time.Hour
	refreshTokenLifetime      = 30 * 24 * time.Hour
	accessTokenType           = "access"
	refreshTokenType          = "refresh"
)

// OAuth 2.0 response types
const (
	ResponseTypeCode = "code"
)

// OAuth 2.0 error codes
const (
	ErrorInvalidRequest          = "invalid_request"
	ErrorUnauthorizedClient      = "unauthorized_client"
	ErrorAccessDenied            = "access_denied"
	ErrorUnsupportedResponseType = "unsupported_response_type"
	ErrorInvalidScope            = "invalid_scope"
	ErrorServerError             = "server_error"
	ErrorTemporarilyUnavailable  = "temporarily_unavailable"
	ErrorInvalidClient           = "invalid_client"
	ErrorInvalidGrant            = "invalid_grant"
	ErrorUnsupportedGrantType    = "unsupported_grant_type"
)

// ProcessAuthorizationRequest processes OAuth 2.0 authorization request with PKCE
func (s *Server) ProcessAuthorizationRequest(
	ctx context.Context,
	req *AuthorizationRequest,
) (*AuthorizeResponse, error) {
	return s.processAuthorizationRequest(ctx, req, 0)
}

// ProcessAuthorizationRequestWithUser processes OAuth 2.0 authorization request with a specific user ID
func (s *Server) ProcessAuthorizationRequestWithUser(
	ctx context.Context,
	req *AuthorizationRequest,
	userID int64,
) (*AuthorizeResponse, error) {
	return s.processAuthorizationRequest(ctx, req, userID)
}

// ValidateAuthorizationRequest validates an authorization request without
// issuing a code. It is used by the consent-denial path before redirecting to
// a client-supplied URI.
func (s *Server) ValidateAuthorizationRequest(ctx context.Context, req *AuthorizationRequest) error {
	if req == nil {
		return &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Authorization request is required",
		}
	}
	if req.ResponseType != ResponseTypeCode {
		return &TokenError{
			ErrorCode:        ErrorUnsupportedResponseType,
			ErrorDescription: "Only 'code' response type is supported",
		}
	}

	client, err := s.getClient(ctx, req.ClientID)
	if err != nil {
		return &TokenError{ErrorCode: ErrorInvalidClient, ErrorDescription: "Invalid client_id"}
	}
	if !s.validateRedirectURI(client, req.RedirectURI) {
		return &TokenError{ErrorCode: ErrorInvalidRequest, ErrorDescription: "Invalid redirect_uri"}
	}
	if req.CodeChallenge == "" {
		return &TokenError{ErrorCode: ErrorInvalidRequest, ErrorDescription: "code_challenge is required"}
	}
	if req.CodeChallengeMethod != PKCEMethodS256 {
		return &TokenError{ErrorCode: ErrorInvalidRequest, ErrorDescription: "code_challenge_method must be S256"}
	}
	if err := ValidateCodeChallenge(req.CodeChallenge); err != nil {
		return &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: fmt.Sprintf("Invalid code_challenge: %v", err),
		}
	}

	return nil
}

// processAuthorizationRequest validates and stores an authorization request
// for the authenticated user. Authorization codes must never be issued for a
// guessed or implicit user ID.
func (s *Server) processAuthorizationRequest(
	ctx context.Context,
	req *AuthorizationRequest,
	userID int64,
) (*AuthorizeResponse, error) {
	if req == nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Authorization request is required",
		}
	}

	if userID <= 0 {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Authenticated user is required",
		}
	}

	if err := s.ValidateAuthorizationRequest(ctx, req); err != nil {
		return nil, err
	}

	// Generate authorization code
	authCode, err := GenerateAuthorizationCode()
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to generate authorization code",
		}
	}

	// Store authorization code with PKCE parameters and the provided user ID
	expiresAt := time.Now().Add(authorizationCodeLifetime)
	err = s.storeAuthorizationCodeWithUser(ctx, &models.AuthorizationCode{
		Code:                authCode,
		ClientID:            req.ClientID,
		UserID:              userID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		Used:                false,
	})

	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to store authorization code",
		}
	}

	return &AuthorizeResponse{
		Code:  authCode,
		State: req.State,
	}, nil
}

// ProcessTokenRequest processes OAuth 2.0 token request with PKCE verification
func (s *Server) ProcessTokenRequest(ctx context.Context, req *TokenRequest) (*TokenPair, error) {
	if req == nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Token request is required",
		}
	}

	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.processAuthorizationCodeGrant(ctx, req)
	case GrantTypeRefreshToken:
		return s.processRefreshTokenGrant(ctx, req)
	default:
		return nil, &TokenError{
			ErrorCode:        ErrorUnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("Grant type '%s' is not supported", req.GrantType),
		}
	}
}

// processAuthorizationCodeGrant processes authorization code grant with PKCE
func (s *Server) processAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenPair, error) {
	// Validate required parameters
	if req.Code == "" {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: code",
		}
	}

	if req.RedirectURI == "" {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: redirect_uri",
		}
	}

	// Validate client
	_, err := s.getClient(ctx, req.ClientID)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidClient,
			ErrorDescription: "Invalid client_id",
		}
	}

	// Get and validate authorization code
	authCode, err := s.getAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid or expired authorization code",
		}
	}

	// Check if code is already used
	if authCode.Used {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Authorization code already used",
		}
	}

	// Check if code is expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Authorization code expired",
		}
	}

	// Validate client matches
	if authCode.ClientID != req.ClientID {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Client mismatch",
		}
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Redirect URI mismatch",
		}
	}

	// Validate PKCE if code challenge was provided
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, &TokenError{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: "Missing required parameter: code_verifier",
			}
		}

		err = ValidateCodeVerifier(req.CodeVerifier)
		if err != nil {
			return nil, &TokenError{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_verifier: %v", err),
			}
		}

		// Verify PKCE challenge
		if !VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, &TokenError{
				ErrorCode:        ErrorInvalidGrant,
				ErrorDescription: "PKCE verification failed",
			}
		}
	}

	// Mark authorization code as used atomically. This closes the replay race
	// where two requests could both read an unused code before either update.
	if markErr := s.markAuthorizationCodeUsed(ctx, req.Code); markErr != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Authorization code already used or expired",
		}
	}

	// Get user from authorization code
	user, err := s.getUserByID(ctx, authCode.UserID)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "User not found",
		}
	}

	// Generate tokens
	return s.GenerateTokenPair(ctx, user)
}

// GenerateTokenPair generates access and refresh token pair
func (s *Server) GenerateTokenPair(ctx context.Context, user *models.User) (*TokenPair, error) {
	if user == nil || user.ID <= 0 {
		return nil, fmt.Errorf("cannot issue tokens for an invalid user")
	}
	if s.config == nil {
		return nil, fmt.Errorf("JWT configuration is not available")
	}
	if s.keyRing == nil {
		return nil, fmt.Errorf("JWT key configuration is invalid")
	}

	now := time.Now()
	accessLifetime := s.config.JWT.Expiration
	if accessLifetime <= 0 {
		accessLifetime = accessTokenLifetime
	}
	refreshID := uuid.NewString()
	accessID := uuid.NewString()
	accessExpiresAt := now.Add(accessLifetime)
	refreshExpiresAt := now.Add(refreshTokenLifetime)

	// Generate access token
	accessClaims := jwt.MapClaims{
		"user_id":  user.ID,
		"username": user.Username,
		"email":    user.Email,
		"type":     accessTokenType,
		"jti":      accessID,
		"exp":      accessExpiresAt.Unix(),
		"iat":      now.Unix(),
		"iss":      "maigo-oauth2",
		"aud":      "maigo-api",
	}

	accessTokenString, err := s.keyRing.Sign(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"type":    refreshTokenType,
		"jti":     refreshID,
		"exp":     refreshExpiresAt.Unix(),
		"iat":     now.Unix(),
		"iss":     "maigo-oauth2",
	}

	refreshTokenString, err := s.keyRing.Sign(refreshClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	// Keep refresh tokens stateful so logout and rotation have real effect. Each
	// login or authorization flow gets its own session, allowing multiple
	// devices or clients to remain signed in independently.
	if s.db != nil {
		const query = `
			INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at, updated_at)
			VALUES ($1, $2, $3, $4, $5, $5)
		`
		if _, err := s.db.Exec(
			ctx,
			query,
			refreshID,
			user.ID,
			hashToken(refreshTokenString),
			refreshExpiresAt,
			now,
		); err != nil {
			return nil, fmt.Errorf("failed to persist refresh session: %w", err)
		}
	}

	expiresIn := int(accessLifetime / time.Second)
	if expiresIn < 1 {
		expiresIn = 1
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshTokenString,
	}, nil
}

// RefreshAccessToken creates a new access token from a refresh token
func (s *Server) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	if refreshTokenString == "" {
		return nil, &TokenError{ErrorCode: ErrorInvalidGrant, ErrorDescription: "Invalid refresh token"}
	}

	// Parse and validate refresh token using one exact signing algorithm.
	token, err := s.parseSignedToken(refreshTokenString)

	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid refresh token",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid refresh token",
		}
	}

	// Check if token type is refresh
	if tokenType, tokenOk := claims["type"].(string); !tokenOk || tokenType != refreshTokenType {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Token is not a refresh token",
		}
	}

	// Extract user ID
	userID, ok := claimInt64(claims["user_id"])
	if !ok || userID <= 0 {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid user ID in refresh token",
		}
	}

	refreshID, ok := claims["jti"].(string)
	if !ok || refreshID == "" {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid refresh token",
		}
	}

	// Consume the current session atomically. A rotated refresh token cannot be
	// replayed, including when two refresh requests arrive concurrently.
	if s.db != nil {
		var sessionUserID int64
		const query = `
			DELETE FROM sessions
			WHERE id = $1 AND user_id = $2 AND refresh_token = $3 AND expires_at > NOW()
			RETURNING user_id`
		err = s.db.QueryRow(ctx, query, refreshID, userID, hashToken(refreshTokenString)).Scan(&sessionUserID)
		if err != nil || sessionUserID != userID {
			return nil, &TokenError{
				ErrorCode:        ErrorInvalidGrant,
				ErrorDescription: "Invalid or expired refresh token",
			}
		}
	}

	// Get user
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "User not found",
		}
	}

	// Generate new token pair
	return s.GenerateTokenPair(ctx, user)
}

// processRefreshTokenGrant processes refresh token grant
func (s *Server) processRefreshTokenGrant(ctx context.Context, req *TokenRequest) (*TokenPair, error) {
	if req.RefreshToken == "" {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: refresh_token",
		}
	}

	if _, err := s.getClient(ctx, req.ClientID); err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidClient,
			ErrorDescription: "Invalid client_id",
		}
	}

	return s.RefreshAccessToken(ctx, req.RefreshToken)
}

// GetAuthorizationURL constructs OAuth 2.0 authorization URL with PKCE
func (s *Server) GetAuthorizationURL(clientID, redirectURI, scope, state string, pkce *PKCEParams) (string, error) {
	// Construct base URL from config
	protocol := redirectSchemeHTTP
	if s.config.App.TLS {
		protocol = "https"
	}
	baseURL := fmt.Sprintf("%s://%s:%d/oauth/authorize", protocol, s.config.Server.Host, s.config.Server.Port)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", clientID)
	params.Set("redirect_uri", redirectURI)

	if scope != "" {
		params.Set("scope", scope)
	}

	if state != "" {
		params.Set("state", state)
	}

	if pkce != nil {
		params.Set("code_challenge", pkce.CodeChallenge)
		params.Set("code_challenge_method", pkce.CodeChallengeMethod)
	}

	return baseURL + "?" + params.Encode(), nil
}

// AuthenticateUser authenticates a user with username/password and returns a token pair
func (s *Server) AuthenticateUser(ctx context.Context, username, password string) (*TokenPair, error) {
	// Get user by username/email
	user, err := s.getUserByUsernameOrEmail(ctx, username)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid username or password",
		}
	}

	// Passwords are stored as bcrypt hashes. Never compare or persist the raw
	// password.
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid username or password",
		}
	}

	// Generate token pair
	return s.GenerateTokenPair(ctx, user)
}

// RegisterUser creates a new user account and returns the user
func (s *Server) RegisterUser(ctx context.Context, username, email, password string) (*models.User, error) {
	// Check both unique fields before hashing or inserting the password.
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM users WHERE username = $1 OR email = $2)`,
		username, email,
	).Scan(&exists)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to check existing user",
		}
	}
	if exists {
		return nil, &TokenError{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "User already exists",
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to secure password",
		}
	}

	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: string(hashedPassword),
	}

	// Insert user into database
	query := `
		INSERT INTO users (username, email, password_hash, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id, created_at`

	err = s.db.QueryRow(ctx, query, user.Username, user.Email, user.PasswordHash).
		Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, &TokenError{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: "User already exists",
			}
		}
		return nil, &TokenError{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to create user",
		}
	}
	user.PasswordHash = ""

	return user, nil
}

// RevokeToken revokes all tokens for a user
func (s *Server) RevokeToken(ctx context.Context, userID int64) error {
	if userID <= 0 {
		return fmt.Errorf("invalid user ID")
	}
	if s.db != nil {
		if _, err := s.db.Exec(ctx, `DELETE FROM sessions WHERE user_id = $1`, userID); err != nil {
			return fmt.Errorf("failed to revoke refresh sessions: %w", err)
		}
	}

	s.logger.Info("Refresh sessions revoked for user", "user_id", userID)
	return nil
}

// RevokeTokenString revokes a refresh-token session. Per RFC 7009, malformed
// or unknown tokens are treated as already revoked and do not reveal token
// metadata to callers.
func (s *Server) RevokeTokenString(ctx context.Context, tokenString string) error {
	token, err := s.parseSignedToken(tokenString)
	if err != nil || !token.Valid {
		return nil
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil
	}
	userID, ok := claimInt64(claims["user_id"])
	if !ok || userID <= 0 {
		return nil
	}

	if s.db == nil {
		return nil
	}

	if tokenType, tokenTypeOK := claims["type"].(string); tokenTypeOK && tokenType == refreshTokenType {
		if refreshID, ok := claims["jti"].(string); ok && refreshID != "" {
			_, err = s.db.Exec(ctx,
				`DELETE FROM sessions WHERE id = $1 AND user_id = $2 AND refresh_token = $3`,
				refreshID, userID, hashToken(tokenString))
			return err
		}
	}

	return s.RevokeToken(ctx, userID)
}

func (s *Server) parseSignedToken(tokenString string) (*jwt.Token, error) {
	if s.keyRing == nil {
		return nil, fmt.Errorf("JWT key configuration is invalid")
	}

	return s.keyRing.Parse(tokenString, jwt.WithIssuer("maigo-oauth2"))
}

// ParseAccessToken validates an access token for the OAuth browser session.
func (s *Server) ParseAccessToken(tokenString string) (*jwt.Token, error) {
	if s.keyRing == nil {
		return nil, fmt.Errorf("JWT key configuration is invalid")
	}

	return s.keyRing.Parse(tokenString, jwt.WithIssuer("maigo-oauth2"), jwt.WithAudience("maigo-api"))
}

func claimInt64(value any) (int64, bool) {
	switch value := value.(type) {
	case float64:
		return int64(value), value == float64(int64(value))
	case int64:
		return value, true
	case int:
		return int64(value), true
	default:
		return 0, false
	}
}

func hashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

// Helper methods for database operations

// getClient retrieves OAuth client by ID
func (s *Server) getClient(ctx context.Context, clientID string) (*models.OAuthClient, error) {
	query := `SELECT id, name, redirect_uri, created_at FROM oauth_clients WHERE id = $1`

	var client models.OAuthClient
	err := s.db.QueryRow(ctx, query, clientID).Scan(
		&client.ID, &client.Name, &client.RedirectURI, &client.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("client not found: %w", err)
	}

	return &client, nil
}

// validateRedirectURI validates redirect URI against registered client URI
func (s *Server) validateRedirectURI(client *models.OAuthClient, redirectURI string) bool {
	if client == nil || ValidateRedirectURI(client.RedirectURI) != nil || ValidateRedirectURI(redirectURI) != nil {
		return false
	}

	// Exact matches are the normal OAuth rule.
	if client.RedirectURI == redirectURI {
		return true
	}

	// The CLI may choose another local port when 8000 is busy. Permit that
	// narrow loopback variation while keeping scheme, host, path, and query
	// fixed. This avoids prefix checks such as "localhost.evil.example".
	registered, registeredErr := url.Parse(client.RedirectURI)
	requested, requestedErr := url.Parse(redirectURI)
	if registeredErr != nil || requestedErr != nil || registered.User != nil || requested.User != nil {
		return false
	}
	if registered.Scheme != "http" || requested.Scheme != "http" ||
		!strings.EqualFold(registered.Hostname(), "localhost") ||
		!strings.EqualFold(requested.Hostname(), "localhost") ||
		registered.Path != requested.Path || registered.RawQuery != requested.RawQuery ||
		requested.Port() == "" {
		return false
	}

	return true
}

// storeAuthorizationCodeWithUser stores authorization code with PKCE parameters and specific user ID
func (s *Server) storeAuthorizationCodeWithUser(ctx context.Context, authCode *models.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes 
		(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`

	_, err := s.db.Exec(ctx, query,
		authCode.Code,
		authCode.ClientID,
		authCode.UserID, // Use the provided user ID instead of hardcoding
		authCode.RedirectURI,
		authCode.Scope,
		authCode.CodeChallenge,
		authCode.CodeChallengeMethod,
		authCode.ExpiresAt,
		authCode.Used,
	)

	return err
}

// getAuthorizationCode retrieves authorization code from database
func (s *Server) getAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	query := `
		SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, 
		       code_challenge_method, expires_at, used, created_at
		FROM authorization_codes 
		WHERE code = $1`

	var authCode models.AuthorizationCode
	err := s.db.QueryRow(ctx, query, code).Scan(
		&authCode.Code,
		&authCode.ClientID,
		&authCode.UserID,
		&authCode.RedirectURI,
		&authCode.Scope,
		&authCode.CodeChallenge,
		&authCode.CodeChallengeMethod,
		&authCode.ExpiresAt,
		&authCode.Used,
		&authCode.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("authorization code not found: %w", err)
	}

	return &authCode, nil
}

// markAuthorizationCodeUsed marks authorization code as used
func (s *Server) markAuthorizationCodeUsed(ctx context.Context, code string) error {
	result, err := s.db.Exec(ctx,
		`UPDATE authorization_codes SET used = true WHERE code = $1 AND used = false AND expires_at > NOW()`,
		code)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("authorization code already used or expired")
	}
	return nil
}

// getUserByID retrieves user by ID
func (s *Server) getUserByID(ctx context.Context, userID int64) (*models.User, error) {
	query := `SELECT id, username, email, created_at FROM users WHERE id = $1`

	var user models.User
	err := s.db.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Username, &user.Email, &user.CreatedAt,
	)

	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	return &user, nil
}

// getUserByUsernameOrEmail gets a user by username or email
func (s *Server) getUserByUsernameOrEmail(ctx context.Context, usernameOrEmail string) (*models.User, error) {
	var user models.User
	query := `
		SELECT id, username, email, password_hash, created_at
		FROM users 
		WHERE username = $1 OR email = $1`

	err := s.db.QueryRow(ctx, query, usernameOrEmail).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash, &user.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	return &user, nil
}

// EnsureDefaultOAuthClient creates default CLI client if it doesn't exist
func (s *Server) EnsureDefaultOAuthClient(ctx context.Context) error {
	// Check if client already exists
	_, err := s.getClient(ctx, DefaultCLIClientID)
	if err == nil {
		// Client already exists
		return nil
	}

	// Create default CLI client with all required fields
	query := `
		INSERT INTO oauth_clients (id, secret, name, redirect_uri, created_at)
		VALUES ($1, $2, $3, $4, NOW())
		ON CONFLICT (id) DO UPDATE SET
			secret = EXCLUDED.secret,
			name = EXCLUDED.name,
			redirect_uri = EXCLUDED.redirect_uri`

	_, err = s.db.Exec(ctx, query,
		DefaultCLIClientID,
		DefaultCLIClientSecret,
		DefaultCLIClientName,
		DefaultCLIRedirectURI,
	)

	if err != nil {
		return fmt.Errorf("failed to create default CLI client: %w", err)
	}

	s.logger.Info("Created default CLI OAuth client", "client_id", DefaultCLIClientID)
	return nil
}
