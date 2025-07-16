// Package oauth implements OAuth 2.0 and PKCE logic for Maigo.
package oauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
)

// Default CLI client constants - must match CLI package constants
const (
	DefaultCLIClientID     = "maigo-cli"
	DefaultCLIClientSecret = "cli-client-secret-not-used-with-pkce"
	DefaultCLIClientName   = "Maigo CLI Application"
	DefaultCLIRedirectURI  = "http://localhost:8000/callback"
)

// Server handles OAuth2 operations
type Server struct {
	db     *pgxpool.Pool
	config *config.Config
	logger *slog.Logger
}

// NewServer creates a new OAuth2 server
func NewServer(db *pgxpool.Pool, cfg *config.Config, logger *slog.Logger) *Server {
	return &Server{
		db:     db,
		config: cfg,
		logger: logger,
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

// TokenErrorResponse represents an OAuth 2.0 error response
type TokenErrorResponse struct {
	ErrorCode        string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
	ErrorURI         string `json:"error_uri,omitempty"`
}

// Error implements the error interface for TokenErrorResponse
func (e *TokenErrorResponse) Error() string {
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
func (s *Server) ProcessAuthorizationRequest(ctx context.Context, req *AuthorizationRequest) (*AuthorizeResponse, error) {
	// Validate response type
	if req.ResponseType != ResponseTypeCode {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorUnsupportedResponseType,
			ErrorDescription: "Only 'code' response type is supported",
		}
	}

	// Validate client
	client, err := s.getClient(ctx, req.ClientID)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidClient,
			ErrorDescription: "Invalid client_id",
		}
	}

	// Validate redirect URI
	if !s.validateRedirectURI(client, req.RedirectURI) {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Invalid redirect_uri",
		}
	}

	// Validate PKCE parameters if present
	if req.CodeChallenge != "" {
		if err := ValidateCodeChallenge(req.CodeChallenge); err != nil {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_challenge: %v", err),
			}
		}

		// Default to plain if method not specified
		if req.CodeChallengeMethod == "" {
			req.CodeChallengeMethod = PKCEMethodPlain
		}

		if err := ValidateCodeChallengeMethod(req.CodeChallengeMethod); err != nil {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_challenge_method: %v", err),
			}
		}
	}

	// Generate authorization code
	authCode, err := GenerateAuthorizationCode()
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to generate authorization code",
		}
	}

	// Store authorization code with PKCE parameters
	expiresAt := time.Now().Add(10 * time.Minute) // 10 minute expiry
	err = s.storeAuthorizationCode(ctx, &models.AuthorizationCode{
		Code:                authCode,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           expiresAt,
		Used:                false,
	})

	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to store authorization code",
		}
	}

	return &AuthorizeResponse{
		Code:  authCode,
		State: req.State,
	}, nil
}

// ProcessAuthorizationRequestWithUser processes OAuth 2.0 authorization request with a specific user ID
func (s *Server) ProcessAuthorizationRequestWithUser(ctx context.Context, req *AuthorizationRequest, userID int64) (*AuthorizeResponse, error) {
	// Validate response type
	if req.ResponseType != ResponseTypeCode {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorUnsupportedResponseType,
			ErrorDescription: "Only 'code' response type is supported",
		}
	}

	// Validate client
	client, err := s.getClient(ctx, req.ClientID)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidClient,
			ErrorDescription: "Invalid client_id",
		}
	}

	// Validate redirect URI
	if !s.validateRedirectURI(client, req.RedirectURI) {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Invalid redirect_uri",
		}
	}

	// Validate PKCE parameters if present
	if req.CodeChallenge != "" {
		if err := ValidateCodeChallenge(req.CodeChallenge); err != nil {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_challenge: %v", err),
			}
		}

		// Default to plain if method not specified
		if req.CodeChallengeMethod == "" {
			req.CodeChallengeMethod = PKCEMethodPlain
		}

		if err := ValidateCodeChallengeMethod(req.CodeChallengeMethod); err != nil {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_challenge_method: %v", err),
			}
		}
	}

	// Generate authorization code
	authCode, err := GenerateAuthorizationCode()
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to generate authorization code",
		}
	}

	// Store authorization code with PKCE parameters and the provided user ID
	expiresAt := time.Now().Add(10 * time.Minute) // 10 minute expiry
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
		return nil, &TokenErrorResponse{
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
	switch req.GrantType {
	case GrantTypeAuthorizationCode:
		return s.processAuthorizationCodeGrant(ctx, req)
	case GrantTypeRefreshToken:
		return s.processRefreshTokenGrant(ctx, req)
	default:
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorUnsupportedGrantType,
			ErrorDescription: fmt.Sprintf("Grant type '%s' is not supported", req.GrantType),
		}
	}
}

// processAuthorizationCodeGrant processes authorization code grant with PKCE
func (s *Server) processAuthorizationCodeGrant(ctx context.Context, req *TokenRequest) (*TokenPair, error) {
	// Validate required parameters
	if req.Code == "" {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: code",
		}
	}

	if req.RedirectURI == "" {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: redirect_uri",
		}
	}

	// Validate client
	_, err := s.getClient(ctx, req.ClientID)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidClient,
			ErrorDescription: "Invalid client_id",
		}
	}

	// Get and validate authorization code
	authCode, err := s.getAuthorizationCode(ctx, req.Code)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid or expired authorization code",
		}
	}

	// Check if code is already used
	if authCode.Used {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Authorization code already used",
		}
	}

	// Check if code is expired
	if time.Now().After(authCode.ExpiresAt) {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Authorization code expired",
		}
	}

	// Validate client matches
	if authCode.ClientID != req.ClientID {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Client mismatch",
		}
	}

	// Validate redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Redirect URI mismatch",
		}
	}

	// Validate PKCE if code challenge was provided
	if authCode.CodeChallenge != "" {
		if req.CodeVerifier == "" {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: "Missing required parameter: code_verifier",
			}
		}

		if err := ValidateCodeVerifier(req.CodeVerifier); err != nil {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidRequest,
				ErrorDescription: fmt.Sprintf("Invalid code_verifier: %v", err),
			}
		}

		// Verify PKCE challenge
		if !VerifyCodeChallenge(req.CodeVerifier, authCode.CodeChallenge, authCode.CodeChallengeMethod) {
			return nil, &TokenErrorResponse{
				ErrorCode:        ErrorInvalidGrant,
				ErrorDescription: "PKCE verification failed",
			}
		}
	}

	// Mark authorization code as used
	if err := s.markAuthorizationCodeUsed(ctx, req.Code); err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to mark authorization code as used",
		}
	}

	// Get user from authorization code
	user, err := s.getUserByID(ctx, authCode.UserID)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "User not found",
		}
	}

	// Generate tokens
	return s.GenerateTokenPair(ctx, user)
}

// GenerateTokenPair generates access and refresh token pair
func (s *Server) GenerateTokenPair(ctx context.Context, user *models.User) (*TokenPair, error) {
	// Generate access token
	accessClaims := jwt.MapClaims{
		"user_id": user.ID,
		"email":   user.Email,
		"exp":     time.Now().Add(time.Hour).Unix(), // 1 hour expiration
		"iat":     time.Now().Unix(),
		"iss":     "maigo-oauth2",
		"aud":     "maigo-api",
	}

	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	accessTokenString, err := accessToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign access token: %w", err)
	}

	// Generate refresh token
	refreshClaims := jwt.MapClaims{
		"user_id": user.ID,
		"exp":     time.Now().Add(time.Hour * 24 * 30).Unix(), // 30 days expiration
		"iat":     time.Now().Unix(),
		"iss":     "maigo-oauth2",
		"type":    "refresh",
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(s.config.JWT.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessTokenString,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour in seconds
		RefreshToken: refreshTokenString,
	}, nil
}

// RefreshAccessToken creates a new access token from a refresh token
func (s *Server) RefreshAccessToken(ctx context.Context, refreshTokenString string) (*TokenPair, error) {
	// Parse and validate refresh token
	token, err := jwt.Parse(refreshTokenString, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(s.config.JWT.Secret), nil
	})

	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid refresh token",
		}
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid refresh token",
		}
	}

	// Check if token type is refresh
	if tokenType, ok := claims["type"]; !ok || tokenType != "refresh" {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Token is not a refresh token",
		}
	}

	// Extract user ID
	userIDFloat, ok := claims["user_id"].(float64)
	if !ok {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid user ID in refresh token",
		}
	}
	userID := int64(userIDFloat)

	// Get user
	user, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, &TokenErrorResponse{
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
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "Missing required parameter: refresh_token",
		}
	}

	return s.RefreshAccessToken(ctx, req.RefreshToken)
}

// GetAuthorizationURL constructs OAuth 2.0 authorization URL with PKCE
func (s *Server) GetAuthorizationURL(clientID, redirectURI, scope, state string, pkce *PKCEParams) (string, error) {
	// Construct base URL from config
	protocol := "http"
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
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid username or password",
		}
	}

	// Verify password (assuming password is stored as hashed for now)
	if user.PasswordHash != password {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidGrant,
			ErrorDescription: "Invalid username or password",
		}
	}

	// Generate token pair
	return s.GenerateTokenPair(ctx, user)
}

// RegisterUser creates a new user account and returns the user
func (s *Server) RegisterUser(ctx context.Context, username, email, password string) (*models.User, error) {
	// Check if user already exists
	existingUser, err := s.getUserByUsernameOrEmail(ctx, email)
	if err != nil {
		// Log error but continue - absence of user is expected for registration
		s.logger.Debug("User lookup failed during registration", "error", err)
	}
	if existingUser != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorInvalidRequest,
			ErrorDescription: "User already exists",
		}
	}

	// Create new user (in a real implementation, password should be hashed)
	user := &models.User{
		Username:     username,
		Email:        email,
		PasswordHash: password, // Should be hashed in production!
	}

	// Insert user into database
	query := `
		INSERT INTO users (username, email, password_hash, created_at)
		VALUES ($1, $2, $3, NOW())
		RETURNING id, created_at`

	err = s.db.QueryRow(ctx, query, user.Username, user.Email, user.PasswordHash).
		Scan(&user.ID, &user.CreatedAt)
	if err != nil {
		return nil, &TokenErrorResponse{
			ErrorCode:        ErrorServerError,
			ErrorDescription: "Failed to create user",
		}
	}

	return user, nil
}

// RevokeToken revokes all tokens for a user
func (s *Server) RevokeToken(ctx context.Context, userID int64) error {
	// In a production system, you would maintain a token blacklist or
	// token revocation table. For now, this is a no-op since we're using
	// stateless JWT tokens.
	// You could:
	// 1. Add tokens to a blacklist table
	// 2. Change the user's token version/salt
	// 3. Set token expiration in a cache

	s.logger.Info("Token revocation requested for user", "user_id", userID)
	return nil
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
	// For CLI applications, we allow exact match or localhost variations
	if client.RedirectURI == redirectURI {
		return true
	}

	// Allow localhost with different ports for CLI apps
	if strings.HasPrefix(client.RedirectURI, "http://localhost") &&
		strings.HasPrefix(redirectURI, "http://localhost") {
		return true
	}

	return false
}

// storeAuthorizationCode stores authorization code with PKCE parameters
func (s *Server) storeAuthorizationCode(ctx context.Context, authCode *models.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes 
		(code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`

	// For now, we'll use a default user ID since user authentication happens separately
	// In a real implementation, this would come from the authenticated user session
	userID := int64(1) // TODO: Get from authenticated user session

	_, err := s.db.Exec(ctx, query,
		authCode.Code,
		authCode.ClientID,
		userID,
		authCode.RedirectURI,
		authCode.Scope,
		authCode.CodeChallenge,
		authCode.CodeChallengeMethod,
		authCode.ExpiresAt,
		authCode.Used,
	)

	return err
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
		SELECT code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at, used, created_at
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
	query := `UPDATE authorization_codes SET used = true WHERE code = $1`
	_, err := s.db.Exec(ctx, query, code)
	return err
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
