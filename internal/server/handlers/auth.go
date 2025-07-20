// Package handlers contains HTTP handlers for Maigo server endpoints.
package handlers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// AuthHandler handles authentication operations
type AuthHandler struct {
	db          *pgxpool.Pool
	config      *config.Config
	logger      *logger.Logger
	oauthServer *oauth.Server
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(db *pgxpool.Pool, cfg *config.Config, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		db:          db,
		config:      cfg,
		logger:      log,
		oauthServer: oauth.NewServer(db, cfg, log.Logger),
	}
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// RegisterRequest represents the registration request body
type RegisterRequest struct {
	Username string `json:"username" binding:"required,min=3,max=50"`
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required,min=6"`
}

// RefreshTokenRequest represents the refresh token request body
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// TokenResponse represents a token response
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// Login authenticates a user and returns tokens
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid login request", "error", err)
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid login request", err.Error())
		return
	}

	// Authenticate user
	tokens, err := h.oauthServer.AuthenticateUser(c.Request.Context(), req.Username, req.Password)
	if err != nil {
		h.logger.Error("Authentication failed", "username", req.Username, "error", err)
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "Invalid credentials", nil)
		return
	}

	h.logger.Info("User logged in successfully", "username", req.Username)
	c.JSON(http.StatusOK, tokens)
}

// Register creates a new user account
func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid registration request", "error", err)
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid registration request", err.Error())
		return
	}

	// Create user
	user, err := h.oauthServer.RegisterUser(c.Request.Context(), req.Username, req.Email, req.Password)
	if err != nil {
		h.logger.Error("User registration failed", "username", req.Username, "email", req.Email, "error", err)
		SendAPIError(c, http.StatusConflict, "conflict", "Username or email already exists", nil)
		return
	}

	// Generate tokens for new user
	tokens, err := h.oauthServer.GenerateTokenPair(c.Request.Context(), user)
	if err != nil {
		h.logger.Error("Token generation failed after registration", "user_id", user.ID, "error", err)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error",
			"Failed to generate authentication tokens", nil)
		return
	}

	h.logger.Info("User registered successfully", "username", req.Username, "user_id", user.ID)
	c.JSON(http.StatusCreated, gin.H{
		"message": "Registration successful",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
		},
		"tokens": tokens,
	})
}

// RefreshToken refreshes an access token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		h.logger.Error("Invalid refresh token request", "error", err)
		SendAPIError(c, http.StatusBadRequest, "bad_request", "Invalid refresh token request", err.Error())
		return
	}

	// Refresh token
	tokens, err := h.oauthServer.RefreshAccessToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		h.logger.Error("Token refresh failed", "error", err)
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "Invalid or expired refresh token", nil)
		return
	}

	h.logger.Info("Token refreshed successfully")
	c.JSON(http.StatusOK, tokens)
}

// Logout invalidates the user's tokens
func (h *AuthHandler) Logout(c *gin.Context) {
	// Get user ID from context (set by auth middleware)
	userIDInterface, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context during logout")
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "User not found in context", nil)
		return
	}

	// Convert user ID to int64
	var userID int64
	switch v := userIDInterface.(type) {
	case int64:
		userID = v
	case float64:
		userID = int64(v)
	default:
		h.logger.Error("Invalid user ID type in context", "type", fmt.Sprintf("%T", v))
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Invalid user ID format", nil)
		return
	}

	// Revoke refresh token
	err := h.oauthServer.RevokeToken(c.Request.Context(), userID)
	if err != nil {
		h.logger.Error("Token revocation failed", "user_id", userID, "error", err)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to logout", nil)
		return
	}

	h.logger.Info("User logged out successfully", "user_id", userID)
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetProfile returns the authenticated user's profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	// Get user info from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		h.logger.Error("User ID not found in context")
		SendAPIError(c, http.StatusUnauthorized, "unauthorized", "User not found in context", nil)
		return
	}

	// Get user details from database
	var username, email string
	var createdAt string
	query := `SELECT username, email, created_at FROM users WHERE id = $1`
	err := h.db.QueryRow(c.Request.Context(), query, userID).Scan(&username, &email, &createdAt)
	if err != nil {
		h.logger.Error("Failed to get user profile", "user_id", userID, "error", err)
		SendAPIError(c, http.StatusInternalServerError, "internal_server_error", "Failed to retrieve user profile", nil)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":         userID,
		"username":   username,
		"email":      email,
		"created_at": createdAt,
	})
}
