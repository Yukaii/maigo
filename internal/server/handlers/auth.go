package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
)

// AuthHandler handles authentication operations
type AuthHandler struct {
	db     *pgxpool.Pool
	config *config.Config
	logger *logger.Logger
}

// NewAuthHandler creates a new auth handler
func NewAuthHandler(db *pgxpool.Pool, cfg *config.Config, log *logger.Logger) *AuthHandler {
	return &AuthHandler{
		db:     db,
		config: cfg,
		logger: log,
	}
}

// LoginRequest represents the login request body
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Bad Request",
			"message": err.Error(),
		})
		return
	}

	// TODO: Implement authentication logic
	// For now, return a placeholder token
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  "placeholder_access_token",
		RefreshToken: "placeholder_refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	})
}

// RefreshToken refreshes an access token
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	// TODO: Implement token refresh logic
	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  "new_placeholder_access_token",
		RefreshToken: "new_placeholder_refresh_token",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	})
}

// Logout invalidates the user's tokens
func (h *AuthHandler) Logout(c *gin.Context) {
	// TODO: Implement logout logic (token blacklisting)
	c.JSON(http.StatusOK, gin.H{
		"message": "Logged out successfully",
	})
}

// GetProfile returns the authenticated user's profile
func (h *AuthHandler) GetProfile(c *gin.Context) {
	// Get user info from context (set by auth middleware)
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "Unauthorized",
			"message": "User not found in context",
		})
		return
	}

	// TODO: Implement profile retrieval logic
	c.JSON(http.StatusOK, gin.H{
		"id":         userID,
		"username":   "placeholder_user",
		"email":      "user@example.com",
		"created_at": "2024-01-01T00:00:00Z",
	})
}
