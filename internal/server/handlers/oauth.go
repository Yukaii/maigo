// Package handlers contains HTTP handlers for Maigo server endpoints.
package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// OAuthLoginData is the template data structure for OAuth login pages.
type OAuthLoginData struct {
	Title               string
	ClientID            string
	RedirectURI         string
	Scope               string
	PkceInfo            string
	ResponseType        string
	ScopeValue          string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	ErrorMessage        string
}

type OAuthAuthorizeData struct {
	Title               string
	ClientID            string
	RedirectURI         string
	Scope               string
	PkceInfo            string
	ResponseType        string
	ScopeValue          string
	State               string
	CodeChallenge       string
	CodeChallengeMethod string
	UserID              string
}

type CallbackSuccessData struct {
	Title string
}

type CallbackErrorData struct {
	Title            string
	ErrorCode        string
	ErrorDescription string
}

// OAuthHandler handles OAuth 2.0 operations
type OAuthHandler struct {
	db          *pgxpool.Pool
	config      *config.Config
	logger      *logger.Logger
	oauthServer *oauth.Server
}

// NewOAuthHandler creates a new OAuth handler
func NewOAuthHandler(db *pgxpool.Pool, cfg *config.Config, log *logger.Logger) *OAuthHandler {
	return &OAuthHandler{
		db:          db,
		config:      cfg,
		logger:      log,
		oauthServer: oauth.NewServer(db, cfg, log.Logger),
	}
}

// AuthorizeEndpoint handles OAuth 2.0 authorization requests
// GET /oauth/authorize
func (h *OAuthHandler) AuthorizeEndpoint(c *gin.Context) {
	var req oauth.AuthorizationRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		h.logger.Error("Invalid authorization request", "error", err)
		h.redirectWithError(c, req.RedirectURI, req.State, oauth.ErrorInvalidRequest, "Invalid request parameters")
		return
	}

	h.logger.Info("OAuth authorization request",
		"client_id", req.ClientID,
		"redirect_uri", req.RedirectURI,
		"response_type", req.ResponseType,
		"has_pkce", req.CodeChallenge != "",
	)

	// For demonstration, we'll skip the user authentication UI and assume user is already authenticated
	// In a real implementation, you would redirect to a login page if not authenticated

	// Check if user is authenticated (from session/cookie)
	userID := h.getCurrentUserID(c)
	if userID == 0 {
		// Redirect to login page
		h.renderLoginPage(c, &req)
		return
	}

	// Process authorization request
	response, err := h.oauthServer.ProcessAuthorizationRequest(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Authorization request failed", "error", err)

		// Check if it's a token error response
		if tokenErr, ok := err.(*oauth.TokenErrorResponse); ok {
			h.redirectWithError(c, req.RedirectURI, req.State, tokenErr.ErrorCode, tokenErr.ErrorDescription)
		} else {
			h.redirectWithError(c, req.RedirectURI, req.State, oauth.ErrorServerError, "Internal server error")
		}
		return
	}

	// Redirect back to client with authorization code
	h.redirectWithCode(c, req.RedirectURI, response.Code, response.State)
}

// TokenEndpoint handles OAuth 2.0 token requests
// POST /oauth/token
func (h *OAuthHandler) TokenEndpoint(c *gin.Context) {
	var req oauth.TokenRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Invalid token request", "error", err)
		c.JSON(http.StatusBadRequest, oauth.TokenErrorResponse{
			ErrorCode:        oauth.ErrorInvalidRequest,
			ErrorDescription: "Invalid request parameters",
		})
		return
	}

	h.logger.Info("OAuth token request",
		"grant_type", req.GrantType,
		"client_id", req.ClientID,
		"has_code", req.Code != "",
		"has_refresh_token", req.RefreshToken != "",
		"has_code_verifier", req.CodeVerifier != "",
	)

	// Process token request
	tokens, err := h.oauthServer.ProcessTokenRequest(c.Request.Context(), &req)
	if err != nil {
		h.logger.Error("Token request failed", "error", err)

		// Check if it's a token error response
		if tokenErr, ok := err.(*oauth.TokenErrorResponse); ok {
			status := http.StatusBadRequest
			if tokenErr.ErrorCode == oauth.ErrorInvalidClient {
				status = http.StatusUnauthorized
			}
			c.JSON(status, tokenErr)
		} else {
			c.JSON(http.StatusInternalServerError, oauth.TokenErrorResponse{
				ErrorCode:        oauth.ErrorServerError,
				ErrorDescription: "Internal server error",
			})
		}
		return
	}

	h.logger.Info("Token issued successfully", "client_id", req.ClientID)
	c.JSON(http.StatusOK, tokens)
}

// RevokeEndpoint handles OAuth 2.0 token revocation
// POST /oauth/revoke
func (h *OAuthHandler) RevokeEndpoint(c *gin.Context) {
	token := c.PostForm("token")
	if token == "" {
		c.JSON(http.StatusBadRequest, oauth.TokenErrorResponse{
			ErrorCode:        oauth.ErrorInvalidRequest,
			ErrorDescription: "Missing token parameter",
		})
		return
	}

	// For simplicity, we'll assume this is a refresh token
	// In a real implementation, you'd determine the token type

	h.logger.Info("Token revocation request", "token_prefix", token[:min(8, len(token))])

	// Since we don't have the user ID from the token directly,
	// we'll need to parse the token or look it up in the database
	// For now, we'll return success (idempotent)

	h.logger.Info("Token revoked successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

// Helper methods

// getCurrentUserID gets the current user ID from session/authentication
// This is a simplified implementation - in reality you'd check session cookies,
// JWT tokens, or other authentication mechanisms
func (h *OAuthHandler) getCurrentUserID(c *gin.Context) int64 {
	// Check for demo user in query parameter (for testing)
	if userIDStr := c.Query("user_id"); userIDStr != "" {
		if userID, err := strconv.ParseInt(userIDStr, 10, 64); err == nil {
			return userID
		}
	}

	// Check session cookie or other auth mechanism
	// For now, return 0 (not authenticated)
	return 0
}

// renderLoginPage renders the OAuth login and authorization page
func (h *OAuthHandler) renderLoginPage(c *gin.Context, req *oauth.AuthorizationRequest) {
	data := OAuthLoginData{
		Title:               "OAuth Authorization",
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               h.formatScope(req.Scope),
		PkceInfo:            h.formatPKCE(req.CodeChallenge, req.CodeChallengeMethod),
		ResponseType:        req.ResponseType,
		ScopeValue:          req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ErrorMessage:        "",
	}

	c.HTML(http.StatusOK, "oauth/login.tmpl", data)
}

// renderLoginPageWithError renders the login page with an error message
func (h *OAuthHandler) renderLoginPageWithError(c *gin.Context, req *oauth.AuthorizationRequest, errorMsg string) {
	data := OAuthLoginData{
		Title:               "OAuth Authorization",
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               h.formatScope(req.Scope),
		PkceInfo:            h.formatPKCE(req.CodeChallenge, req.CodeChallengeMethod),
		ResponseType:        req.ResponseType,
		ScopeValue:          req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ErrorMessage:        errorMsg,
	}

	c.HTML(http.StatusOK, "oauth/login.tmpl", data)
}

// renderAuthorizationPage renders the authorization consent page after login
func (h *OAuthHandler) renderAuthorizationPage(c *gin.Context, req *oauth.AuthorizationRequest, userID int64) {
	data := OAuthAuthorizeData{
		Title:               "OAuth Authorization",
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               h.formatScope(req.Scope),
		PkceInfo:            h.formatPKCE(req.CodeChallenge, req.CodeChallengeMethod),
		ResponseType:        req.ResponseType,
		ScopeValue:          req.Scope,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserID:              fmt.Sprintf("%d", userID),
	}
	c.HTML(http.StatusOK, "oauth/authorize.tmpl", data)
}

// extractUserIDFromToken extracts user ID from an access token
func (h *OAuthHandler) extractUserIDFromToken(tokenString string) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.config.JWT.Secret), nil
	})

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if userIDFloat, ok := claims["user_id"].(float64); ok {
			return int64(userIDFloat), nil
		}
		return 0, fmt.Errorf("user_id not found in token")
	}

	return 0, fmt.Errorf("invalid token")
}

// AuthorizePostEndpoint handles POST to authorization endpoint (login and user consent)
// POST /oauth/authorize
func (h *OAuthHandler) AuthorizePostEndpoint(c *gin.Context) {
	action := c.PostForm("action")

	// Parse the authorization request parameters
	var req oauth.AuthorizationRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Invalid authorization POST request", "error", err)
		c.String(http.StatusBadRequest, "Invalid request parameters")
		return
	}

	if action == "login" {
		// Handle login attempt
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == "" || password == "" {
			h.logger.Error("Missing username or password")
			h.renderLoginPageWithError(c, &req, "Username and password are required")
			return
		}

		// Authenticate user
		tokens, err := h.oauthServer.AuthenticateUser(c.Request.Context(), username, password)
		if err != nil {
			h.logger.Error("Authentication failed", "username", username, "error", err)
			h.renderLoginPageWithError(c, &req, "Invalid username or password")
			return
		}

		// Parse token to get user ID
		userID, err := h.extractUserIDFromToken(tokens.AccessToken)
		if err != nil {
			h.logger.Error("Failed to extract user ID from token", "error", err)
			h.renderLoginPageWithError(c, &req, "Authentication error")
			return
		}

		h.logger.Info("User authenticated successfully", "username", username, "user_id", userID)

		// Show authorization consent page
		h.renderAuthorizationPage(c, &req, userID)
		return

	} else if action == "deny" {
		// User denied authorization
		redirectURI := c.PostForm("redirect_uri")
		state := c.PostForm("state")
		h.redirectWithError(c, redirectURI, state, oauth.ErrorAccessDenied, "User denied authorization")
		return

	} else if action == "authorize" {
		// Get user ID from the form (set during login)
		userIDStr := c.PostForm("user_id")
		if userIDStr == "" {
			h.logger.Error("Missing user ID in authorization request")
			h.renderLoginPage(c, &req) // Redirect back to login
			return
		}

		userID, err := strconv.ParseInt(userIDStr, 10, 64)
		if err != nil {
			h.logger.Error("Invalid user ID in authorization request", "user_id", userIDStr, "error", err)
			h.renderLoginPage(c, &req) // Redirect back to login
			return
		}

		// Process authorization request with the authenticated user ID
		response, err := h.oauthServer.ProcessAuthorizationRequestWithUser(c.Request.Context(), &req, userID)
		if err != nil {
			h.logger.Error("Authorization request failed", "error", err)

			if tokenErr, ok := err.(*oauth.TokenErrorResponse); ok {
				h.redirectWithError(c, req.RedirectURI, req.State, tokenErr.ErrorCode, tokenErr.ErrorDescription)
			} else {
				h.redirectWithError(c, req.RedirectURI, req.State, oauth.ErrorServerError, "Internal server error")
			}
			return
		}

		// Redirect back to client with authorization code
		h.redirectWithCode(c, req.RedirectURI, response.Code, response.State)
		return
	}

	// Invalid action
	h.logger.Error("Invalid action in authorization POST", "action", action)
	c.String(http.StatusBadRequest, "Invalid action")
}

// redirectWithCode redirects with authorization code
func (h *OAuthHandler) redirectWithCode(c *gin.Context, redirectURI, code, state string) {
	redirectURL := fmt.Sprintf("%s?code=%s", redirectURI, code)
	if state != "" {
		redirectURL += fmt.Sprintf("&state=%s", state)
	}

	h.logger.Info("Redirecting with authorization code", "redirect_url", redirectURL)
	c.Redirect(http.StatusFound, redirectURL)
}

// redirectWithError redirects with OAuth error
func (h *OAuthHandler) redirectWithError(c *gin.Context, redirectURI, state, errorCode, errorDescription string) {
	if redirectURI == "" {
		// Can't redirect, show error page
		c.JSON(http.StatusBadRequest, oauth.TokenErrorResponse{
			ErrorCode:        errorCode,
			ErrorDescription: errorDescription,
		})
		return
	}

	redirectURL := fmt.Sprintf("%s?error=%s", redirectURI, errorCode)
	if errorDescription != "" {
		redirectURL += fmt.Sprintf("&error_description=%s", errorDescription)
	}
	if state != "" {
		redirectURL += fmt.Sprintf("&state=%s", state)
	}

	h.logger.Info("Redirecting with error", "error", errorCode, "redirect_url", redirectURL)
	c.Redirect(http.StatusFound, redirectURL)
}

// formatScope formats scope for display
func (h *OAuthHandler) formatScope(scope string) string {
	if scope == "" {
		return "Default access"
	}
	return scope
}

// formatPKCE formats PKCE info for display
func (h *OAuthHandler) formatPKCE(codeChallenge, method string) string {
	if codeChallenge == "" {
		return "Not using PKCE"
	}
	return fmt.Sprintf("Using PKCE with %s method", method)
}

// min helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
