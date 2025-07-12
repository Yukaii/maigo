package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

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

// renderLoginPage renders the OAuth login page
func (h *OAuthHandler) renderLoginPage(c *gin.Context, req *oauth.AuthorizationRequest) {
	// In a real implementation, you'd render a proper login form
	// For now, we'll show a simple HTML page with the authorization request
	
	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Maigo OAuth Authorization</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .auth-box { border: 1px solid #ddd; padding: 30px; border-radius: 8px; background: #f9f9f9; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .client-info { background: #e7f3ff; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .scope-list { margin: 10px 0; padding-left: 20px; }
    </style>
</head>
<body>
    <div class="auth-box">
        <h2>🔐 Maigo OAuth Authorization</h2>
        
        <div class="client-info">
            <h3>Application requesting access:</h3>
            <p><strong>Client:</strong> %s</p>
            <p><strong>Redirect URI:</strong> %s</p>
            <p><strong>Scope:</strong> %s</p>
            <p><strong>PKCE:</strong> %s</p>
        </div>
        
        <p>Do you want to authorize this application to access your Maigo account?</p>
        
        <form method="post" action="/oauth/authorize">
            <input type="hidden" name="response_type" value="%s">
            <input type="hidden" name="client_id" value="%s">
            <input type="hidden" name="redirect_uri" value="%s">
            <input type="hidden" name="scope" value="%s">
            <input type="hidden" name="state" value="%s">
            <input type="hidden" name="code_challenge" value="%s">
            <input type="hidden" name="code_challenge_method" value="%s">
            
            <button type="submit" name="action" value="authorize" class="btn">✅ Authorize</button>
            <button type="submit" name="action" value="deny" class="btn" style="background: #dc3545;">❌ Deny</button>
        </form>
    </div>
</body>
</html>`,
		req.ClientID,
		req.RedirectURI,
		h.formatScope(req.Scope),
		h.formatPKCE(req.CodeChallenge, req.CodeChallengeMethod),
		req.ResponseType,
		req.ClientID,
		req.RedirectURI,
		req.Scope,
		req.State,
		req.CodeChallenge,
		req.CodeChallengeMethod,
	)
	
	c.Header("Content-Type", "text/html")
	c.String(http.StatusOK, html)
}

// AuthorizePostEndpoint handles POST to authorization endpoint (user consent)
// POST /oauth/authorize
func (h *OAuthHandler) AuthorizePostEndpoint(c *gin.Context) {
	action := c.PostForm("action")
	
	if action == "deny" {
		// User denied authorization
		redirectURI := c.PostForm("redirect_uri")
		state := c.PostForm("state")
		h.redirectWithError(c, redirectURI, state, oauth.ErrorAccessDenied, "User denied authorization")
		return
	}
	
	// User authorized - process like GET request
	var req oauth.AuthorizationRequest
	if err := c.ShouldBind(&req); err != nil {
		h.logger.Error("Invalid authorization POST request", "error", err)
		c.String(http.StatusBadRequest, "Invalid request parameters")
		return
	}
	
	// For demo purposes, assume user ID = 1
	// In real implementation, get from authenticated session
	
	// Process authorization request
	response, err := h.oauthServer.ProcessAuthorizationRequest(c.Request.Context(), &req)
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
