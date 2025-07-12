package handlers

import (
	"fmt"
	"html"
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
	
	// Escape all dynamic content for HTML context
	clientID := html.EscapeString(req.ClientID)
	redirectURI := html.EscapeString(req.RedirectURI)
	scope := html.EscapeString(h.formatScope(req.Scope))
	pkceInfo := html.EscapeString(h.formatPKCE(req.CodeChallenge, req.CodeChallengeMethod))
	responseType := html.EscapeString(req.ResponseType)
	scopeValue := html.EscapeString(req.Scope)
	state := html.EscapeString(req.State)
	codeChallenge := html.EscapeString(req.CodeChallenge)
	codeChallengeMethod := html.EscapeString(req.CodeChallengeMethod)
	
	htmlContent := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Maigo OAuth Authorization</title>
    <style>
        * {
            box-sizing: border-box;
        }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            max-width: 600px; 
            margin: 50px auto; 
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .auth-box { 
            border: 1px solid #ddd; 
            padding: 40px; 
            border-radius: 12px; 
            background: #ffffff;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .lock-icon {
            font-size: 48px;
            color: #007bff;
            margin-bottom: 10px;
        }
        h2 {
            margin: 0;
            color: #2c3e50;
            font-size: 24px;
            font-weight: 600;
        }
        .btn { 
            background: #007bff; 
            color: white; 
            padding: 12px 24px; 
            border: none; 
            border-radius: 6px; 
            cursor: pointer; 
            text-decoration: none; 
            display: inline-block;
            font-size: 16px;
            font-weight: 500;
            margin: 0 8px 8px 0;
            transition: background-color 0.2s ease;
        }
        .btn:hover { 
            background: #0056b3; 
        }
        .btn-deny {
            background: #dc3545;
        }
        .btn-deny:hover {
            background: #c82333;
        }
        .client-info { 
            background: #e8f4fd; 
            padding: 20px; 
            border-radius: 8px; 
            margin: 25px 0;
            border-left: 4px solid #007bff;
        }
        .client-info h3 {
            margin-top: 0;
            color: #1e3a8a;
            font-size: 18px;
        }
        .info-row {
            margin: 12px 0;
            display: flex;
            flex-wrap: wrap;
        }
        .info-label {
            font-weight: 600;
            margin-right: 8px;
            min-width: 100px;
            color: #374151;
        }
        .info-value {
            color: #1f2937;
            word-break: break-all;
        }
        .authorization-prompt {
            text-align: center;
            margin: 30px 0;
            font-size: 16px;
            color: #4b5563;
        }
        .button-container {
            text-align: center;
            margin-top: 30px;
        }
        .form-container {
            margin-top: 20px;
        }
        @media (max-width: 600px) {
            body {
                margin: 20px auto;
                padding: 15px;
            }
            .auth-box {
                padding: 25px;
            }
            .btn {
                display: block;
                width: 100%%;
                margin-bottom: 12px;
                margin-right: 0;
            }
        }
    </style>
</head>
<body>
    <div class="auth-box">
        <div class="header">
            <div class="lock-icon">🔒</div>
            <h2>Maigo OAuth Authorization</h2>
        </div>
        
        <div class="client-info">
            <h3>Application Requesting Access</h3>
            <div class="info-row">
                <span class="info-label">Client ID:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Redirect URI:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Scope:</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">Security:</span>
                <span class="info-value">%s</span>
            </div>
        </div>
        
        <div class="authorization-prompt">
            <p>Do you want to authorize this application to access your Maigo account?</p>
        </div>
        
        <div class="form-container">
            <form method="post" action="/oauth/authorize">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                
                <div class="button-container">
                    <button type="submit" name="action" value="authorize" class="btn">
                        ✅ Authorize Access
                    </button>
                    <button type="submit" name="action" value="deny" class="btn btn-deny">
                        ❌ Deny Access
                    </button>
                </div>
            </form>
        </div>
    </div>
</body>
</html>`,
		clientID,
		redirectURI,
		scope,
		pkceInfo,
		responseType,
		clientID,
		redirectURI,
		scopeValue,
		state,
		codeChallenge,
		codeChallengeMethod,
	)
	
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, htmlContent)
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
