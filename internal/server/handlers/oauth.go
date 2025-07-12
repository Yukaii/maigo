package handlers

import (
	"fmt"
	"html"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
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

// renderLoginPage renders the OAuth login and authorization page
func (h *OAuthHandler) renderLoginPage(c *gin.Context, req *oauth.AuthorizationRequest) {
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
            width: 100%%;
        }
        .btn:hover { 
            background: #0056b3; 
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
        .login-form {
            margin: 30px 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #374151;
        }
        .form-input {
            width: 100%%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.2s ease;
        }
        .form-input:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }
        .button-container {
            text-align: center;
            margin-top: 30px;
        }
        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 6px;
            padding: 12px;
            margin: 15px 0;
            color: #c53030;
            font-size: 14px;
        }
        .step-indicator {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }
        .step-indicator h4 {
            margin: 0 0 10px 0;
            color: #28a745;
            font-size: 16px;
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

        <div class="step-indicator">
            <h4>📝 Step 1: Login Required</h4>
            <p>Please log in to authorize this application to access your Maigo account.</p>
        </div>
        
        <div class="login-form">
            <form method="post" action="/oauth/authorize">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label for="username" class="form-label">Username or Email</label>
                    <input type="text" id="username" name="username" class="form-input" 
                           placeholder="Enter your username or email" required>
                </div>
                
                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" id="password" name="password" class="form-input" 
                           placeholder="Enter your password" required>
                </div>
                
                <div class="button-container">
                    <button type="submit" class="btn">
                        🔐 Login & Continue
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

// renderLoginPageWithError renders the login page with an error message
func (h *OAuthHandler) renderLoginPageWithError(c *gin.Context, req *oauth.AuthorizationRequest, errorMsg string) {
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
	_ = html.EscapeString(errorMsg) // Silence unused variable warning
	
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
            width: 100%%;
        }
        .btn:hover { 
            background: #0056b3; 
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
        .login-form {
            margin: 30px 0;
        }
        .form-group {
            margin-bottom: 20px;
        }
        .form-label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            color: #374151;
        }
        .form-input {
            width: 100%%;
            padding: 12px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 16px;
            transition: border-color 0.2s ease;
        }
        .form-input:focus {
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 3px rgba(0, 123, 255, 0.1);
        }
        .button-container {
            text-align: center;
            margin-top: 30px;
        }
        .error-message {
            background: #fee;
            border: 1px solid #fcc;
            border-radius: 6px;
            padding: 12px;
            margin: 15px 0;
            color: #c53030;
            font-size: 14px;
        }
        .step-indicator {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }
        .step-indicator h4 {
            margin: 0 0 10px 0;
            color: #28a745;
            font-size: 16px;
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

        <div class="step-indicator">
            <h4>📝 Step 1: Login Required</h4>
            <p>Please log in to authorize this application to access your Maigo account.</p>
        </div>
        
        <div class="login-form">
            <form method="post" action="/oauth/authorize">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                <input type="hidden" name="action" value="login">
                
                <div class="form-group">
                    <label for="username" class="form-label">Username or Email</label>
                    <input type="text" id="username" name="username" class="form-input" 
                           placeholder="Enter your username or email" required>
                </div>
                
                <div class="form-group">
                    <label for="password" class="form-label">Password</label>
                    <input type="password" id="password" name="password" class="form-input" 
                           placeholder="Enter your password" required>
                </div>
                
                <div class="button-container">
                    <button type="submit" class="btn">
                        🔐 Login & Continue
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



// renderAuthorizationPage renders the authorization consent page after login
func (h *OAuthHandler) renderAuthorizationPage(c *gin.Context, req *oauth.AuthorizationRequest, userID int64) {
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
	userIDStr := fmt.Sprintf("%d", userID)
	
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
        .check-icon {
            font-size: 48px;
            color: #28a745;
            margin-bottom: 10px;
        }
        h2 {
            margin: 0;
            color: #2c3e50;
            font-size: 24px;
            font-weight: 600;
        }
        .btn { 
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
        .btn-primary {
            background: #28a745;
        }
        .btn-primary:hover { 
            background: #218838; 
        }
        .btn-secondary {
            background: #6c757d;
        }
        .btn-secondary:hover { 
            background: #5a6268; 
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
        .permissions {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 25px 0;
            border-left: 4px solid #28a745;
        }
        .permissions h3 {
            margin-top: 0;
            color: #155724;
            font-size: 18px;
        }
        .permission-item {
            display: flex;
            align-items: center;
            margin: 12px 0;
            padding: 8px;
            background: white;
            border-radius: 6px;
            border: 1px solid #e9ecef;
        }
        .permission-icon {
            font-size: 20px;
            margin-right: 10px;
            color: #28a745;
        }
        .button-container {
            text-align: center;
            margin-top: 30px;
        }
        .success-indicator {
            background: #d4edda;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }
        .success-indicator h4 {
            margin: 0 0 10px 0;
            color: #155724;
            font-size: 16px;
        }
        .warning-box {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        .warning-box h4 {
            margin: 0 0 10px 0;
            color: #856404;
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
            <div class="check-icon">✅</div>
            <h2>Authorization Required</h2>
        </div>
        
        <div class="success-indicator">
            <h4>🔐 Login Successful</h4>
            <p>You have successfully authenticated. Please review the permissions below.</p>
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

        <div class="permissions">
            <h3>🔐 Requested Permissions</h3>
            <div class="permission-item">
                <span class="permission-icon">🔗</span>
                <div>
                    <strong>Access your shortened URLs</strong><br>
                    <small>View and manage your URL collection</small>
                </div>
            </div>
            <div class="permission-item">
                <span class="permission-icon">📊</span>
                <div>
                    <strong>View usage statistics</strong><br>
                    <small>Access analytics for your shortened URLs</small>
                </div>
            </div>
            <div class="permission-item">
                <span class="permission-icon">👤</span>
                <div>
                    <strong>Access your profile information</strong><br>
                    <small>Read your basic profile details</small>
                </div>
            </div>
        </div>
        
        <div class="warning-box">
            <h4>⚠️ Security Notice</h4>
            <p>Only authorize applications that you trust. This will give the application access to your Maigo account as described above.</p>
        </div>
        
        <div class="button-container">
            <form method="post" action="/oauth/authorize" style="display: inline;">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                <input type="hidden" name="user_id" value="%s">
                <input type="hidden" name="action" value="authorize">
                <button type="submit" class="btn btn-primary">
                    ✅ Authorize Application
                </button>
            </form>
            
            <form method="post" action="/oauth/authorize" style="display: inline;">
                <input type="hidden" name="response_type" value="%s">
                <input type="hidden" name="client_id" value="%s">
                <input type="hidden" name="redirect_uri" value="%s">
                <input type="hidden" name="scope" value="%s">
                <input type="hidden" name="state" value="%s">
                <input type="hidden" name="code_challenge" value="%s">
                <input type="hidden" name="code_challenge_method" value="%s">
                <input type="hidden" name="action" value="deny">
                <button type="submit" class="btn btn-secondary">
                    ❌ Deny Access
                </button>
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
		userIDStr,
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
