// Package handlers contains HTTP handlers for Maigo server endpoints.
package handlers

import (
	"fmt"
	"net/http"
	"net/url"

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

const oauthSessionCookie = "maigo_oauth_session"

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
		SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid request parameters", nil)
		return
	}

	h.logger.Info("OAuth authorization request",
		"client_id", req.ClientID,
		"redirect_uri", req.RedirectURI,
		"response_type", req.ResponseType,
		"has_pkce", req.CodeChallenge != "",
	)
	if err := h.oauthServer.ValidateAuthorizationRequest(c.Request.Context(), &req); err != nil {
		h.logger.Error("OAuth authorization request rejected", "error", err)
		SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid authorization request", nil)
		return
	}

	// Check if the browser has an authenticated, signed access-token cookie.
	userID := h.getCurrentUserID(c)
	if userID == 0 {
		// Redirect to login page
		h.renderLoginPage(c, &req)
		return
	}

	// Process authorization request
	response, err := h.oauthServer.ProcessAuthorizationRequestWithUser(c.Request.Context(), &req, userID)
	if err != nil {
		h.logger.Error("Authorization request failed", "error", err)

		// Check if it's a token error response
		if tokenErr, ok := err.(*oauth.TokenError); ok {
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
		SendAPIError(c, http.StatusBadRequest, "invalid_request", "Invalid request parameters", nil)
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
		if tokenErr, ok := err.(*oauth.TokenError); ok {
			status := http.StatusBadRequest
			if tokenErr.ErrorCode == oauth.ErrorInvalidClient {
				status = http.StatusUnauthorized
			}
			SendAPIError(c, status, tokenErr.ErrorCode, tokenErr.ErrorDescription, nil)
		} else {
			SendAPIError(c, http.StatusInternalServerError, "server_error", "Internal server error", nil)
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
		SendAPIError(c, http.StatusBadRequest, "invalid_request", "Missing token parameter", nil)
		return
	}

	h.logger.Info("Token revocation request", "token_prefix", token[:minInt(8, len(token))])
	if err := h.oauthServer.RevokeTokenString(c.Request.Context(), token); err != nil {
		h.logger.Error("Token revocation failed", "error", err)
		SendAPIError(c, http.StatusInternalServerError, "server_error", "Failed to revoke token", nil)
		return
	}

	h.logger.Info("Token revoked successfully")
	c.JSON(http.StatusOK, gin.H{"message": "Token revoked successfully"})
}

// Helper methods

// getCurrentUserID gets the current user ID from the signed, short-lived
// browser session cookie created after OAuth login.
func (h *OAuthHandler) getCurrentUserID(c *gin.Context) int64 {
	tokenString, err := c.Cookie(oauthSessionCookie)
	if err != nil || tokenString == "" {
		return 0
	}
	userID, err := h.extractUserIDFromToken(tokenString)
	if err != nil {
		return 0
	}

	return userID

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
func (h *OAuthHandler) renderAuthorizationPage(c *gin.Context, req *oauth.AuthorizationRequest) {
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
	}
	c.HTML(http.StatusOK, "oauth/authorize.tmpl", data)
}

// extractUserIDFromToken extracts user ID from an access token
func (h *OAuthHandler) extractUserIDFromToken(tokenString string) (int64, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(h.config.JWT.Secret), nil
	}, jwt.WithIssuer("maigo-oauth2"), jwt.WithAudience("maigo-api"))

	if err != nil {
		return 0, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if tokenType, ok := claims["type"].(string); !ok || tokenType != "access" {
			return 0, fmt.Errorf("token is not an access token")
		}
		switch userID := claims["user_id"].(type) {
		case float64:
			if userID <= 0 || userID != float64(int64(userID)) {
				break
			}
			return int64(userID), nil
		case int64:
			if userID > 0 {
				return userID, nil
			}
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
	if err := h.oauthServer.ValidateAuthorizationRequest(c.Request.Context(), &req); err != nil {
		h.logger.Error("OAuth authorization POST rejected", "error", err)
		SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid authorization request", nil)
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
		h.setOAuthSessionCookie(c, tokens.AccessToken)

		h.logger.Info("User authenticated successfully", "username", username, "user_id", userID)

		// Show authorization consent page
		h.renderAuthorizationPage(c, &req)
		return

	} else if action == "deny" {
		// User denied authorization
		if err := h.oauthServer.ValidateAuthorizationRequest(c.Request.Context(), &req); err != nil {
			h.logger.Error("Invalid authorization denial request", "error", err)
			SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid authorization request", nil)
			return
		}
		redirectURI := c.PostForm("redirect_uri")
		state := c.PostForm("state")
		h.clearOAuthSessionCookie(c)
		h.redirectWithError(c, redirectURI, state, oauth.ErrorAccessDenied, "User denied authorization")
		return

	} else if action == "authorize" {
		// Read the user from the signed cookie instead of trusting a hidden form
		// field, which a browser user can freely modify.
		userID := h.getCurrentUserID(c)
		if userID == 0 {
			h.logger.Error("Missing or invalid OAuth session")
			h.renderLoginPageWithError(c, &req, "Your session has expired. Please log in again.")
			return
		}

		// Process authorization request with the authenticated user ID
		response, err := h.oauthServer.ProcessAuthorizationRequestWithUser(c.Request.Context(), &req, userID)
		if err != nil {
			h.logger.Error("Authorization request failed", "error", err)

			if tokenErr, ok := err.(*oauth.TokenError); ok {
				h.redirectWithError(c, req.RedirectURI, req.State, tokenErr.ErrorCode, tokenErr.ErrorDescription)
			} else {
				h.redirectWithError(c, req.RedirectURI, req.State, oauth.ErrorServerError, "Internal server error")
			}
			return
		}

		h.clearOAuthSessionCookie(c)
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
	redirectURL, err := addRedirectParams(redirectURI, url.Values{
		"code":  []string{code},
		"state": []string{state},
	})
	if err != nil {
		SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid redirect URI", nil)
		return
	}

	h.logger.Info("Redirecting with authorization code", "has_state", state != "", "code_length", len(code))
	c.Redirect(http.StatusFound, redirectURL)
}

// redirectWithError redirects with OAuth error
func (h *OAuthHandler) redirectWithError(c *gin.Context, redirectURI, state, errorCode, errorDescription string) {
	if redirectURI == "" {
		// Can't redirect, show error page
		SendAPIError(c, http.StatusBadRequest, errorCode, errorDescription, nil)
		return
	}

	params := url.Values{
		"error": []string{errorCode},
	}
	if errorDescription != "" {
		params.Set("error_description", errorDescription)
	}
	if state != "" {
		params.Set("state", state)
	}
	redirectURL, err := addRedirectParams(redirectURI, params)
	if err != nil {
		SendAPIError(c, http.StatusBadRequest, oauth.ErrorInvalidRequest, "Invalid redirect URI", nil)
		return
	}

	h.logger.Info("Redirecting with error", "error", errorCode, "has_state", state != "")
	c.Redirect(http.StatusFound, redirectURL)
}

func addRedirectParams(redirectURI string, params url.Values) (string, error) {
	parsedURL, err := url.Parse(redirectURI)
	if err != nil || parsedURL.Scheme == "" || parsedURL.Hostname() == "" {
		return "", fmt.Errorf("invalid redirect URI")
	}

	query := parsedURL.Query()
	for key, values := range params {
		if len(values) > 0 && values[0] != "" {
			query.Set(key, values[0])
		}
	}
	parsedURL.RawQuery = query.Encode()
	return parsedURL.String(), nil
}

func (h *OAuthHandler) setOAuthSessionCookie(c *gin.Context, accessToken string) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthSessionCookie, accessToken, 600, "/oauth", "", h.config.App.TLS, true)
}

func (h *OAuthHandler) clearOAuthSessionCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oauthSessionCookie, "", -1, "/oauth", "", h.config.App.TLS, true)
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

// minInt helper function
func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
