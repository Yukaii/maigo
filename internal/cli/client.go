// Package cli implements the Maigo command-line interface.
package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
)

// APIClient handles HTTP requests to the Maigo API
type APIClient struct {
	BaseURL    string
	HTTPClient *http.Client
	TokenPath  string
}

// TokenData represents stored authentication tokens
type TokenData struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresAt    int64  `json:"expires_at"`
}

// NewAPIClient creates a new API client
func NewAPIClient(cfg *config.Config) *APIClient {
	// Get token path
	tokenPath := getTokenPath()

	return &APIClient{
		BaseURL: fmt.Sprintf("http://localhost:%d", cfg.Server.Port),
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		TokenPath: tokenPath,
	}
}

// getTokenPath returns the path where tokens should be stored
func getTokenPath() string {
	// Check XDG_CONFIG_HOME first
	if xdgConfig := os.Getenv("XDG_CONFIG_HOME"); xdgConfig != "" {
		return filepath.Join(xdgConfig, "maigo", "tokens.json")
	}

	// Fall back to ~/.config
	if home := os.Getenv("HOME"); home != "" {
		return filepath.Join(home, ".config", "maigo", "tokens.json")
	}

	// Fall back to current directory
	return "tokens.json"
}

// SaveTokens saves authentication tokens to disk
func (c *APIClient) SaveTokens(tokens *models.TokenResponse) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(c.TokenPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Calculate expires_at timestamp
	expiresAt := time.Now().Add(time.Duration(tokens.ExpiresIn) * time.Second).Unix()

	tokenData := TokenData{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    tokens.TokenType,
		ExpiresAt:    expiresAt,
	}

	data, err := json.MarshalIndent(tokenData, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal tokens: %w", err)
	}

	if err := os.WriteFile(c.TokenPath, data, 0o600); err != nil {
		return fmt.Errorf("failed to save tokens: %w", err)
	}

	return nil
}

// LoadTokens loads authentication tokens from disk
func (c *APIClient) LoadTokens() (*TokenData, error) {
	data, err := os.ReadFile(c.TokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // No tokens exist
		}
		return nil, fmt.Errorf("failed to read tokens: %w", err)
	}

	var tokens TokenData
	if err := json.Unmarshal(data, &tokens); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tokens: %w", err)
	}

	return &tokens, nil
}

// IsTokenExpired checks if the token is expired
func (c *APIClient) IsTokenExpired(tokens *TokenData) bool {
	// Add 5 minute buffer for safety
	return time.Now().Unix() > (tokens.ExpiresAt - 300)
}

// RefreshTokens refreshes the access token using the refresh token via OAuth 2.0 endpoint
func (c *APIClient) RefreshTokens() (*TokenData, error) {
	tokens, err := c.LoadTokens()
	if err != nil {
		return nil, err
	}
	if tokens == nil || tokens.RefreshToken == "" {
		return nil, fmt.Errorf("no refresh token available")
	}

	// Use OAuth 2.0 token endpoint for refresh
	refreshResp, err := c.refreshTokensOAuth(tokens.RefreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Save new tokens
	if err := c.SaveTokens(refreshResp); err != nil {
		return nil, fmt.Errorf("failed to save refreshed tokens: %w", err)
	}

	return c.LoadTokens()
}

// refreshTokensOAuth performs OAuth 2.0 refresh token flow
func (c *APIClient) refreshTokensOAuth(refreshToken string) (*models.TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", c.BaseURL)

	// Prepare form data for OAuth 2.0 token endpoint
	reqBody := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": refreshToken,
		"client_id":     CLIClientID,
	}

	// Convert to form-encoded data
	formData := make([]string, 0, len(reqBody))
	for key, value := range reqBody {
		formData = append(formData, fmt.Sprintf("%s=%s", key, value))
	}
	formDataString := strings.Join(formData, "&")

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(formDataString))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh tokens: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("❌ Failed to read refresh response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// Try to parse OAuth error response
		var oauthErr struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		if json.Unmarshal(respBody, &oauthErr) == nil && oauthErr.Error != "" {
			return nil, buildRefreshTokenError(oauthErr.Error, oauthErr.ErrorDescription)
		}
		return nil, fmt.Errorf("❌ Refresh token request failed with HTTP status %d", resp.StatusCode)
	}

	var tokenResp models.TokenResponse
	if err := json.Unmarshal(respBody, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh token response: %w", err)
	}

	return &tokenResp, nil
}

// GetValidToken returns a valid access token, refreshing if necessary
func (c *APIClient) GetValidToken() (string, error) {
	tokens, err := c.LoadTokens()
	if err != nil {
		return "", err
	}
	if tokens == nil {
		return "", fmt.Errorf("not authenticated - please run 'maigo auth login' first")
	}

	// Check if token is expired
	if c.IsTokenExpired(tokens) {
		fmt.Printf("🔄 Access token expired, refreshing automatically...\n")

		// Try to refresh
		refreshedTokens, err := c.RefreshTokens()
		if err != nil {
			fmt.Printf("❌ Token refresh failed. Please run 'maigo auth login' to re-authenticate.\n")
			return "", fmt.Errorf("token expired and refresh failed: %w", err)
		}

		fmt.Printf("✅ Token refreshed successfully!\n")
		tokens = refreshedTokens
	}

	return tokens.AccessToken, nil
}

// ClearTokens removes stored authentication tokens
func (c *APIClient) ClearTokens() error {
	err := os.Remove(c.TokenPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to clear tokens: %w", err)
	}
	return nil
}

// Login authenticates with username and password
func (c *APIClient) Login(username, password string) (*models.TokenResponse, error) {
	reqBody := map[string]string{
		"username": username,
		"password": password,
	}

	var response models.TokenResponse
	err := c.makeRequest("POST", "/api/v1/auth/login", reqBody, &response, "")
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return &response, nil
}

// Register creates a new user account
func (c *APIClient) Register(username, email, password string) (map[string]interface{}, error) {
	reqBody := map[string]string{
		"username": username,
		"email":    email,
		"password": password,
	}

	var response map[string]interface{}
	err := c.makeRequest("POST", "/api/v1/auth/register", reqBody, &response, "")
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	return response, nil
}

// CreateShortURL creates a new short URL
func (c *APIClient) CreateShortURL(url, custom string, ttl int64) (map[string]interface{}, error) {
	token, err := c.GetValidToken()
	if err != nil {
		return nil, err
	}

	reqBody := map[string]interface{}{
		"url": url,
	}
	if custom != "" {
		reqBody["custom"] = custom
	}
	if ttl > 0 {
		reqBody["ttl"] = ttl
	}

	var response map[string]interface{}
	err = c.makeRequest("POST", "/api/v1/urls", reqBody, &response, token)
	if err != nil {
		return nil, fmt.Errorf("failed to create short URL: %w", err)
	}

	return response, nil
}

// GetUserURLs retrieves all URLs for the authenticated user
func (c *APIClient) GetUserURLs(page, pageSize int) (*models.URLListResponse, error) {
	token, err := c.GetValidToken()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/api/v1/user/urls?page=%d&page_size=%d", page, pageSize)

	var response models.URLListResponse
	err = c.makeRequest("GET", url, nil, &response, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get URLs: %w", err)
	}

	return &response, nil
}

// DeleteURL deletes a short URL by code
func (c *APIClient) DeleteURL(shortCode string) error {
	token, err := c.GetValidToken()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("/api/v1/urls/%s", shortCode)

	var response map[string]interface{}
	err = c.makeRequest("DELETE", url, nil, &response, token)
	if err != nil {
		return fmt.Errorf("failed to delete URL: %w", err)
	}

	return nil
}

// GetURL gets details of a specific short URL
func (c *APIClient) GetURL(shortCode string) (map[string]interface{}, error) {
	token, err := c.GetValidToken()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/api/v1/urls/%s", shortCode)

	var response map[string]interface{}
	err = c.makeRequest("GET", url, nil, &response, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get URL details: %w", err)
	}

	return response, nil
}

// GetURLStats gets analytics for a specific short URL
func (c *APIClient) GetURLStats(shortCode string) (map[string]interface{}, error) {
	token, err := c.GetValidToken()
	if err != nil {
		return nil, err
	}

	url := fmt.Sprintf("/api/v1/urls/%s/stats", shortCode)

	var response map[string]interface{}
	err = c.makeRequest("GET", url, nil, &response, token)
	if err != nil {
		return nil, fmt.Errorf("failed to get URL statistics: %w", err)
	}

	return response, nil
}

// makeRequest makes an HTTP request to the API
func (c *APIClient) makeRequest(method, path string, body, response interface{}, token string) error {
	url := c.BaseURL + path

	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, url, reqBody)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	// Make request
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			fmt.Printf("Warning: failed to close response body: %v\n", closeErr)
		}
	}()

	// Read response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode >= 400 {
		var errorResp models.ErrorResponse
		if err := json.Unmarshal(respBody, &errorResp); err == nil {
			return fmt.Errorf("API error (%d): %s", resp.StatusCode, errorResp.Message)
		}
		return fmt.Errorf("API error (%d): %s", resp.StatusCode, string(respBody))
	}

	// Parse response
	if response != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, response); err != nil {
			return fmt.Errorf("failed to unmarshal response: %w", err)
		}
	}

	return nil
}

// OAuth error codes
const (
	oauthErrInvalidGrant   = "invalid_grant"
	oauthErrInvalidRequest = "invalid_request"
	oauthErrInvalidClient  = "invalid_client"
	oauthErrUnauthorized   = "unauthorized_client"
)

// buildRefreshTokenError creates a user-friendly error message for refresh token errors
func buildRefreshTokenError(errorCode, errorDescription string) error {
	var userMessage string

	switch errorCode {
	case oauthErrInvalidGrant:
		userMessage = "❌ Refresh token expired or invalid\n   " +
			"Please run 'maigo auth login' to re-authenticate"
	case oauthErrInvalidRequest:
		userMessage = "❌ Invalid refresh token request\n   " +
			"Please run 'maigo auth login' to re-authenticate"
	case oauthErrInvalidClient:
		userMessage = "❌ Invalid client credentials\n   Please update your Maigo CLI"
	case oauthErrUnauthorized:
		userMessage = "❌ Client not authorized for token refresh\n   " +
			"Please run 'maigo auth login' to re-authenticate"
	default:
		userMessage = fmt.Sprintf("❌ Token refresh failed - %s\n   "+
			"Please run 'maigo auth login' to re-authenticate", errorCode)
	}

	if errorDescription != "" {
		return fmt.Errorf("%s\n   Details: %s", userMessage, errorDescription)
	}

	return fmt.Errorf("%s", userMessage)
}

// GetTokenStatus returns the current authentication status
func (c *APIClient) GetTokenStatus() (map[string]interface{}, error) {
	tokens, err := c.LoadTokens()
	if err != nil {
		return nil, err
	}

	status := map[string]interface{}{
		"authenticated": false,
		"token_exists":  false,
		"expired":       false,
		"expires_at":    nil,
		"time_left":     nil,
	}

	if tokens == nil {
		return status, nil
	}

	status["token_exists"] = true
	status["authenticated"] = true
	status["expires_at"] = time.Unix(tokens.ExpiresAt, 0).Format(time.RFC3339)

	if c.IsTokenExpired(tokens) {
		status["expired"] = true
		status["authenticated"] = false
	} else {
		timeLeft := time.Until(time.Unix(tokens.ExpiresAt, 0))
		status["time_left"] = timeLeft.String()
	}

	return status, nil
}
