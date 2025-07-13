package cli

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// CLI OAuth client constants - hardcoded for consistency
// These must match the constants in internal/oauth/server.go
const (
	CLIClientID     = "maigo-cli"
	CLIClientSecret = "cli-client-secret-not-used-with-pkce" // Not used with PKCE but kept for completeness
	CLIRedirectURI  = "http://localhost:8000/callback"
)

// OAuthClient handles OAuth 2.0 flow for CLI applications
type OAuthClient struct {
	config      *config.Config
	logger      *logger.Logger
	clientID    string
	redirectURI string
	baseURL     string
	httpClient  *http.Client
}

// OAuthCallbackResult represents the result of OAuth callback
type OAuthCallbackResult struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

// NewOAuthClient creates a new OAuth 2.0 client for CLI
func NewOAuthClient(cfg *config.Config, log *logger.Logger) *OAuthClient {
	return &OAuthClient{
		config:      cfg,
		logger:      log,
		clientID:    CLIClientID,
		redirectURI: CLIRedirectURI,
		baseURL:     fmt.Sprintf("http://localhost:%d", cfg.Server.Port),
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// PerformOAuthFlow performs the complete OAuth 2.0 authorization code flow with PKCE
func (c *OAuthClient) PerformOAuthFlow(ctx context.Context) (*models.TokenResponse, error) {
	c.logger.Info("Starting OAuth 2.0 authorization code flow with PKCE")

	// Step 1: Generate PKCE parameters
	pkce, err := oauth.GeneratePKCEParams()
	if err != nil {
		return nil, fmt.Errorf("failed to generate PKCE parameters: %w", err)
	}

	c.logger.Info("Generated PKCE parameters",
		"code_challenge_method", pkce.CodeChallengeMethod,
		"code_verifier_length", len(pkce.CodeVerifier),
		"code_challenge_length", len(pkce.CodeChallenge),
	)

	// Step 2: Generate state parameter for CSRF protection
	state, err := c.generateState()
	if err != nil {
		return nil, fmt.Errorf("failed to generate state parameter: %w", err)
	}

	// Step 3: Start local HTTP server to handle callback
	callbackChan := make(chan *OAuthCallbackResult, 1)
	server, err := c.startCallbackServer(callbackChan, state)
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	defer server.Shutdown(ctx)

	// Step 4: Build authorization URL
	authURL, err := c.buildAuthorizationURL(pkce, state)
	if err != nil {
		return nil, fmt.Errorf("failed to build authorization URL: %w", err)
	}

	c.logger.Info("Authorization URL generated", "url", authURL)

	// Step 5: Open browser to authorization URL
	fmt.Printf("🌐 Opening browser for OAuth authorization...\n")
	fmt.Printf("If the browser doesn't open automatically, please visit:\n%s\n\n", authURL)

	if err := c.openBrowser(authURL); err != nil {
		c.logger.Warn("Failed to open browser automatically", "error", err)
		fmt.Printf("⚠️  Please manually open the URL above in your browser.\n\n")
	}

	// Step 6: Wait for callback
	fmt.Printf("⏳ Waiting for authorization...\n")

	select {
	case result := <-callbackChan:
		if result.Error != "" {
			return nil, fmt.Errorf("authorization failed: %s - %s", result.Error, result.ErrorDescription)
		}

		c.logger.Info("Authorization code received", "code_length", len(result.Code))

		// Step 7: Exchange authorization code for tokens
		tokens, err := c.exchangeCodeForTokens(result.Code, pkce.CodeVerifier)
		if err != nil {
			return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
		}

		c.logger.Info("Tokens obtained successfully")
		fmt.Printf("[SUCCESS] OAuth authorization successful!\n")

		return tokens, nil

	case <-ctx.Done():
		return nil, fmt.Errorf("authorization timeout or cancelled")

	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authorization timeout after 5 minutes")
	}
}

// generateState generates a cryptographically secure state parameter
func (c *OAuthClient) generateState() (string, error) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(randomBytes), nil
}

// buildAuthorizationURL builds the OAuth 2.0 authorization URL with PKCE
func (c *OAuthClient) buildAuthorizationURL(pkce *oauth.PKCEParams, state string) (string, error) {
	authURL := fmt.Sprintf("%s/oauth/authorize", c.baseURL)

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", c.clientID)
	params.Set("redirect_uri", c.redirectURI)
	params.Set("scope", "read write") // Default scope
	params.Set("state", state)
	params.Set("code_challenge", pkce.CodeChallenge)
	params.Set("code_challenge_method", pkce.CodeChallengeMethod)

	return authURL + "?" + params.Encode(), nil
}

// startCallbackServer starts a local HTTP server to handle OAuth callback
func (c *OAuthClient) startCallbackServer(callbackChan chan *OAuthCallbackResult, expectedState string) (*http.Server, error) {
	// Parse redirect URI to get port
	redirectURL, err := url.Parse(c.redirectURI)
	if err != nil {
		return nil, fmt.Errorf("invalid redirect URI: %w", err)
	}

	// Find available port near the preferred port
	port := redirectURL.Port()
	if port == "" {
		port = "8000"
	}

	listener, actualPort, err := c.findAvailablePort(port)
	if err != nil {
		return nil, fmt.Errorf("failed to find available port: %w", err)
	}

	// Update redirect URI with actual port
	if actualPort != port {
		c.redirectURI = fmt.Sprintf("http://localhost:%s/callback", actualPort)
		c.logger.Info("Updated redirect URI", "new_uri", c.redirectURI)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		c.handleCallback(w, r, callbackChan, expectedState)
	})

	server := &http.Server{
		Handler: mux,
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			c.logger.Error("Callback server error", "error", err)
		}
	}()

	c.logger.Info("Started OAuth callback server", "port", actualPort)
	return server, nil
}

// findAvailablePort finds an available port starting from the preferred port
func (c *OAuthClient) findAvailablePort(preferredPort string) (net.Listener, string, error) {
	// Try preferred port first
	if listener, err := net.Listen("tcp", ":"+preferredPort); err == nil {
		return listener, preferredPort, nil
	}

	// If preferred port is not available, find any available port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, "", err
	}

	addr := listener.Addr().(*net.TCPAddr)
	actualPort := fmt.Sprintf("%d", addr.Port)

	return listener, actualPort, nil
}

// handleCallback handles the OAuth callback
func (c *OAuthClient) handleCallback(w http.ResponseWriter, r *http.Request, callbackChan chan *OAuthCallbackResult, expectedState string) {
	query := r.URL.Query()

	result := &OAuthCallbackResult{
		Code:             query.Get("code"),
		State:            query.Get("state"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
	}

	// Validate state parameter
	if result.State != expectedState {
		result.Error = "invalid_state"
		result.ErrorDescription = "State parameter mismatch"
		c.logger.Error("State parameter mismatch", "expected", expectedState, "received", result.State)
	}

	// Send result to channel
	select {
	case callbackChan <- result:
	default:
		c.logger.Warn("Callback channel full, result dropped")
	}

	// Render response page
	var htmlContent string
	if result.Error != "" {
		// Escape error content for HTML
		errorCode := html.EscapeString(result.Error)
		errorDescription := html.EscapeString(result.ErrorDescription)

		htmlContent = fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authorization Failed - Maigo</title>
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
            text-align: center;
        }
        .result-box {
            background: #ffffff;
            border: 1px solid #ddd;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .error-icon {
            font-size: 64px;
            color: #dc3545;
            margin-bottom: 20px;
        }
        h2 {
            color: #dc3545;
            margin: 0 0 20px 0;
            font-size: 24px;
            font-weight: 600;
        }
        .error-details {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            text-align: left;
        }
        .error-label {
            font-weight: 600;
            color: #721c24;
            margin-bottom: 8px;
        }
        .error-value {
            color: #721c24;
            font-family: monospace;
            background: rgba(255,255,255,0.7);
            padding: 8px;
            border-radius: 4px;
            word-break: break-all;
        }
        .instruction {
            margin: 30px 0;
            color: #6c757d;
            font-size: 16px;
        }
        .close-instruction {
            margin-top: 30px;
            padding: 15px;
            background: #e9ecef;
            border-radius: 8px;
            color: #495057;
            font-size: 14px;
        }
        @media (max-width: 600px) {
            body {
                margin: 20px auto;
                padding: 15px;
            }
            .result-box {
                padding: 25px;
            }
        }
    </style>
</head>
<body>
    <div class="result-box">
        <div class="error-icon">[ERROR]</div>
        <h2>Authorization Failed</h2>
        
        <div class="error-details">
            <div class="error-label">Error Code:</div>
            <div class="error-value">%s</div>
            
            <div class="error-label" style="margin-top: 15px;">Description:</div>
            <div class="error-value">%s</div>
        </div>
        
        <div class="instruction">
            The OAuth authorization process could not be completed successfully.
        </div>
        
        <div class="close-instruction">
            You can close this window and try the authorization process again from your terminal.
        </div>
    </div>
</body>
</html>`, errorCode, errorDescription)
	} else {
		htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth Authorization Successful - Maigo</title>
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
            text-align: center;
        }
        .result-box {
            background: #ffffff;
            border: 1px solid #ddd;
            border-radius: 12px;
            padding: 40px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .success-icon {
            font-size: 64px;
            color: #28a745;
            margin-bottom: 20px;
            animation: checkmark 0.5s ease-in-out;
        }
        @keyframes checkmark {
            0% { transform: scale(0); }
            50% { transform: scale(1.2); }
            100% { transform: scale(1); }
        }
        h2 {
            color: #28a745;
            margin: 0 0 20px 0;
            font-size: 24px;
            font-weight: 600;
        }
        .success-message {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
            color: #155724;
        }
        .instruction {
            margin: 30px 0;
            color: #6c757d;
            font-size: 16px;
        }
        .auto-close {
            margin-top: 20px;
            padding: 15px;
            background: #e9ecef;
            border-radius: 8px;
            color: #495057;
            font-size: 14px;
        }
        .countdown {
            font-weight: 600;
            color: #007bff;
        }
        @media (max-width: 600px) {
            body {
                margin: 20px auto;
                padding: 15px;
            }
            .result-box {
                padding: 25px;
            }
        }
    </style>
</head>
<body>
    <div class="result-box">
        <div class="success-icon">[OK]</div>
        <h2>Authorization Successful</h2>
        
        <div class="success-message">
            <strong>Great!</strong> You have successfully authorized the Maigo CLI application.
        </div>
        
        <div class="instruction">
            You can now return to your terminal to continue using the Maigo CLI.
        </div>
        
        <div class="auto-close">
            This window will automatically close in <span class="countdown" id="countdown">3</span> seconds.
        </div>
    </div>

    <script>
        let seconds = 3;
        const countdownElement = document.getElementById('countdown');
        
        const timer = setInterval(function() {
            seconds--;
            countdownElement.textContent = seconds;
            
            if (seconds <= 0) {
                clearInterval(timer);
                window.close();
            }
        }, 1000);
        
        // Also allow manual close
        document.addEventListener('keydown', function(e) {
            if (e.key === 'Escape' || e.key === 'Enter') {
                window.close();
            }
        });
    </script>
</body>
</html>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(htmlContent))
}

// exchangeCodeForTokens exchanges authorization code for access tokens
func (c *OAuthClient) exchangeCodeForTokens(code, codeVerifier string) (*models.TokenResponse, error) {
	tokenURL := fmt.Sprintf("%s/oauth/token", c.baseURL)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("redirect_uri", c.redirectURI)
	data.Set("client_id", c.clientID)
	data.Set("code_verifier", codeVerifier)

	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange code for tokens: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokens models.TokenResponse
	if err := c.decodeJSONResponse(resp, &tokens); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokens, nil
}

// openBrowser opens the given URL in the default browser
func (c *OAuthClient) openBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "darwin":
		cmd = "open"
		args = []string{url}
	case "windows":
		cmd = "rundll32"
		args = []string{"url.dll,FileProtocolHandler", url}
	default: // linux and others
		cmd = "xdg-open"
		args = []string{url}
	}

	return exec.Command(cmd, args...).Start()
}

// decodeJSONResponse decodes JSON response into the given interface
func (c *OAuthClient) decodeJSONResponse(resp *http.Response, v interface{}) error {
	return json.NewDecoder(resp.Body).Decode(v)
}
