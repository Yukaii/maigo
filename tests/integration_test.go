package tests

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"golang.org/x/crypto/bcrypt"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/database/repository"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/maintenance"
	"github.com/yukaii/maigo/internal/metrics"
	"github.com/yukaii/maigo/internal/server"
)

// IntegrationTestSuite contains integration tests for the URL shortener
type IntegrationTestSuite struct {
	suite.Suite
	server   *server.HTTPServer
	db       *pgxpool.Pool
	config   *config.Config
	logger   *logger.Logger
	testUser *models.User
}

// Test JWT helpers
func (suite *IntegrationTestSuite) createTestJWT(userID int64, username, email string) string {
	claims := jwt.MapClaims{
		"user_id":  userID,
		"username": username,
		"email":    email,
		"type":     "access",
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
		"iss":      "maigo-oauth2",
		"aud":      "maigo-api",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(suite.config.JWT.Secret))
	require.NoError(suite.T(), err)
	return tokenString
}

func (suite *IntegrationTestSuite) createTestUser() *models.User {
	// Create test user in database
	user := &models.User{
		Username: "testuser",
		Email:    "test@example.com",
	}

	// Use a real bcrypt hash so this fixture can be used by authentication tests.
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("test-password-123"), bcrypt.MinCost)
	require.NoError(suite.T(), err)

	err = suite.db.QueryRow(
		context.Background(),
		"INSERT INTO users (username, email, password_hash, created_at) VALUES ($1, $2, $3, NOW()) RETURNING id",
		user.Username, user.Email, passwordHash,
	).Scan(&user.ID)
	require.NoError(suite.T(), err)

	return user
}

func (suite *IntegrationTestSuite) createAuthenticatedRequest(body []byte) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}

	if suite.testUser != nil {
		token := suite.createTestJWT(suite.testUser.ID, suite.testUser.Username, suite.testUser.Email)
		req.Header.Set("Authorization", "Bearer "+token)
	}

	return req
}

// SetupSuite runs once before all tests
func (suite *IntegrationTestSuite) SetupSuite() {
	// Load test configuration
	cfg, err := config.Load()
	require.NoError(suite.T(), err)

	// Use the configured database by default. MAIGO_TEST_DATABASE_URL is a
	// convenient one-off override for local or CI databases without requiring a
	// second config file.
	if databaseURL := os.Getenv("MAIGO_TEST_DATABASE_URL"); databaseURL != "" {
		cfg.Database.URL = databaseURL
		if parseErr := cfg.ParseDatabaseURL(); parseErr != nil {
			require.NoError(suite.T(), parseErr)
		}
	}

	// Initialize logger
	suite.logger = logger.NewLogger(logger.Config{
		Level:  "debug",
		Format: "text",
	})

	// Initialize database connection
	suite.db, err = database.NewConnection(cfg.DatabaseURL())
	require.NoError(suite.T(), err)

	// Run migrations
	err = database.RunMigrations(suite.db)
	require.NoError(suite.T(), err)

	// Store config
	suite.config = cfg

	// Initialize HTTP server
	suite.server = server.NewHTTPServer(cfg, suite.db, suite.logger)
}

// TearDownSuite runs once after all tests
func (suite *IntegrationTestSuite) TearDownSuite() {
	if suite.db != nil {
		suite.db.Close()
	}
}

// SetupTest runs before each test
func (suite *IntegrationTestSuite) SetupTest() {
	// Clean up test data before each test
	_, err := suite.db.Exec(context.Background(), "DELETE FROM urls")
	require.NoError(suite.T(), err)
	_, err = suite.db.Exec(context.Background(), "DELETE FROM users")
	require.NoError(suite.T(), err)

	// Create test user for authenticated requests
	suite.testUser = suite.createTestUser()
}

// TestHealthEndpoints tests the health check endpoints
func (suite *IntegrationTestSuite) TestHealthEndpoints() {
	tests := []struct {
		name           string
		endpoint       string
		expectedStatus int
	}{
		{
			name:           "Health check endpoint",
			endpoint:       "/health",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Readiness check endpoint",
			endpoint:       "/health/ready",
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodGet, tt.endpoint, http.NoBody)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)

			// Different endpoints return different status values
			if tt.endpoint == "/health" {
				assert.Equal(suite.T(), "ok", response["status"])
			} else if tt.endpoint == "/health/ready" {
				assert.Equal(suite.T(), "ready", response["status"])
			}
		})
	}
}

// TestCreateShortURL tests URL creation with various scenarios
func (suite *IntegrationTestSuite) TestCreateShortURL() {
	tests := []struct {
		name           string
		requestBody    models.CreateURLRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Create URL with random short code",
			requestBody: models.CreateURLRequest{
				URL: "https://github.com/yukaii/maigo",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Create URL with custom short code",
			requestBody: models.CreateURLRequest{
				URL:    "https://golang.org",
				Custom: "golang",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Create URL with minimal valid URL",
			requestBody: models.CreateURLRequest{
				URL: "http://example.com",
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name: "Create URL with empty URL",
			requestBody: models.CreateURLRequest{
				URL: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "bad_request",
		},
		{
			name: "Create URL with duplicate custom code",
			requestBody: models.CreateURLRequest{
				URL:    "https://example.com",
				Custom: "golang", // This should conflict with the previous test
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "conflict",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(suite.T(), err)

			req := suite.createAuthenticatedRequest(body)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), tt.expectedError, errorResponse.Error)
			} else {
				var urlResponse map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &urlResponse)
				require.NoError(suite.T(), err)

				assert.NotEmpty(suite.T(), urlResponse["id"])
				assert.NotEmpty(suite.T(), urlResponse["short_code"])
				assert.Equal(suite.T(), tt.requestBody.URL, urlResponse["url"])
				assert.Equal(suite.T(), float64(0), urlResponse["hits"]) // JSON numbers are float64
				assert.NotEmpty(suite.T(), urlResponse["created_at"])

				if tt.requestBody.Custom != "" {
					assert.Equal(suite.T(), tt.requestBody.Custom, urlResponse["short_code"])
				} else {
					assert.NotEmpty(suite.T(), urlResponse["short_code"])
					shortCode, ok := urlResponse["short_code"].(string)
					require.True(suite.T(), ok, "short_code should be a string")
					assert.Len(suite.T(), shortCode, 6) // Default length
				}
			}
		})
	}
}

// TestGetURL tests retrieving URL details
func (suite *IntegrationTestSuite) TestGetURL() {
	// First create a URL
	createReq := models.CreateURLRequest{
		URL:    "https://example.com",
		Custom: "example",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	tests := []struct {
		name           string
		shortCode      string
		expectedStatus int
		expectedError  string
	}{
		{
			name:           "Get existing URL",
			shortCode:      "example",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Get non-existent URL",
			shortCode:      "nonexistent",
			expectedStatus: http.StatusNotFound,
			expectedError:  "not_found",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/urls/"+tt.shortCode, http.NoBody)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), tt.expectedError, errorResponse.Error)
			} else {
				var urlResponse map[string]interface{}
				err := json.Unmarshal(w.Body.Bytes(), &urlResponse)
				require.NoError(suite.T(), err)

				assert.Equal(suite.T(), tt.shortCode, urlResponse["short_code"])
				assert.Equal(suite.T(), "https://example.com", urlResponse["url"])
				assert.Equal(suite.T(), float64(0), urlResponse["hits"])
			}
		})
	}
}

// TestRedirectShortURL tests the redirect functionality
func (suite *IntegrationTestSuite) TestRedirectShortURL() {
	// First create a URL
	createReq := models.CreateURLRequest{
		URL:    "https://github.com/yukaii/maigo",
		Custom: "maigo",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	tests := []struct {
		name             string
		shortCode        string
		expectedStatus   int
		expectedLocation string
		expectedError    string
	}{
		{
			name:             "Redirect existing URL",
			shortCode:        "maigo",
			expectedStatus:   http.StatusFound,
			expectedLocation: "https://github.com/yukaii/maigo",
		},
		{
			name:           "Redirect non-existent URL",
			shortCode:      "nonexistent",
			expectedStatus: http.StatusNotFound,
			expectedError:  "not_found",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodGet, "/"+tt.shortCode, http.NoBody)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), tt.expectedError, errorResponse.Error)
			} else {
				assert.Equal(suite.T(), tt.expectedLocation, w.Header().Get("Location"))
			}
		})
	}
}

// TestAuthenticationAndTokenLifecycle exercises bcrypt-backed login,
// stateful refresh-token rotation, and logout revocation.
func (suite *IntegrationTestSuite) TestAuthenticationAndTokenLifecycle() {
	username := fmt.Sprintf("auth_user_%d", time.Now().UnixNano())
	email := username + "@example.com"
	password := "test-password-123"

	registerBody, err := json.Marshal(models.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
	})
	require.NoError(suite.T(), err)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	registerResp := httptest.NewRecorder()
	suite.server.ServeHTTP(registerResp, registerReq)
	require.Equal(suite.T(), http.StatusCreated, registerResp.Code)

	var registration struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
		Tokens models.TokenResponse `json:"tokens"`
	}
	require.NoError(suite.T(), json.Unmarshal(registerResp.Body.Bytes(), &registration))
	require.NotZero(suite.T(), registration.User.ID)
	require.NotEmpty(suite.T(), registration.Tokens.RefreshToken)

	var sessionCount int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1", registration.User.ID).Scan(&sessionCount)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(1), sessionCount)

	duplicateBody, err := json.Marshal(models.CreateUserRequest{
		Username: username,
		Email:    "other-" + email,
		Password: password,
	})
	require.NoError(suite.T(), err)
	duplicateReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(duplicateBody))
	duplicateReq.Header.Set("Content-Type", "application/json")
	duplicateResp := httptest.NewRecorder()
	suite.server.ServeHTTP(duplicateResp, duplicateReq)
	assert.Equal(suite.T(), http.StatusConflict, duplicateResp.Code)

	var storedHash string
	err = suite.db.QueryRow(context.Background(),
		"SELECT password_hash FROM users WHERE username = $1", username).Scan(&storedHash)
	require.NoError(suite.T(), err)
	assert.NotEqual(suite.T(), password, storedHash)
	assert.True(suite.T(), strings.HasPrefix(storedHash, "$2"), "password should be bcrypt-hashed")

	loginBody, err := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})
	require.NoError(suite.T(), err)
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp := httptest.NewRecorder()
	suite.server.ServeHTTP(loginResp, loginReq)
	require.Equal(suite.T(), http.StatusOK, loginResp.Code)

	var loginTokens models.TokenResponse
	require.NoError(suite.T(), json.Unmarshal(loginResp.Body.Bytes(), &loginTokens))
	require.NotEmpty(suite.T(), loginTokens.AccessToken)
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1", registration.User.ID).Scan(&sessionCount)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(2), sessionCount, "a second login should keep the first device session")

	refreshBody, err := json.Marshal(models.TokenResponse{RefreshToken: loginTokens.RefreshToken})
	require.NoError(suite.T(), err)
	refreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/json")
	refreshResp := httptest.NewRecorder()
	suite.server.ServeHTTP(refreshResp, refreshReq)
	require.Equal(suite.T(), http.StatusOK, refreshResp.Code)

	var refreshedTokens models.TokenResponse
	require.NoError(suite.T(), json.Unmarshal(refreshResp.Body.Bytes(), &refreshedTokens))
	require.NotEmpty(suite.T(), refreshedTokens.RefreshToken)
	assert.NotEqual(suite.T(), loginTokens.RefreshToken, refreshedTokens.RefreshToken)
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1", registration.User.ID).Scan(&sessionCount)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(2), sessionCount, "rotation should replace one session without affecting the other device")

	// The old refresh token was consumed during rotation.
	replayResp := httptest.NewRecorder()
	replayReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewReader(refreshBody))
	replayReq.Header.Set("Content-Type", "application/json")
	suite.server.ServeHTTP(replayResp, replayReq)
	assert.Equal(suite.T(), http.StatusUnauthorized, replayResp.Code)

	logoutReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", http.NoBody)
	logoutReq.Header.Set("Authorization", "Bearer "+refreshedTokens.AccessToken)
	logoutResp := httptest.NewRecorder()
	suite.server.ServeHTTP(logoutResp, logoutReq)
	require.Equal(suite.T(), http.StatusOK, logoutResp.Code)
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE user_id = $1", registration.User.ID).Scan(&sessionCount)
	require.NoError(suite.T(), err)
	assert.Zero(suite.T(), sessionCount, "JSON logout should revoke every device session")

	latestRefreshBody, err := json.Marshal(models.TokenResponse{RefreshToken: refreshedTokens.RefreshToken})
	require.NoError(suite.T(), err)
	latestRefreshReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", bytes.NewReader(latestRefreshBody))
	latestRefreshReq.Header.Set("Content-Type", "application/json")
	latestRefreshResp := httptest.NewRecorder()
	suite.server.ServeHTTP(latestRefreshResp, latestRefreshReq)
	assert.Equal(suite.T(), http.StatusUnauthorized, latestRefreshResp.Code)
}

// TestOAuthAuthorizationCodeFlow verifies that the consent flow binds the
// issued authorization code to the logged-in user and enforces PKCE.
func (suite *IntegrationTestSuite) TestOAuthAuthorizationCodeFlow() {
	username := fmt.Sprintf("oauth_user_%d", time.Now().UnixNano())
	email := username + "@example.com"
	password := "oauth-password-123"
	registerBody, err := json.Marshal(models.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
	})
	require.NoError(suite.T(), err)
	registerReq := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewReader(registerBody))
	registerReq.Header.Set("Content-Type", "application/json")
	registerResp := httptest.NewRecorder()
	suite.server.ServeHTTP(registerResp, registerReq)
	require.Equal(suite.T(), http.StatusCreated, registerResp.Code)

	var registration struct {
		User struct {
			ID int64 `json:"id"`
		} `json:"user"`
	}
	require.NoError(suite.T(), json.Unmarshal(registerResp.Body.Bytes(), &registration))
	require.NotZero(suite.T(), registration.User.ID)

	verifier := strings.Repeat("v", 43)
	digest := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(digest[:])
	params := url.Values{
		"response_type":         []string{"code"},
		"client_id":             []string{"maigo-cli"},
		"redirect_uri":          []string{"http://localhost:8123/callback"},
		"scope":                 []string{"read write"},
		"state":                 []string{"oauth-state"},
		"code_challenge":        []string{challenge},
		"code_challenge_method": []string{"S256"},
	}

	loginPageReq := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+params.Encode(), http.NoBody)
	loginPageResp := httptest.NewRecorder()
	suite.server.ServeHTTP(loginPageResp, loginPageReq)
	require.Equal(suite.T(), http.StatusOK, loginPageResp.Code)

	loginParams := cloneURLValues(params)
	loginParams.Set("action", "login")
	loginParams.Set("username", username)
	loginParams.Set("password", password)
	loginReq := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(loginParams.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResp := httptest.NewRecorder()
	suite.server.ServeHTTP(loginResp, loginReq)
	require.Equal(suite.T(), http.StatusOK, loginResp.Code)
	require.Contains(suite.T(), loginResp.Body.String(), "Authorize Application")

	cookies := loginResp.Result().Cookies()
	require.Len(suite.T(), cookies, 1)

	consentParams := cloneURLValues(params)
	consentParams.Set("action", "authorize")
	consentReq := httptest.NewRequest(http.MethodPost, "/oauth/authorize", strings.NewReader(consentParams.Encode()))
	consentReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	consentReq.AddCookie(cookies[0])
	consentResp := httptest.NewRecorder()
	suite.server.ServeHTTP(consentResp, consentReq)
	require.Equal(suite.T(), http.StatusFound, consentResp.Code)

	callback, err := url.Parse(consentResp.Header().Get("Location"))
	require.NoError(suite.T(), err)
	authorizationCode := callback.Query().Get("code")
	require.NotEmpty(suite.T(), authorizationCode)
	assert.Equal(suite.T(), "oauth-state", callback.Query().Get("state"))

	var storedUserID int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT user_id FROM authorization_codes WHERE code = $1", authorizationCode).Scan(&storedUserID)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), registration.User.ID, storedUserID)

	tokenParams := url.Values{
		"grant_type":    []string{"authorization_code"},
		"code":          []string{authorizationCode},
		"redirect_uri":  []string{"http://localhost:8123/callback"},
		"client_id":     []string{"maigo-cli"},
		"code_verifier": []string{verifier},
	}
	tokenReq := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(tokenParams.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenResp := httptest.NewRecorder()
	suite.server.ServeHTTP(tokenResp, tokenReq)
	require.Equal(suite.T(), http.StatusOK, tokenResp.Code)

	var tokens models.TokenResponse
	require.NoError(suite.T(), json.Unmarshal(tokenResp.Body.Bytes(), &tokens))
	assert.NotEmpty(suite.T(), tokens.AccessToken)
	assert.NotEmpty(suite.T(), tokens.RefreshToken)
}

// TestExpiredURLDoesNotRedirectOrCountAsAHit verifies the expiration guard on
// the public redirect route.
func (suite *IntegrationTestSuite) TestExpiredURLDoesNotRedirectOrCountAsAHit() {
	var userID int64
	err := suite.db.QueryRow(context.Background(),
		"SELECT id FROM users WHERE username = $1", suite.testUser.Username).Scan(&userID)
	require.NoError(suite.T(), err)

	_, err = suite.db.Exec(context.Background(), `
		INSERT INTO urls (short_code, target_url, user_id, hits, created_at, expires_at)
		VALUES ($1, $2, $3, 0, NOW(), NOW() - INTERVAL '1 minute')`,
		"expired", "https://example.com/expired", userID)
	require.NoError(suite.T(), err)

	req := httptest.NewRequest(http.MethodGet, "/expired", http.NoBody)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	assert.Equal(suite.T(), http.StatusGone, w.Code)

	var hits int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT hits FROM urls WHERE short_code = $1", "expired").Scan(&hits)
	require.NoError(suite.T(), err)
	assert.Zero(suite.T(), hits)

	var clickEvents int64
	err = suite.db.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM click_events
		WHERE url_id = (SELECT id FROM urls WHERE short_code = $1)`, "expired").Scan(&clickEvents)
	require.NoError(suite.T(), err)
	assert.Zero(suite.T(), clickEvents)
}

func cloneURLValues(values url.Values) url.Values {
	cloned := make(url.Values, len(values))
	for key, entries := range values {
		cloned[key] = append([]string(nil), entries...)
	}
	return cloned
}

// TestHitTracking tests that hit counts are properly incremented
func (suite *IntegrationTestSuite) TestHitTracking() {
	// Create a URL
	createReq := models.CreateURLRequest{
		URL:    "https://example.com",
		Custom: "tracking",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	// Check initial hit count
	req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/tracking", http.NoBody)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)

	var urlResponse map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), float64(0), urlResponse["hits"])

	// Perform redirects
	for i := 1; i <= 3; i++ {
		req = httptest.NewRequest(http.MethodGet, "/tracking", http.NoBody)
		w = httptest.NewRecorder()
		suite.server.ServeHTTP(w, req)
		assert.Equal(suite.T(), http.StatusFound, w.Code)

		// Check hit count after each redirect
		req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/tracking", http.NoBody)
		w = httptest.NewRecorder()
		suite.server.ServeHTTP(w, req)
		require.Equal(suite.T(), http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), float64(i), urlResponse["hits"])
	}

	var clickEvents int64
	err = suite.db.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM click_events
		WHERE url_id = (SELECT id FROM urls WHERE short_code = $1)`, "tracking").Scan(&clickEvents)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(3), clickEvents)

	req = httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)
	recordedCount, err := metricValue(w.Body.String(), "maigo_click_events_recorded_total")
	require.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), recordedCount, uint64(3))
}

// TestURLStatsTimeline verifies that stored click events are returned in UTC
// day buckets rather than being synthesized from the aggregate hit count.
func (suite *IntegrationTestSuite) TestURLStatsTimeline() {
	createReq := models.CreateURLRequest{
		URL:    "https://example.com/analytics",
		Custom: "analytics",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	var urlID int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT id FROM urls WHERE short_code = $1", "analytics").Scan(&urlID)
	require.NoError(suite.T(), err)

	// A URL without click events should expose an empty timeline, not a
	// fabricated bucket based on its creation date.
	req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/analytics/stats", http.NoBody)
	token := suite.createTestJWT(suite.testUser.ID, suite.testUser.Username, suite.testUser.Email)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)

	var emptyResponse struct {
		Timeline []struct {
			Date string `json:"date"`
			Hits int64  `json:"hits"`
		} `json:"timeline"`
	}
	require.NoError(suite.T(), json.Unmarshal(w.Body.Bytes(), &emptyResponse))
	assert.Empty(suite.T(), emptyResponse.Timeline)

	now := time.Now().UTC()
	yesterday := now.AddDate(0, 0, -1)
	_, err = suite.db.Exec(context.Background(), `
		INSERT INTO click_events (url_id, clicked_at)
		VALUES ($1, $2), ($1, $2), ($1, $3)`, urlID, yesterday, now)
	require.NoError(suite.T(), err)
	_, err = suite.db.Exec(context.Background(),
		"UPDATE urls SET hits = hits + 3 WHERE id = $1", urlID)
	require.NoError(suite.T(), err)

	req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/analytics/stats", http.NoBody)
	req.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)

	var response struct {
		Hits     int64 `json:"hits"`
		Timeline []struct {
			Date string `json:"date"`
			Hits int64  `json:"hits"`
		} `json:"timeline"`
	}
	require.NoError(suite.T(), json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(suite.T(), int64(3), response.Hits)

	expected := map[string]int64{
		yesterday.Format("2006-01-02"): 2,
		now.Format("2006-01-02"):       1,
	}
	require.Len(suite.T(), response.Timeline, len(expected))
	for _, point := range response.Timeline {
		expectedHits, ok := expected[point.Date]
		require.True(suite.T(), ok, "unexpected timeline date %q", point.Date)
		assert.Equal(suite.T(), expectedHits, point.Hits)
		delete(expected, point.Date)
	}
	assert.Empty(suite.T(), expected)
}

// TestClickEventRetentionCleanup verifies that retention removes only old
// event rows while leaving the URL's lifetime aggregate untouched.
func (suite *IntegrationTestSuite) TestClickEventRetentionCleanup() {
	createReq := models.CreateURLRequest{
		URL:    "https://example.com/retention",
		Custom: "retention",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	var urlID int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT id FROM urls WHERE short_code = $1", "retention").Scan(&urlID)
	require.NoError(suite.T(), err)

	now := time.Now().UTC()
	_, err = suite.db.Exec(context.Background(), `
		INSERT INTO click_events (url_id, clicked_at)
		VALUES ($1, $2), ($1, $3)`, urlID, now.Add(-48*time.Hour), now.Add(-time.Hour))
	require.NoError(suite.T(), err)
	_, err = suite.db.Exec(context.Background(),
		"UPDATE urls SET hits = hits + 2 WHERE id = $1", urlID)
	require.NoError(suite.T(), err)

	telemetry := metrics.New()
	worker := maintenance.NewClickRetentionWorker(
		repository.NewURLRepository(suite.db),
		24*time.Hour,
		time.Hour,
		suite.logger,
		telemetry,
	)
	require.NoError(suite.T(), worker.RunOnce(context.Background()))

	var oldEvents, recentEvents, hits int64
	err = suite.db.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM click_events
		WHERE url_id = $1 AND clicked_at < NOW() - INTERVAL '24 hours'`, urlID).Scan(&oldEvents)
	require.NoError(suite.T(), err)
	err = suite.db.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM click_events
		WHERE url_id = $1 AND clicked_at >= NOW() - INTERVAL '24 hours'`, urlID).Scan(&recentEvents)
	require.NoError(suite.T(), err)
	err = suite.db.QueryRow(context.Background(),
		"SELECT hits FROM urls WHERE id = $1", urlID).Scan(&hits)
	require.NoError(suite.T(), err)

	assert.Zero(suite.T(), oldEvents)
	assert.Equal(suite.T(), int64(1), recentEvents)
	assert.Equal(suite.T(), int64(2), hits)
	retentionRuns, err := metricValue(telemetry.RenderPrometheus(), "maigo_click_retention_runs_total")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), uint64(1), retentionRuns)
	deletedEvents, err := metricValue(telemetry.RenderPrometheus(), "maigo_click_events_deleted_total")
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), uint64(1), deletedEvents)
}

// TestSessionCleanup verifies that the real PostgreSQL repository removes only
// expired refresh sessions and reports the deletion through worker metrics.
func (suite *IntegrationTestSuite) TestSessionCleanup() {
	now := time.Now().UTC()
	_, err := suite.db.Exec(context.Background(), `
		INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $5), ($6, $2, $7, $8, $5, $5)`,
		"expired-session", suite.testUser.ID, "expired-hash", now.Add(-time.Hour), now,
		"active-session", "active-hash", now.Add(time.Hour))
	require.NoError(suite.T(), err)
	_, err = suite.db.Exec(context.Background(), `
		INSERT INTO sessions (id, user_id, refresh_token, expires_at, created_at, updated_at)
		SELECT 'expired-batch-' || generate_series::text, $1, 'expired-batch-hash', $2, $2, $2
		FROM generate_series(1, 1001)`, suite.testUser.ID, now.Add(-2*time.Hour))
	require.NoError(suite.T(), err)

	telemetry := metrics.New()
	worker := maintenance.NewSessionCleanupWorker(
		repository.NewSessionRepository(suite.db),
		time.Hour,
		suite.logger,
		telemetry,
	)
	require.NoError(suite.T(), worker.RunOnce(context.Background()))

	var expiredCount, batchedExpiredCount, activeCount int64
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE id = $1", "expired-session").Scan(&expiredCount)
	require.NoError(suite.T(), err)
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE id LIKE 'expired-batch-%'").Scan(&batchedExpiredCount)
	require.NoError(suite.T(), err)
	err = suite.db.QueryRow(context.Background(),
		"SELECT COUNT(*) FROM sessions WHERE id = $1", "active-session").Scan(&activeCount)
	require.NoError(suite.T(), err)

	assert.Zero(suite.T(), expiredCount)
	assert.Zero(suite.T(), batchedExpiredCount)
	assert.Equal(suite.T(), int64(1), activeCount)
	assert.Contains(suite.T(), telemetry.RenderPrometheus(), "maigo_session_cleanup_runs_total 1")
	assert.Contains(suite.T(), telemetry.RenderPrometheus(), "maigo_sessions_deleted_total 1002")
}

// TestClickTrackingFailureIsObservable verifies that a click persistence
// outage does not break redirects and increments the failure counter.
func (suite *IntegrationTestSuite) TestClickTrackingFailureIsObservable() {
	createReq := models.CreateURLRequest{
		URL:    "https://example.com/tracking-failure",
		Custom: "failtrack",
	}
	body, err := json.Marshal(createReq)
	require.NoError(suite.T(), err)

	req := suite.createAuthenticatedRequest(body)
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	_, err = suite.db.Exec(context.Background(),
		"ALTER TABLE click_events RENAME TO click_events_tracking_outage")
	require.NoError(suite.T(), err)
	defer func() {
		_, restoreErr := suite.db.Exec(context.Background(),
			"ALTER TABLE click_events_tracking_outage RENAME TO click_events")
		require.NoError(suite.T(), restoreErr)
	}()

	req = httptest.NewRequest(http.MethodGet, "/failtrack", http.NoBody)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusFound, w.Code)

	req = httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)
	failureCount, err := metricValue(w.Body.String(), "maigo_click_event_record_failures_total")
	require.NoError(suite.T(), err)
	assert.GreaterOrEqual(suite.T(), failureCount, uint64(1))
}

func metricValue(rendered, name string) (uint64, error) {
	prefix := name + " "
	for _, line := range strings.Split(rendered, "\n") {
		if strings.HasPrefix(line, prefix) {
			return strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, prefix)), 10, 64)
		}
	}

	return 0, fmt.Errorf("metric %q not found", name)
}

// TestConcurrentURLCreation tests creating URLs concurrently
func (suite *IntegrationTestSuite) TestConcurrentURLCreation() {
	const numWorkers = 10
	const urlsPerWorker = 5

	results := make(chan error, numWorkers*urlsPerWorker)

	// Launch workers
	for i := 0; i < numWorkers; i++ {
		go func(workerID int) {
			for j := 0; j < urlsPerWorker; j++ {
				createReq := models.CreateURLRequest{
					URL: fmt.Sprintf("https://example.com/worker%d/url%d", workerID, j),
				}
				body, err := json.Marshal(createReq)
				if err != nil {
					results <- err
					continue
				}

				req := suite.createAuthenticatedRequest(body)
				w := httptest.NewRecorder()

				suite.server.ServeHTTP(w, req)

				if w.Code != http.StatusCreated {
					results <- fmt.Errorf("worker %d, url %d: expected status %d, got %d",
						workerID, j, http.StatusCreated, w.Code)
				} else {
					results <- nil
				}
			}
		}(i)
	}

	// Collect results
	for i := 0; i < numWorkers*urlsPerWorker; i++ {
		err := <-results
		assert.NoError(suite.T(), err)
	}

	// Verify total count
	var count int64
	err := suite.db.QueryRow(context.Background(), "SELECT COUNT(*) FROM urls").Scan(&count)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(numWorkers*urlsPerWorker), count)
}

// TestRateLimiting tests the rate limiting functionality
func (suite *IntegrationTestSuite) TestRateLimiting() {
	// Note: Rate limiting is optional and requires Redis
	// This test verifies that the API works whether or not rate limiting is enabled

	// Create a test user and get auth token
	username := fmt.Sprintf("ratelimit_user_%d", time.Now().UnixNano())
	email := fmt.Sprintf("%s@example.com", username)
	password := "testpassword123"

	// Register user
	registerBody := models.CreateUserRequest{
		Username: username,
		Email:    email,
		Password: password,
	}
	registerJSON, err := json.Marshal(registerBody)
	require.NoError(suite.T(), err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/register", bytes.NewBuffer(registerJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)

	require.Equal(suite.T(), http.StatusCreated, w.Code, "Failed to register user")

	// Parse the registration response which has nested user and tokens
	var registerResp struct {
		Message string `json:"message"`
		User    struct {
			ID       int64  `json:"id"`
			Username string `json:"username"`
			Email    string `json:"email"`
		} `json:"user"`
		Tokens models.TokenResponse `json:"tokens"`
	}
	err = json.Unmarshal(w.Body.Bytes(), &registerResp)
	require.NoError(suite.T(), err)
	require.NotEmpty(suite.T(), registerResp.User.ID, "Registration should return user ID")

	// Create a proper JWT for testing (same as other integration tests)
	token := suite.createTestJWT(registerResp.User.ID, username, email)

	// Make multiple requests to test rate limiting behavior
	// If Redis is enabled and rate limit is configured, we should eventually get 429
	// If Redis is not enabled, all requests should succeed with 201

	successCount := 0
	rateLimitedCount := 0

	// Make 10 rapid requests
	for i := 0; i < 10; i++ {
		urlReq := models.CreateURLRequest{
			URL: fmt.Sprintf("https://example.com/ratelimit-test-%d", i),
		}
		urlJSON, err := json.Marshal(urlReq)
		require.NoError(suite.T(), err)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(urlJSON))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token))
		w := httptest.NewRecorder()

		suite.server.ServeHTTP(w, req)

		if w.Code == http.StatusCreated {
			successCount++
		} else if w.Code == http.StatusTooManyRequests {
			rateLimitedCount++

			// Verify rate limit headers are present
			assert.NotEmpty(suite.T(), w.Header().Get("X-RateLimit-Limit"))
			assert.NotEmpty(suite.T(), w.Header().Get("X-RateLimit-Remaining"))
			assert.NotEmpty(suite.T(), w.Header().Get("Retry-After"))
		} else {
			// Log unexpected status codes for debugging
			suite.T().Logf("Request %d: unexpected status %d, body: %s", i, w.Code, w.Body.String())
		}
	}

	// We should have at least some successful requests
	assert.Greater(suite.T(), successCount, 0, "Should have at least some successful requests")

	// Log the results for debugging
	suite.T().Logf("Rate limiting test results: %d successful, %d rate-limited", successCount, rateLimitedCount)

	// If Redis is enabled, we might see rate limiting. If not, all should succeed.
	// Either way is valid depending on configuration
	assert.Equal(suite.T(), 10, successCount+rateLimitedCount, "All requests should either succeed or be rate-limited")
}

// TestInvalidRoutes tests that invalid routes return 404
func (suite *IntegrationTestSuite) TestInvalidRoutes() {
	tests := []struct {
		name     string
		method   string
		path     string
		expected int
	}{
		{
			name:     "Invalid API endpoint",
			method:   http.MethodGet,
			path:     "/api/v1/invalid",
			expected: http.StatusNotFound,
		},
		{
			name:     "Invalid root path",
			method:   http.MethodGet,
			path:     "/invalid-path",
			expected: http.StatusBadRequest,
		},
		{
			name:     "Wrong HTTP method",
			method:   http.MethodDelete,
			path:     "/health",
			expected: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(tt.method, tt.path, http.NoBody)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expected, w.Code)

			// Check error response
			// Note: Invalid routes (404) return Gin's default format, not our custom format
			var errorResponse models.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
			require.NoError(suite.T(), err)

			// For 404 errors on invalid routes, Gin returns "Not Found" (not our custom format)
			// For 400 errors from our handlers, we return "bad_request"
			if tt.expected == http.StatusBadRequest {
				assert.Equal(suite.T(), "bad_request", errorResponse.Error)
			} else if tt.expected == http.StatusNotFound {
				// Accept either custom format or Gin's default format
				assert.Contains(suite.T(), []string{"not_found", "Not Found"}, errorResponse.Error)
			}
		})
	}
}

// TestDatabaseConnection tests database connectivity
func (suite *IntegrationTestSuite) TestDatabaseConnection() {
	// Test basic connectivity
	err := suite.db.Ping(context.Background())
	assert.NoError(suite.T(), err)

	// Test transaction
	tx, err := suite.db.Begin(context.Background())
	require.NoError(suite.T(), err)
	defer func() {
		if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
			suite.T().Logf("Warning: failed to rollback transaction: %v", err)
		}
	}()

	var result int
	err = tx.QueryRow(context.Background(), "SELECT 1").Scan(&result)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), 1, result)

	err = tx.Commit(context.Background())
	assert.NoError(suite.T(), err)
}

// TestShortCodeGeneration tests the short code generation logic
func (suite *IntegrationTestSuite) TestShortCodeGeneration() {
	// Create multiple URLs without custom codes
	var shortCodes []string

	for i := 0; i < 10; i++ {
		createReq := models.CreateURLRequest{
			URL: fmt.Sprintf("https://example.com/test%d", i),
		}
		body, err := json.Marshal(createReq)
		require.NoError(suite.T(), err)

		req := suite.createAuthenticatedRequest(body)
		w := httptest.NewRecorder()

		suite.server.ServeHTTP(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code)

		var urlResponse map[string]interface{}
		err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
		require.NoError(suite.T(), err)

		shortCode, ok := urlResponse["short_code"].(string)
		require.True(suite.T(), ok, "short_code should be a string")
		shortCodes = append(shortCodes, shortCode)

		// Verify short code properties
		assert.Len(suite.T(), shortCode, 6)                   // Default length
		assert.Regexp(suite.T(), "^[a-zA-Z0-9]+$", shortCode) // Alphanumeric only
	}

	// Verify all short codes are unique
	uniqueCodes := make(map[string]bool)
	for _, code := range shortCodes {
		assert.False(suite.T(), uniqueCodes[code], "Duplicate short code: %s", code)
		uniqueCodes[code] = true
	}
}

// Run the test suite
func TestIntegrationSuite(t *testing.T) {
	// Check if we're in a testing environment
	if os.Getenv("SKIP_INTEGRATION_TESTS") == "true" {
		t.Skip("Integration tests are disabled")
	}

	suite.Run(t, new(IntegrationTestSuite))
}
