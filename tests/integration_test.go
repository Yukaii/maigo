package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/logger"
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

	// Use a dummy password hash for testing
	passwordHash := "$2a$10$dummypasswordhashfortesting"

	err := suite.db.QueryRow(
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

	// Override database settings for testing
	cfg.Database.Host = "localhost"
	cfg.Database.Port = 5432
	cfg.Database.Name = "maigo_test"
	cfg.Database.User = "postgres"
	cfg.Database.Password = "password"

	// Initialize logger
	suite.logger = logger.NewLogger(logger.Config{
		Level:  "debug",
		Format: "text",
	})

	// Initialize database connection
	databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		cfg.Database.User,
		cfg.Database.Password,
		cfg.Database.Host,
		cfg.Database.Port,
		cfg.Database.Name,
		cfg.Database.SSLMode,
	)
	suite.db, err = database.NewConnection(databaseURL)
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

		// Small delay to allow hit increment goroutine to complete
		time.Sleep(10 * time.Millisecond)

		// Check hit count after each redirect
		req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/tracking", http.NoBody)
		w = httptest.NewRecorder()
		suite.server.ServeHTTP(w, req)
		require.Equal(suite.T(), http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), float64(i), urlResponse["hits"])
	}
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
