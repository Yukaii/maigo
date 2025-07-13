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
	server *server.HTTPServer
	db     *pgxpool.Pool
	config *config.Config
	logger *logger.Logger
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
			req := httptest.NewRequest(http.MethodGet, tt.endpoint, nil)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			var response map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &response)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), "ok", response["status"])
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
			name: "Create URL with invalid URL",
			requestBody: models.CreateURLRequest{
				URL: "not-a-valid-url",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Bad Request",
		},
		{
			name: "Create URL with empty URL",
			requestBody: models.CreateURLRequest{
				URL: "",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "Bad Request",
		},
		{
			name: "Create URL with duplicate custom code",
			requestBody: models.CreateURLRequest{
				URL:    "https://example.com",
				Custom: "golang", // This should conflict with the previous test
			},
			expectedStatus: http.StatusConflict,
			expectedError:  "Conflict",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			body, err := json.Marshal(tt.requestBody)
			require.NoError(suite.T(), err)

			req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), tt.expectedError, errorResponse.Error)
			} else {
				var urlResponse models.URL
				err := json.Unmarshal(w.Body.Bytes(), &urlResponse)
				require.NoError(suite.T(), err)

				assert.NotEmpty(suite.T(), urlResponse.ID)
				assert.NotEmpty(suite.T(), urlResponse.ShortCode)
				assert.Equal(suite.T(), tt.requestBody.URL, urlResponse.TargetURL)
				assert.Equal(suite.T(), int64(0), urlResponse.Hits)
				assert.NotZero(suite.T(), urlResponse.CreatedAt)

				if tt.requestBody.Custom != "" {
					assert.Equal(suite.T(), tt.requestBody.Custom, urlResponse.ShortCode)
				} else {
					assert.NotEmpty(suite.T(), urlResponse.ShortCode)
					assert.Len(suite.T(), urlResponse.ShortCode, 6) // Default length
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
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
			expectedError:  "Not Found",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/urls/"+tt.shortCode, nil)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expectedStatus, w.Code)

			if tt.expectedError != "" {
				var errorResponse models.ErrorResponse
				err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
				require.NoError(suite.T(), err)
				assert.Equal(suite.T(), tt.expectedError, errorResponse.Error)
			} else {
				var urlResponse models.URL
				err := json.Unmarshal(w.Body.Bytes(), &urlResponse)
				require.NoError(suite.T(), err)

				assert.Equal(suite.T(), tt.shortCode, urlResponse.ShortCode)
				assert.Equal(suite.T(), "https://example.com", urlResponse.TargetURL)
				assert.Equal(suite.T(), int64(0), urlResponse.Hits)
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
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
			expectedError:  "Not Found",
		},
	}

	for _, tt := range tests {
		suite.Run(tt.name, func() {
			req := httptest.NewRequest(http.MethodGet, "/"+tt.shortCode, nil)
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

	req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusCreated, w.Code)

	// Check initial hit count
	req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/tracking", nil)
	w = httptest.NewRecorder()
	suite.server.ServeHTTP(w, req)
	require.Equal(suite.T(), http.StatusOK, w.Code)

	var urlResponse models.URL
	err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
	require.NoError(suite.T(), err)
	assert.Equal(suite.T(), int64(0), urlResponse.Hits)

	// Perform redirects
	for i := 1; i <= 3; i++ {
		req = httptest.NewRequest(http.MethodGet, "/tracking", nil)
		w = httptest.NewRecorder()
		suite.server.ServeHTTP(w, req)
		assert.Equal(suite.T(), http.StatusFound, w.Code)

		// Check hit count after each redirect
		req = httptest.NewRequest(http.MethodGet, "/api/v1/urls/tracking", nil)
		w = httptest.NewRecorder()
		suite.server.ServeHTTP(w, req)
		require.Equal(suite.T(), http.StatusOK, w.Code)

		err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
		require.NoError(suite.T(), err)
		assert.Equal(suite.T(), int64(i), urlResponse.Hits)
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

				req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
				req.Header.Set("Content-Type", "application/json")
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
	// Skip this test as rate limiting configuration is complex to test
	suite.T().Skip("Rate limiting test requires more complex setup")
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
			expected: http.StatusNotFound,
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
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			suite.server.ServeHTTP(w, req)

			assert.Equal(suite.T(), tt.expected, w.Code)

			var errorResponse models.ErrorResponse
			err := json.Unmarshal(w.Body.Bytes(), &errorResponse)
			require.NoError(suite.T(), err)
			assert.Equal(suite.T(), "Not Found", errorResponse.Error)
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
	defer tx.Rollback(context.Background())

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

		req := httptest.NewRequest(http.MethodPost, "/api/v1/urls", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		suite.server.ServeHTTP(w, req)
		require.Equal(suite.T(), http.StatusCreated, w.Code)

		var urlResponse models.URL
		err = json.Unmarshal(w.Body.Bytes(), &urlResponse)
		require.NoError(suite.T(), err)

		shortCodes = append(shortCodes, urlResponse.ShortCode)

		// Verify short code properties
		assert.Len(suite.T(), urlResponse.ShortCode, 6)                   // Default length
		assert.Regexp(suite.T(), "^[a-zA-Z0-9]+$", urlResponse.ShortCode) // Alphanumeric only
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
