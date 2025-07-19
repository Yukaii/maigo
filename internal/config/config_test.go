package config

import (
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_DatabaseURL(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{
			name: "Uses DATABASE_URL when set",
			config: Config{
				Database: DatabaseConfig{
					URL: "postgres://user:pass@host:5432/db?sslmode=require",
				},
			},
			expected: "postgres://user:pass@host:5432/db?sslmode=require",
		},
		{
			name: "Constructs URL from individual parameters",
			config: Config{
				Database: DatabaseConfig{
					Host:     "localhost",
					Port:     5432,
					Name:     "testdb",
					User:     "testuser",
					Password: "testpass",
					SSLMode:  "disable",
				},
			},
			expected: "postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.config.DatabaseURL()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestConfig_ServerAddr(t *testing.T) {
	config := Config{
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
	}

	result := config.ServerAddr()
	assert.Equal(t, "127.0.0.1:8080", result)
}

func TestConfig_ParseDatabaseURL(t *testing.T) {
	tests := []struct {
		name          string
		databaseURL   string
		expectedError bool
		expectedDB    DatabaseConfig
	}{
		{
			name:        "Empty DATABASE_URL",
			databaseURL: "",
			expectedDB: DatabaseConfig{
				URL: "",
			},
		},
		{
			name:        "Valid PostgreSQL URL",
			databaseURL: "postgres://myuser:mypass@localhost:5432/mydb?sslmode=require",
			expectedDB: DatabaseConfig{
				URL:      "postgres://myuser:mypass@localhost:5432/mydb?sslmode=require",
				Host:     "localhost",
				Port:     5432,
				Name:     "mydb",
				User:     "myuser",
				Password: "mypass",
				SSLMode:  "require",
			},
		},
		{
			name:        "PostgreSQL URL without port",
			databaseURL: "postgres://user:pass@host/db",
			expectedDB: DatabaseConfig{
				URL:      "postgres://user:pass@host/db",
				Host:     "host",
				Port:     0,
				Name:     "db",
				User:     "user",
				Password: "pass",
				SSLMode:  "",
			},
		},
		{
			name:        "PostgreSQL URL without password",
			databaseURL: "postgres://user@host:5432/db",
			expectedDB: DatabaseConfig{
				URL:      "postgres://user@host:5432/db",
				Host:     "host",
				Port:     5432,
				Name:     "db",
				User:     "user",
				Password: "",
				SSLMode:  "",
			},
		},
		{
			name:          "Invalid URL",
			databaseURL:   ":/invalid-url",
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &Config{
				Database: DatabaseConfig{
					URL: tt.databaseURL,
				},
			}

			err := config.ParseDatabaseURL()
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedDB.Host, config.Database.Host)
				assert.Equal(t, tt.expectedDB.Port, config.Database.Port)
				assert.Equal(t, tt.expectedDB.Name, config.Database.Name)
				assert.Equal(t, tt.expectedDB.User, config.Database.User)
				assert.Equal(t, tt.expectedDB.Password, config.Database.Password)
				assert.Equal(t, tt.expectedDB.SSLMode, config.Database.SSLMode)
			}
		})
	}
}

func TestConfig_ParseDatabaseURLExistingFields(t *testing.T) {
	t.Run("DATABASE_URL does not override existing fields", func(t *testing.T) {
		config := &Config{
			Database: DatabaseConfig{
				URL:      "postgres://newuser:newpass@newhost:5433/newdb?sslmode=require",
				Host:     "existinghost",
				Port:     5432,
				Name:     "existingdb",
				User:     "existinguser",
				Password: "existingpass",
				SSLMode:  "disable",
			},
		}

		err := config.ParseDatabaseURL()
		require.NoError(t, err)

		// Existing fields should not be overridden
		assert.Equal(t, "existinghost", config.Database.Host)
		assert.Equal(t, 5432, config.Database.Port)
		assert.Equal(t, "existingdb", config.Database.Name)
		assert.Equal(t, "existinguser", config.Database.User)
		assert.Equal(t, "existingpass", config.Database.Password)
		assert.Equal(t, "disable", config.Database.SSLMode)
	})
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name          string
		config        Config
		expectedError bool
		errorContains string
	}{
		{
			name: "Valid config with DATABASE_URL",
			config: Config{
				Database: DatabaseConfig{
					URL: "postgres://user:pass@host:5432/db",
				},
				OAuth2: OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 6,
				},
			},
		},
		{
			name: "Valid config with individual DB params",
			config: Config{
				Database: DatabaseConfig{
					Host: "localhost",
					Name: "testdb",
					User: "testuser",
				},
				OAuth2: OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 6,
				},
			},
		},
		{
			name: "Missing database host",
			config: Config{
				Database: DatabaseConfig{
					Name: "testdb",
					User: "testuser",
				},
				OAuth2: OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 6,
				},
			},
			expectedError: true,
			errorContains: "database host is required",
		},
		{
			name: "Missing OAuth2 client ID",
			config: Config{
				Database: DatabaseConfig{
					URL: "postgres://user:pass@host:5432/db",
				},
				OAuth2: OAuth2Config{
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 6,
				},
			},
			expectedError: true,
			errorContains: "oauth2 client ID is required",
		},
		{
			name: "Invalid short code length (too small)",
			config: Config{
				Database: DatabaseConfig{
					URL: "postgres://user:pass@host:5432/db",
				},
				OAuth2: OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 2,
				},
			},
			expectedError: true,
			errorContains: "short code length must be between 3 and 10",
		},
		{
			name: "Invalid short code length (too large)",
			config: Config{
				Database: DatabaseConfig{
					URL: "postgres://user:pass@host:5432/db",
				},
				OAuth2: OAuth2Config{
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				JWT: JWTConfig{
					Secret: "jwt-secret",
				},
				App: AppConfig{
					BaseDomain:      "example.com",
					ShortCodeLength: 11,
				},
			},
			expectedError: true,
			errorContains: "short code length must be between 3 and 10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(&tt.config)
			if tt.expectedError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestLoadWithEnvVars(t *testing.T) {
	// Save original env vars
	originalVars := make(map[string]string)
	envVars := []string{"DATABASE_URL", "PORT", "JWT_SECRET", "DEBUG", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_SSL_MODE"}

	for _, envVar := range envVars {
		originalVars[envVar] = os.Getenv(envVar)
		os.Unsetenv(envVar) // Clear to start fresh
	}

	// Clean up after test
	defer func() {
		for _, envVar := range envVars {
			if originalValue, exists := originalVars[envVar]; exists && originalValue != "" {
				os.Setenv(envVar, originalValue)
			} else {
				os.Unsetenv(envVar)
			}
		}
	}()

	// Set test environment variables
	os.Setenv("DATABASE_URL", "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require")
	os.Setenv("PORT", "9090")
	os.Setenv("JWT_SECRET", "env-jwt-secret")
	os.Setenv("DEBUG", "true")

	// Load config - this should pick up environment variables
	config, err := Load()
	require.NoError(t, err)

	// Verify environment variables were loaded
	assert.Equal(t, "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require", config.Database.URL)
	assert.Equal(t, 9090, config.Server.Port)
	assert.Equal(t, "env-jwt-secret", config.JWT.Secret)
	assert.True(t, config.App.Debug)

	// Note: DATABASE_URL parsing only fills empty fields, so we test the DatabaseURL() method instead
	expectedURL := "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require"
	assert.Equal(t, expectedURL, config.DatabaseURL())
}

func TestLoadDefaults(t *testing.T) {
	// Clear environment variables that might interfere
	envVars := []string{"DATABASE_URL", "PORT", "JWT_SECRET", "DEBUG", "DB_HOST"}
	originalVars := make(map[string]string)

	for _, envVar := range envVars {
		originalVars[envVar] = os.Getenv(envVar)
		os.Unsetenv(envVar)
	}

	defer func() {
		for _, envVar := range envVars {
			if originalValue, exists := originalVars[envVar]; exists {
				os.Setenv(envVar, originalValue)
			}
		}
	}()

	config, err := Load()
	require.NoError(t, err)

	// Verify defaults
	assert.Equal(t, "localhost", config.Database.Host)
	assert.Equal(t, 5432, config.Database.Port)
	assert.Equal(t, "maigo", config.Database.Name)
	assert.Equal(t, "postgres", config.Database.User)
	assert.Equal(t, "password", config.Database.Password)
	assert.Equal(t, "disable", config.Database.SSLMode)

	assert.Equal(t, 8080, config.Server.Port)
	assert.Equal(t, "127.0.0.1", config.Server.Host)
	assert.Equal(t, 30*time.Second, config.Server.ReadTimeout)

	assert.Equal(t, "maigo_cli", config.OAuth2.ClientID)
	assert.Equal(t, "dev_secret_change_in_production", config.OAuth2.ClientSecret)

	assert.Equal(t, "dev_jwt_secret_change_in_production", config.JWT.Secret)
	assert.Equal(t, 24*time.Hour, config.JWT.Expiration)

	assert.Equal(t, "Maigo", config.App.Name)
	assert.Equal(t, "maigo.dev", config.App.BaseDomain)
	assert.Equal(t, 6, config.App.ShortCodeLength)
	assert.Equal(t, 100, config.App.RateLimit.Requests)
	assert.Equal(t, 1*time.Hour, config.App.RateLimit.Window)
	assert.False(t, config.App.Debug)
	assert.True(t, config.App.CORSEnabled)

	assert.Equal(t, "info", config.Log.Level)
	assert.Equal(t, "json", config.Log.Format)
}

func TestPopulateFunctions(t *testing.T) {
	t.Run("populateHost", func(t *testing.T) {
		tests := []struct {
			name         string
			initialHost  string
			urlString    string
			expectedHost string
		}{
			{
				name:         "Empty host gets populated",
				initialHost:  "",
				urlString:    "postgres://user:pass@myhost:5432/db",
				expectedHost: "myhost",
			},
			{
				name:         "Existing host not overridden",
				initialHost:  "existing",
				urlString:    "postgres://user:pass@newhost:5432/db",
				expectedHost: "existing",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{Host: tt.initialHost}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populateHost(db, u)
				assert.Equal(t, tt.expectedHost, db.Host)
			})
		}
	})

	t.Run("populatePort", func(t *testing.T) {
		tests := []struct {
			name         string
			initialPort  int
			urlString    string
			expectedPort int
		}{
			{
				name:         "Zero port gets populated",
				initialPort:  0,
				urlString:    "postgres://user:pass@host:9999/db",
				expectedPort: 9999,
			},
			{
				name:         "Existing port not overridden",
				initialPort:  5432,
				urlString:    "postgres://user:pass@host:9999/db",
				expectedPort: 5432,
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{Port: tt.initialPort}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populatePort(db, u)
				assert.Equal(t, tt.expectedPort, db.Port)
			})
		}
	})

	t.Run("populateName", func(t *testing.T) {
		tests := []struct {
			name         string
			initialName  string
			urlString    string
			expectedName string
		}{
			{
				name:         "Empty name gets populated",
				initialName:  "",
				urlString:    "postgres://user:pass@host:5432/mydb",
				expectedName: "mydb",
			},
			{
				name:         "Existing name not overridden",
				initialName:  "existing",
				urlString:    "postgres://user:pass@host:5432/newdb",
				expectedName: "existing",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{Name: tt.initialName}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populateName(db, u)
				assert.Equal(t, tt.expectedName, db.Name)
			})
		}
	})

	t.Run("populateUser", func(t *testing.T) {
		tests := []struct {
			name         string
			initialUser  string
			urlString    string
			expectedUser string
		}{
			{
				name:         "Empty user gets populated",
				initialUser:  "",
				urlString:    "postgres://myuser:pass@host:5432/db",
				expectedUser: "myuser",
			},
			{
				name:         "Existing user not overridden",
				initialUser:  "existing",
				urlString:    "postgres://newuser:pass@host:5432/db",
				expectedUser: "existing",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{User: tt.initialUser}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populateUser(db, u)
				assert.Equal(t, tt.expectedUser, db.User)
			})
		}
	})

	t.Run("populatePassword", func(t *testing.T) {
		tests := []struct {
			name             string
			initialPassword  string
			urlString        string
			expectedPassword string
		}{
			{
				name:             "Empty password gets populated",
				initialPassword:  "",
				urlString:        "postgres://user:mypass@host:5432/db",
				expectedPassword: "mypass",
			},
			{
				name:             "Existing password not overridden",
				initialPassword:  "existing",
				urlString:        "postgres://user:newpass@host:5432/db",
				expectedPassword: "existing",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{Password: tt.initialPassword}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populatePassword(db, u)
				assert.Equal(t, tt.expectedPassword, db.Password)
			})
		}
	})

	t.Run("populateSSLMode", func(t *testing.T) {
		tests := []struct {
			name            string
			initialSSLMode  string
			urlString       string
			expectedSSLMode string
		}{
			{
				name:            "Empty SSL mode gets populated",
				initialSSLMode:  "",
				urlString:       "postgres://user:pass@host:5432/db?sslmode=require",
				expectedSSLMode: "require",
			},
			{
				name:            "Existing SSL mode not overridden",
				initialSSLMode:  "disable",
				urlString:       "postgres://user:pass@host:5432/db?sslmode=require",
				expectedSSLMode: "disable",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				db := &DatabaseConfig{SSLMode: tt.initialSSLMode}
				u, err := url.Parse(tt.urlString)
				require.NoError(t, err)

				populateSSLMode(db, u)
				assert.Equal(t, tt.expectedSSLMode, db.SSLMode)
			})
		}
	})
}
