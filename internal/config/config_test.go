package config

import (
	"net/url"
	"os"
	"path/filepath"
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

func TestValidateConfigProductionSecuritySettings(t *testing.T) {
	baseConfig := Config{
		Database: DatabaseConfig{URL: "postgres://user:pass@host:5432/db"},
		OAuth2:   OAuth2Config{ClientID: "client-id", ClientSecret: "client-secret"},
		JWT:      JWTConfig{Secret: "a-unique-production-secret-that-is-long-enough"},
		App: AppConfig{
			Environment:     "production",
			BaseDomain:      "short.example.com",
			ShortCodeLength: 6,
			CORSOrigins:     "https://console.example.com",
		},
	}

	tests := []struct {
		name          string
		mutate        func(*Config)
		errorContains string
	}{
		{
			name: "accepts a strong unique secret",
		},
		{
			name: "accepts a rotating key ring",
			mutate: func(cfg *Config) {
				cfg.JWT.Secret = ""
				cfg.JWT.ActiveKeyID = "primary-2026"
				cfg.JWT.Keys = []JWTKeyConfig{
					{ID: "primary-2026", Secret: "a-unique-primary-secret-that-is-long-enough"},
					{ID: "primary-2025", Secret: "a-unique-previous-secret-that-is-long-enough"},
				}
			},
		},
		{
			name: "rejects debug mode",
			mutate: func(cfg *Config) {
				cfg.App.Debug = true
			},
			errorContains: "debug must be disabled",
		},
		{
			name: "rejects short secret",
			mutate: func(cfg *Config) {
				cfg.JWT.Secret = "short-secret"
			},
			errorContains: "at least 32 bytes",
		},
		{
			name: "rejects short rotating key",
			mutate: func(cfg *Config) {
				cfg.JWT.Secret = ""
				cfg.JWT.ActiveKeyID = "primary-2026"
				cfg.JWT.Keys = []JWTKeyConfig{
					{ID: "primary-2026", Secret: "short-secret"},
				}
			},
			errorContains: "jwt key \"primary-2026\" must be at least 32 bytes",
		},
		{
			name: "rejects documented placeholder",
			mutate: func(cfg *Config) {
				cfg.JWT.Secret = "your-secure-jwt-secret-minimum-32-characters"
			},
			errorContains: "unique secret",
		},
		{
			name: "rejects placeholder database password",
			mutate: func(cfg *Config) {
				cfg.Database.URL = "postgres://user:your-secure-database-password-here@host:5432/db"
			},
			errorContains: "database password",
		},
		{
			name: "rejects placeholder Redis password",
			mutate: func(cfg *Config) {
				cfg.Redis = RedisConfig{
					Enabled:  true,
					Host:     "redis.example",
					Port:     6379,
					Password: "your-secure-redis-password",
				}
			},
			errorContains: "redis password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			err := validateConfig(&cfg)
			if tt.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestValidateConfigCORS(t *testing.T) {
	baseConfig := Config{
		Database: DatabaseConfig{URL: "postgres://user:pass@host:5432/db"},
		OAuth2:   OAuth2Config{ClientID: "client-id", ClientSecret: "client-secret"},
		JWT:      JWTConfig{Secret: "jwt-secret"},
		App: AppConfig{
			BaseDomain:      "example.com",
			ShortCodeLength: 6,
			CORSEnabled:     true,
		},
	}

	tests := []struct {
		name          string
		mutate        func(*Config)
		errorContains string
	}{
		{
			name: "debug mode may use the wildcard",
			mutate: func(cfg *Config) {
				cfg.App.Debug = true
				cfg.App.CORSOrigins = "*"
			},
		},
		{
			name:          "requires origins outside debug mode",
			errorContains: "cors origins are required",
		},
		{
			name: "rejects wildcard outside debug mode",
			mutate: func(cfg *Config) {
				cfg.App.CORSOrigins = "*"
			},
			errorContains: "wildcard CORS origin",
		},
		{
			name: "rejects a path in an origin",
			mutate: func(cfg *Config) {
				cfg.App.CORSOrigins = "https://console.example.com/app"
			},
			errorContains: "invalid CORS origin",
		},
		{
			name: "accepts comma separated origins",
			mutate: func(cfg *Config) {
				cfg.App.CORSOrigins = "https://console.example.com, https://admin.example.com"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			err := validateConfig(&cfg)
			if tt.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestAppConfigAllowedCORSOrigins(t *testing.T) {
	cfg := AppConfig{CORSOrigins: " https://one.example, ,https://two.example "}
	assert.Equal(t, []string{"https://one.example", "https://two.example"}, cfg.AllowedCORSOrigins())
}

func TestAppConfigTrustedProxyList(t *testing.T) {
	cfg := AppConfig{TrustedProxies: " 10.0.0.0/8, , 192.0.2.10 "}
	assert.Equal(t, []string{"10.0.0.0/8", "192.0.2.10"}, cfg.TrustedProxyList())
}

func TestValidateConfigRedisSettings(t *testing.T) {
	baseConfig := Config{
		Database: DatabaseConfig{URL: "postgres://user:pass@host:5432/db"},
		OAuth2:   OAuth2Config{ClientID: "client-id", ClientSecret: "client-secret"},
		JWT:      JWTConfig{Secret: "jwt-secret"},
		App:      AppConfig{BaseDomain: "example.com", ShortCodeLength: 6},
	}

	tests := []struct {
		name          string
		redis         RedisConfig
		errorContains string
	}{
		{
			name: "accepts a valid Redis configuration",
			redis: RedisConfig{
				Enabled: true,
				Host:    "redis.example",
				Port:    6379,
				DB:      1,
			},
		},
		{
			name: "requires a Redis host",
			redis: RedisConfig{
				Enabled: true,
				Port:    6379,
			},
			errorContains: "redis host is required",
		},
		{
			name: "rejects an invalid Redis port",
			redis: RedisConfig{
				Enabled: true,
				Host:    "redis.example",
				Port:    65536,
			},
			errorContains: "redis port must be between",
		},
		{
			name: "rejects a negative Redis database number",
			redis: RedisConfig{
				Enabled: true,
				Host:    "redis.example",
				Port:    6379,
				DB:      -1,
			},
			errorContains: "cannot be negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := baseConfig
			cfg.Redis = tt.redis

			err := validateConfig(&cfg)
			if tt.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.errorContains)
		})
	}
}

func TestValidateConfigAnalyticsSettings(t *testing.T) {
	baseConfig := Config{
		Database: DatabaseConfig{URL: "postgres://user:pass@host:5432/db"},
		OAuth2:   OAuth2Config{ClientID: "client-id", ClientSecret: "client-secret"},
		JWT:      JWTConfig{Secret: "jwt-secret"},
		App:      AppConfig{BaseDomain: "example.com", ShortCodeLength: 6},
	}

	tests := []struct {
		name          string
		analytics     AnalyticsConfig
		errorContains string
	}{
		{
			name:      "accepts enabled retention",
			analytics: AnalyticsConfig{ClickEventRetention: 90 * 24 * time.Hour, CleanupInterval: time.Hour},
		},
		{
			name:      "allows disabled retention",
			analytics: AnalyticsConfig{},
		},
		{
			name:          "rejects negative retention",
			analytics:     AnalyticsConfig{ClickEventRetention: -time.Hour},
			errorContains: "retention cannot be negative",
		},
		{
			name:          "rejects negative cleanup interval",
			analytics:     AnalyticsConfig{CleanupInterval: -time.Minute},
			errorContains: "cleanup interval cannot be negative",
		},
		{
			name:          "requires cleanup interval when retention is enabled",
			analytics:     AnalyticsConfig{ClickEventRetention: 24 * time.Hour},
			errorContains: "cleanup interval is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := baseConfig
			cfg.Analytics = test.analytics
			err := validateConfig(&cfg)
			if test.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errorContains)
		})
	}
}

func TestParseJWTKeysEnv(t *testing.T) {
	keys, err := parseJWTKeysEnv("primary=secret-one,previous=secret-two")
	require.NoError(t, err)
	assert.Equal(t, []JWTKeyConfig{
		{ID: "primary", Secret: "secret-one"},
		{ID: "previous", Secret: "secret-two"},
	}, keys)

	_, err = parseJWTKeysEnv("primary-secret")
	assert.Error(t, err)
	_, err = parseJWTKeysEnv("primary=")
	assert.Error(t, err)
}

func TestValidateConfigJWTKeyRingSettings(t *testing.T) {
	baseConfig := Config{
		Database: DatabaseConfig{URL: "postgres://user:pass@host:5432/db"},
		OAuth2:   OAuth2Config{ClientID: "client-id", ClientSecret: "client-secret"},
		App:      AppConfig{BaseDomain: "example.com", ShortCodeLength: 6},
	}
	validKeys := []JWTKeyConfig{
		{ID: "primary", Secret: "primary-secret"},
		{ID: "previous", Secret: "previous-secret"},
	}

	tests := []struct {
		name          string
		jwt           JWTConfig
		errorContains string
	}{
		{
			name: "accepts legacy secret",
			jwt:  JWTConfig{Secret: "legacy-secret"},
		},
		{
			name: "accepts active key ring",
			jwt:  JWTConfig{ActiveKeyID: "primary", Keys: validKeys},
		},
		{
			name:          "requires active key ID",
			jwt:           JWTConfig{Keys: validKeys},
			errorContains: "active key ID is required",
		},
		{
			name:          "rejects unknown active key ID",
			jwt:           JWTConfig{ActiveKeyID: "missing", Keys: validKeys},
			errorContains: "is not configured",
		},
		{
			name: "rejects duplicate key IDs",
			jwt: JWTConfig{ActiveKeyID: "primary", Keys: []JWTKeyConfig{
				{ID: "primary", Secret: "primary-secret"},
				{ID: "primary", Secret: "another-secret"},
			}},
			errorContains: "is duplicated",
		},
		{
			name: "rejects empty key secret",
			jwt: JWTConfig{ActiveKeyID: "primary", Keys: []JWTKeyConfig{
				{ID: "primary"},
			}},
			errorContains: "secret is required",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := baseConfig
			cfg.JWT = test.jwt
			err := validateConfig(&cfg)
			if test.errorContains == "" {
				require.NoError(t, err)
				return
			}

			require.Error(t, err)
			assert.Contains(t, err.Error(), test.errorContains)
		})
	}
}

func TestLoadJWTKeyRingFromConfigFile(t *testing.T) {
	t.Setenv("JWT_SECRET", "")
	t.Setenv("JWT_ACTIVE_KEY_ID", "")
	t.Setenv("JWT_KEYS", "")
	configPath := filepath.Join(t.TempDir(), "maigo.yaml")
	configYAML := []byte(`jwt:
  active_key_id: primary-2026
  keys:
    - id: primary-2026
      secret: primary-config-secret
    - id: primary-2025
      secret: previous-config-secret
`)
	require.NoError(t, os.WriteFile(configPath, configYAML, 0o600))

	loaded, err := Load(configPath)
	require.NoError(t, err)
	assert.Empty(t, loaded.JWT.Secret)
	assert.Equal(t, "primary-2026", loaded.JWT.ActiveKeyID)
	assert.Equal(t, []JWTKeyConfig{
		{ID: "primary-2026", Secret: "primary-config-secret"},
		{ID: "primary-2025", Secret: "previous-config-secret"},
	}, loaded.JWT.Keys)
}

func TestLoadWithEnvVars(t *testing.T) {
	// Save original env vars
	originalVars := make(map[string]string)
	envVars := []string{"DATABASE_URL", "PORT", "JWT_SECRET", "JWT_ACTIVE_KEY_ID", "JWT_KEYS", "DEBUG", "APP_ENV", "TRUSTED_PROXIES", "CORS_ENABLED", "CORS_ORIGINS", "AUTH_RATE_LIMIT_REQUESTS", "AUTH_RATE_LIMIT_WINDOW", "REDIS_ENABLED", "REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB", "REDIS_FAIL_OPEN", "CLICK_EVENT_RETENTION", "CLICK_EVENT_CLEANUP_INTERVAL", "DB_HOST", "DB_PORT", "DB_NAME", "DB_USER", "DB_PASSWORD", "DB_SSL_MODE"}

	for _, envVar := range envVars {
		originalVars[envVar] = os.Getenv(envVar)
		//nolint:errcheck // test setup doesn't need error checking
		os.Unsetenv(envVar) // Clear to start fresh
	}

	// Clean up after test
	defer func() {
		for _, envVar := range envVars {
			if originalValue, exists := originalVars[envVar]; exists && originalValue != "" {
				//nolint:errcheck // test cleanup doesn't need error checking
				os.Setenv(envVar, originalValue)
			} else {
				//nolint:errcheck // test cleanup doesn't need error checking
				os.Unsetenv(envVar)
			}
		}
	}()

	// Set test environment variables
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("DATABASE_URL", "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("PORT", "9090")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("JWT_SECRET", "env-jwt-secret")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("JWT_ACTIVE_KEY_ID", "primary-2026")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("JWT_KEYS", "primary-2026=env-primary-secret,primary-2025=env-previous-secret")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("DEBUG", "true")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("APP_ENV", "test")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("TRUSTED_PROXIES", "10.0.0.0/8")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("CORS_ENABLED", "true")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("CORS_ORIGINS", "http://localhost:3000")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("AUTH_RATE_LIMIT_REQUESTS", "7")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("AUTH_RATE_LIMIT_WINDOW", "5m")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_ENABLED", "true")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_HOST", "redis.example")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_PORT", "6380")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_PASSWORD", "redis-pass")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_DB", "2")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("REDIS_FAIL_OPEN", "true")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("CLICK_EVENT_RETENTION", "720h")
	//nolint:errcheck // test setup doesn't need error checking
	os.Setenv("CLICK_EVENT_CLEANUP_INTERVAL", "30m")

	// Load config - this should pick up environment variables
	config, err := Load()
	require.NoError(t, err)

	// Verify environment variables were loaded
	assert.Equal(t, "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require", config.Database.URL)
	assert.Equal(t, 9090, config.Server.Port)
	assert.Equal(t, "env-jwt-secret", config.JWT.Secret)
	assert.Equal(t, "primary-2026", config.JWT.ActiveKeyID)
	assert.Equal(t, []JWTKeyConfig{
		{ID: "primary-2026", Secret: "env-primary-secret"},
		{ID: "primary-2025", Secret: "env-previous-secret"},
	}, config.JWT.Keys)
	assert.True(t, config.App.Debug)
	assert.Equal(t, "test", config.App.Environment)
	assert.Equal(t, "10.0.0.0/8", config.App.TrustedProxies)
	assert.Equal(t, "http://localhost:3000", config.App.CORSOrigins)
	assert.Equal(t, 7, config.App.AuthRateLimit.Requests)
	assert.Equal(t, 5*time.Minute, config.App.AuthRateLimit.Window)
	assert.True(t, config.Redis.Enabled)
	assert.Equal(t, "redis.example", config.Redis.Host)
	assert.Equal(t, 6380, config.Redis.Port)
	assert.Equal(t, "redis-pass", config.Redis.Password)
	assert.Equal(t, 2, config.Redis.DB)
	assert.True(t, config.Redis.FailOpen)
	assert.Equal(t, 30*24*time.Hour, config.Analytics.ClickEventRetention)
	assert.Equal(t, 30*time.Minute, config.Analytics.CleanupInterval)

	// Note: DATABASE_URL parsing only fills empty fields, so we test the DatabaseURL() method instead
	expectedURL := "postgres://envuser:envpass@envhost:5433/envdb?sslmode=require"
	assert.Equal(t, expectedURL, config.DatabaseURL())
}

func TestLoadDefaults(t *testing.T) {
	// Clear environment variables that might interfere
	envVars := []string{"DATABASE_URL", "PORT", "JWT_SECRET", "JWT_ACTIVE_KEY_ID", "JWT_KEYS", "DEBUG", "APP_ENV", "TRUSTED_PROXIES", "CORS_ENABLED", "CORS_ORIGINS", "AUTH_RATE_LIMIT_REQUESTS", "AUTH_RATE_LIMIT_WINDOW", "REDIS_ENABLED", "REDIS_HOST", "REDIS_PORT", "REDIS_PASSWORD", "REDIS_DB", "REDIS_FAIL_OPEN", "CLICK_EVENT_RETENTION", "CLICK_EVENT_CLEANUP_INTERVAL", "DB_HOST"}
	originalVars := make(map[string]string)

	for _, envVar := range envVars {
		originalVars[envVar] = os.Getenv(envVar)
		//nolint:errcheck // test setup doesn't need error checking
		os.Unsetenv(envVar)
	}

	defer func() {
		for _, envVar := range envVars {
			if originalValue, exists := originalVars[envVar]; exists {
				//nolint:errcheck // test cleanup doesn't need error checking
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

	assert.Equal(t, "maigo-cli", config.OAuth2.ClientID)
	assert.Equal(t, "cli-client-secret-not-used-with-pkce", config.OAuth2.ClientSecret)

	assert.Equal(t, "dev_jwt_secret_change_in_production", config.JWT.Secret)
	assert.Empty(t, config.JWT.ActiveKeyID)
	assert.Empty(t, config.JWT.Keys)
	assert.Equal(t, 24*time.Hour, config.JWT.Expiration)

	assert.Equal(t, "Maigo", config.App.Name)
	assert.Equal(t, "development", config.App.Environment)
	assert.Empty(t, config.App.TrustedProxies)
	assert.Equal(t, "maigo.dev", config.App.BaseDomain)
	assert.Equal(t, 6, config.App.ShortCodeLength)
	assert.Equal(t, 100, config.App.RateLimit.Requests)
	assert.Equal(t, 1*time.Hour, config.App.RateLimit.Window)
	assert.Equal(t, 20, config.App.AuthRateLimit.Requests)
	assert.Equal(t, 15*time.Minute, config.App.AuthRateLimit.Window)
	assert.False(t, config.App.Debug)
	assert.False(t, config.App.CORSEnabled)
	assert.Empty(t, config.App.CORSOrigins)
	assert.False(t, config.Redis.Enabled)
	assert.Equal(t, "localhost", config.Redis.Host)
	assert.Equal(t, 6379, config.Redis.Port)
	assert.False(t, config.Redis.FailOpen)
	assert.Equal(t, 90*24*time.Hour, config.Analytics.ClickEventRetention)
	assert.Equal(t, time.Hour, config.Analytics.CleanupInterval)

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
