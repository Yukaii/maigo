package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() Config {
	return Config{
		Database: DatabaseConfig{Path: "data/maigo.db"},
		Server: ServerConfig{
			Host: "127.0.0.1", Port: 8080,
			ReadTimeout: 30, WriteTimeout: 30, IdleTimeout: 120,
		},
		Auth: AuthConfig{APIKey: "a-development-key"},
		App: AppConfig{
			Environment: "development", PublicURL: "http://localhost:8080", ShortCodeLength: 6,
		},
	}
}

func TestValidateAcceptsCoreConfig(t *testing.T) {
	cfg := validConfig()
	require.NoError(t, Validate(&cfg))
	assert.Equal(t, "127.0.0.1:8080", cfg.ServerAddr())
	assert.Equal(t, "http://localhost:8080/abc123", cfg.ShortURL("abc123"))
}

func TestValidateRejectsUnsafeProductionDefaults(t *testing.T) {
	cfg := validConfig()
	cfg.App.Environment = "production"
	cfg.Auth.APIKey = defaultAPIKey
	assert.ErrorContains(t, Validate(&cfg), "api key")

	cfg.Auth.APIKey = "a-unique-production-key-that-is-long-enough-123456"
	cfg.App.Debug = true
	assert.ErrorContains(t, Validate(&cfg), "debug")
}

func TestValidateRejectsInvalidPublicURL(t *testing.T) {
	cfg := validConfig()
	cfg.App.PublicURL = "ftp://example.com"
	assert.ErrorContains(t, Validate(&cfg), "scheme")

	cfg.App.PublicURL = "https://user:pass@example.com"
	assert.ErrorContains(t, Validate(&cfg), "credentials")
}

func TestLoadReadsCoreYAMLAndEnvironmentOverrides(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "maigo.yaml")
	contents := []byte("database:\n  path: ./from-file.db\nserver:\n  port: 9090\napp:\n  public_url: https://file.example\nauth:\n  api_key: file-key\n")
	require.NoError(t, os.WriteFile(configPath, contents, 0o600))
	t.Setenv("MAIGO_API_KEY", "environment-key")
	t.Setenv("MAIGO_PUBLIC_URL", "https://env.example/")

	cfg, err := Load(configPath)
	require.NoError(t, err)
	assert.Equal(t, "./from-file.db", cfg.Database.Path)
	assert.Equal(t, 9090, cfg.Server.Port)
	assert.Equal(t, "environment-key", cfg.Auth.APIKey)
	assert.Equal(t, "https://env.example", cfg.App.PublicURL)
}
