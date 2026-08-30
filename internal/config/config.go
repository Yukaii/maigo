// Package config provides the small configuration surface needed by Maigo
// Core.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/viper"
)

// #nosec G101 -- this is an explicit development-only placeholder; production
// validation rejects it and deployment examples require replacement.
const defaultAPIKey = "dev_maigo_api_key_change_me"

// Config contains the runtime configuration for a single-owner Maigo Core
// installation.
type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Server   ServerConfig   `mapstructure:"server"`
	Auth     AuthConfig     `mapstructure:"auth"`
	App      AppConfig      `mapstructure:"app"`
	Log      LogConfig      `mapstructure:"log"`
}

// DatabaseConfig selects the SQLite database file.
type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

// ServerConfig controls the HTTP listener.
type ServerConfig struct {
	Port         int    `mapstructure:"port"`
	Host         string `mapstructure:"host"`
	ReadTimeout  int    `mapstructure:"read_timeout_seconds"`
	WriteTimeout int    `mapstructure:"write_timeout_seconds"`
	IdleTimeout  int    `mapstructure:"idle_timeout_seconds"`
}

// AuthConfig contains the one API key used to protect management operations.
type AuthConfig struct {
	APIKey string `mapstructure:"api_key"`
}

// AppConfig controls public link generation and short-code validation.
type AppConfig struct {
	Environment     string `mapstructure:"environment"`
	PublicURL       string `mapstructure:"public_url"`
	ShortCodeLength int    `mapstructure:"short_code_length"`
	Debug           bool   `mapstructure:"debug"`
}

// LogConfig controls structured application logging.
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load reads configuration from a YAML file and environment variables.
// Environment variables take precedence over file values.
func Load(configFile ...string) (*Config, error) {
	v := viper.New()
	if len(configFile) > 0 && configFile[0] != "" {
		v.SetConfigFile(configFile[0])
	} else if configPath := os.Getenv("CONFIG_PATH"); configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		v.SetConfigName("maigo")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.maigo")
	}

	v.SetEnvPrefix("MAIGO")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	setDefaults(v)

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
	}
	bindEnvVars(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	if err := validate(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	cfg.App.PublicURL = strings.TrimRight(cfg.App.PublicURL, "/")
	return &cfg, nil
}

func setDefaults(v *viper.Viper) {
	v.SetDefault("database.path", "data/maigo.db")
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.read_timeout_seconds", 30)
	v.SetDefault("server.write_timeout_seconds", 30)
	v.SetDefault("server.idle_timeout_seconds", 120)
	v.SetDefault("auth.api_key", defaultAPIKey)
	v.SetDefault("app.environment", "development")
	v.SetDefault("app.public_url", "http://127.0.0.1:8080")
	v.SetDefault("app.short_code_length", 6)
	v.SetDefault("app.debug", false)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "text")
}

func bindEnvVars(v *viper.Viper) {
	bindEnv(v, "database.path", "MAIGO_DATABASE_PATH", "DATABASE_PATH")
	bindEnv(v, "server.port", "MAIGO_PORT", "PORT")
	bindEnv(v, "server.host", "MAIGO_HOST", "HOST")
	bindEnv(v, "auth.api_key", "MAIGO_API_KEY", "API_KEY")
	bindEnv(v, "app.environment", "MAIGO_APP_ENV", "APP_ENV")
	bindEnv(v, "app.public_url", "MAIGO_PUBLIC_URL", "PUBLIC_URL")
	bindEnv(v, "app.short_code_length", "MAIGO_SHORT_CODE_LENGTH", "SHORT_CODE_LENGTH")
	bindEnv(v, "app.debug", "MAIGO_DEBUG", "DEBUG")
	bindEnv(v, "log.level", "MAIGO_LOG_LEVEL", "LOG_LEVEL")
	bindEnv(v, "log.format", "MAIGO_LOG_FORMAT", "LOG_FORMAT")
}

func bindEnv(v *viper.Viper, key string, names ...string) {
	for _, name := range names {
		if value, ok := os.LookupEnv(name); ok && strings.TrimSpace(value) != "" {
			v.Set(key, value)
			return
		}
	}
}

func validate(cfg *Config) error {
	if strings.TrimSpace(cfg.Database.Path) == "" {
		return fmt.Errorf("database path is required")
	}
	if cfg.Database.Path != ":memory:" {
		if filepath.IsAbs(cfg.Database.Path) && filepath.Dir(cfg.Database.Path) == string(filepath.Separator) {
			return fmt.Errorf("database path must not be directly under the filesystem root")
		}
	}
	if cfg.Server.Port < 1 || cfg.Server.Port > 65535 {
		return fmt.Errorf("server port must be between 1 and 65535")
	}
	if strings.TrimSpace(cfg.Server.Host) == "" {
		return fmt.Errorf("server host is required")
	}
	if cfg.Server.ReadTimeout <= 0 || cfg.Server.WriteTimeout <= 0 || cfg.Server.IdleTimeout <= 0 {
		return fmt.Errorf("server timeouts must be positive")
	}
	if strings.TrimSpace(cfg.Auth.APIKey) == "" {
		return fmt.Errorf("api key is required")
	}
	if cfg.App.ShortCodeLength < 3 || cfg.App.ShortCodeLength > 10 {
		return fmt.Errorf("short code length must be between 3 and 10")
	}
	if err := validatePublicURL(cfg.App.PublicURL); err != nil {
		return err
	}
	if strings.EqualFold(strings.TrimSpace(cfg.App.Environment), "production") {
		if cfg.App.Debug {
			return fmt.Errorf("debug must be disabled in production")
		}
		if len([]byte(cfg.Auth.APIKey)) < 32 || isPlaceholderAPIKey(cfg.Auth.APIKey) {
			return fmt.Errorf("api key must be a unique secret of at least 32 bytes in production")
		}
	}
	return nil
}

// Validate checks a configuration after command-line overrides have been
// applied. Load calls the same validation automatically.
func Validate(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration is required")
	}
	return validate(cfg)
}

func validatePublicURL(raw string) error {
	parsed, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return fmt.Errorf("public URL must include an HTTP(S) scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("public URL scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("public URL must not include credentials, query, or fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return fmt.Errorf("public URL must be an origin without a path")
	}
	return nil
}

func isPlaceholderAPIKey(key string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	return lower == defaultAPIKey || strings.Contains(lower, "change-me") || strings.Contains(lower, "replace")
}

// ServerAddr returns the HTTP listener address.
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}

// ShortURL builds the canonical public link for a short code.
func (c *Config) ShortURL(shortCode string) string {
	return strings.TrimRight(c.App.PublicURL, "/") + "/" + shortCode
}
