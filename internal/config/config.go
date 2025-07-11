package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for our application
type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Server   ServerConfig   `mapstructure:"server"`
	SSH      SSHConfig      `mapstructure:"ssh"`
	OAuth2   OAuth2Config   `mapstructure:"oauth2"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	App      AppConfig      `mapstructure:"app"`
	Log      LogConfig      `mapstructure:"log"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Name     string `mapstructure:"name"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	SSLMode  string `mapstructure:"ssl_mode"`
	MaxConns int    `mapstructure:"max_conns"`
	MaxIdle  int    `mapstructure:"max_idle"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Port         int           `mapstructure:"port"`
	Host         string        `mapstructure:"host"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
	IdleTimeout  time.Duration `mapstructure:"idle_timeout"`
}

// SSHConfig holds SSH server configuration
type SSHConfig struct {
	Port        int    `mapstructure:"port"`
	Host        string `mapstructure:"host"`
	HostKeyPath string `mapstructure:"host_key_path"`
}

// OAuth2Config holds OAuth2 configuration
type OAuth2Config struct {
	ClientID     string `mapstructure:"client_id"`
	ClientSecret string `mapstructure:"client_secret"`
	RedirectURI  string `mapstructure:"redirect_uri"`
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret     string        `mapstructure:"secret"`
	Expiration time.Duration `mapstructure:"expiration"`
}

// AppConfig holds application-specific configuration
type AppConfig struct {
	Name            string          `mapstructure:"name"`
	BaseDomain      string          `mapstructure:"base_domain"`
	Domain          string          `mapstructure:"domain"`
	TLS             bool            `mapstructure:"tls"`
	ShortCodeLength int             `mapstructure:"short_code_length"`
	RateLimit       RateLimitConfig `mapstructure:"rate_limit"`
	Debug           bool            `mapstructure:"debug"`
	CORSEnabled     bool            `mapstructure:"cors_enabled"`
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
	Requests int           `mapstructure:"requests"`
	Window   time.Duration `mapstructure:"window"`
}

// LogConfig holds logging configuration
type LogConfig struct {
	Level  string `mapstructure:"level"`
	Format string `mapstructure:"format"`
}

// Load loads configuration from various sources
func Load() (*Config, error) {
	v := viper.New()

	// Set configuration name and paths
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./configs")
	v.AddConfigPath("$HOME/.maigo")

	// Set environment variable prefix
	v.SetEnvPrefix("MAIGO")
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Set defaults
	setDefaults(v)

	// Read config file (optional)
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config file: %w", err)
		}
	}

	// Bind environment variables
	bindEnvVars(v)

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Database defaults
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.name", "maigo")
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "password")
	v.SetDefault("database.ssl_mode", "disable")
	v.SetDefault("database.max_conns", 10)
	v.SetDefault("database.max_idle", 5)

	// Server defaults
	v.SetDefault("server.port", 8080)
	v.SetDefault("server.host", "127.0.0.1")
	v.SetDefault("server.read_timeout", "30s")
	v.SetDefault("server.write_timeout", "30s")
	v.SetDefault("server.idle_timeout", "120s")

	// SSH defaults
	v.SetDefault("ssh.port", 2222)
	v.SetDefault("ssh.host", "127.0.0.1")
	v.SetDefault("ssh.host_key_path", "host_keys/ssh_host_rsa_key")

	// OAuth2 defaults
	v.SetDefault("oauth2.client_id", "maigo_cli")
	v.SetDefault("oauth2.client_secret", "dev_secret_change_in_production")
	v.SetDefault("oauth2.redirect_uri", "urn:ietf:wg:oauth:2.0:oob")

	// JWT defaults
	v.SetDefault("jwt.secret", "dev_jwt_secret_change_in_production")
	v.SetDefault("jwt.expiration", "24h")

	// App defaults
	v.SetDefault("app.name", "Maigo")
	v.SetDefault("app.base_domain", "maigo.dev")
	v.SetDefault("app.domain", "maigo.dev")
	v.SetDefault("app.tls", false)
	v.SetDefault("app.short_code_length", 6)
	v.SetDefault("app.rate_limit.requests", 100)
	v.SetDefault("app.rate_limit.window", "1h")
	v.SetDefault("app.debug", false)
	v.SetDefault("app.cors_enabled", true)

	// Log defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
}

// bindEnvVars binds environment variables to configuration keys
func bindEnvVars(v *viper.Viper) {
	envVars := map[string]string{
		"DB_HOST":     "database.host",
		"DB_PORT":     "database.port",
		"DB_NAME":     "database.name",
		"DB_USER":     "database.user",
		"DB_PASSWORD": "database.password",
		"DB_SSL_MODE": "database.ssl_mode",

		"HTTP_PORT": "server.port",
		"HOST":      "server.host",

		"SSH_PORT": "ssh.port",

		"OAUTH2_CLIENT_ID":     "oauth2.client_id",
		"OAUTH2_CLIENT_SECRET": "oauth2.client_secret",
		"OAUTH2_REDIRECT_URI":  "oauth2.redirect_uri",

		"JWT_SECRET":     "jwt.secret",
		"JWT_EXPIRATION": "jwt.expiration",

		"BASE_DOMAIN":            "app.base_domain",
		"SHORT_CODE_LENGTH":      "app.short_code_length",
		"RATE_LIMIT_REQUESTS":    "app.rate_limit.requests",
		"RATE_LIMIT_WINDOW":      "app.rate_limit.window",
		"DEBUG":                  "app.debug",
		"CORS_ENABLED":           "app.cors_enabled",

		"LOG_LEVEL":  "log.level",
		"LOG_FORMAT": "log.format",
	}

	for env, key := range envVars {
		if val := os.Getenv(env); val != "" {
			v.Set(key, val)
		}
	}
}

// validateConfig validates the configuration
func validateConfig(cfg *Config) error {
	if cfg.Database.Host == "" {
		return fmt.Errorf("database host is required")
	}
	if cfg.Database.Name == "" {
		return fmt.Errorf("database name is required")
	}
	if cfg.Database.User == "" {
		return fmt.Errorf("database user is required")
	}
	if cfg.OAuth2.ClientID == "" {
		return fmt.Errorf("oauth2 client ID is required")
	}
	if cfg.OAuth2.ClientSecret == "" {
		return fmt.Errorf("oauth2 client secret is required")
	}
	if cfg.JWT.Secret == "" {
		return fmt.Errorf("jwt secret is required")
	}
	if cfg.App.BaseDomain == "" {
		return fmt.Errorf("base domain is required")
	}
	if cfg.App.ShortCodeLength < 3 || cfg.App.ShortCodeLength > 10 {
		return fmt.Errorf("short code length must be between 3 and 10")
	}

	return nil
}

// DatabaseURL returns the database connection URL
func (c *Config) DatabaseURL() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		c.Database.SSLMode,
	)
}

// ServerAddr returns the server address
func (c *Config) ServerAddr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

// SSHAddr returns the SSH server address
func (c *Config) SSHAddr() string {
	return fmt.Sprintf("%s:%d", c.SSH.Host, c.SSH.Port)
}
