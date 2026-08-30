// Package config provides configuration management for Maigo.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for our application
type Config struct {
	Database DatabaseConfig `mapstructure:"database"`
	Server   ServerConfig   `mapstructure:"server"`
	OAuth2   OAuth2Config   `mapstructure:"oauth2"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	App      AppConfig      `mapstructure:"app"`
	Log      LogConfig      `mapstructure:"log"`
	Redis    RedisConfig    `mapstructure:"redis"`
}

// DatabaseConfig holds database configuration
type DatabaseConfig struct {
	// Primary DATABASE_URL (12-factor app style)
	URL string `mapstructure:"url"`

	// Individual connection parameters (fallback)
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
	Environment     string          `mapstructure:"environment"`
	BaseDomain      string          `mapstructure:"base_domain"`
	Domain          string          `mapstructure:"domain"`
	TrustedProxies  string          `mapstructure:"trusted_proxies"`
	TLS             bool            `mapstructure:"tls"`
	ShortCodeLength int             `mapstructure:"short_code_length"`
	RateLimit       RateLimitConfig `mapstructure:"rate_limit"`
	AuthRateLimit   RateLimitConfig `mapstructure:"auth_rate_limit"`
	Debug           bool            `mapstructure:"debug"`
	CORSEnabled     bool            `mapstructure:"cors_enabled"`
	CORSOrigins     string          `mapstructure:"cors_origins"`
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

// RedisConfig holds Redis configuration
type RedisConfig struct {
	Enabled  bool   `mapstructure:"enabled"`
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Password string `mapstructure:"password"`
	DB       int    `mapstructure:"db"`
	FailOpen bool   `mapstructure:"fail_open"`
}

// Load loads configuration from various sources
// If configFile is provided, it will be used instead of searching default paths
func Load(configFile ...string) (*Config, error) {
	v := viper.New()

	// If specific config file is provided, use it
	if len(configFile) > 0 && configFile[0] != "" {
		v.SetConfigFile(configFile[0])
	} else if configPath := os.Getenv("CONFIG_PATH"); configPath != "" {
		v.SetConfigFile(configPath)
	} else {
		// Set configuration name and paths for default search
		v.SetConfigName("maigo")
		v.SetConfigType("yaml")
		v.AddConfigPath(".")
		v.AddConfigPath("$HOME/.maigo")
	}

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

	// Parse DATABASE_URL if provided and populate individual fields
	if err := cfg.ParseDatabaseURL(); err != nil {
		return nil, fmt.Errorf("failed to parse DATABASE_URL: %w", err)
	}

	// Validate configuration
	if err := validateConfig(&cfg); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return &cfg, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// Database defaults (individual parameters as fallback)
	v.SetDefault("database.url", "") // DATABASE_URL takes precedence when set
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

	// OAuth2 defaults
	v.SetDefault("oauth2.client_id", "maigo-cli")
	v.SetDefault("oauth2.client_secret", "cli-client-secret-not-used-with-pkce")
	v.SetDefault("oauth2.redirect_uri", "http://localhost:8000/callback")

	// JWT defaults
	v.SetDefault("jwt.secret", "dev_jwt_secret_change_in_production")
	v.SetDefault("jwt.expiration", "24h")

	// Redis defaults
	v.SetDefault("redis.enabled", false)
	v.SetDefault("redis.host", "localhost")
	v.SetDefault("redis.port", 6379)
	v.SetDefault("redis.password", "")
	v.SetDefault("redis.db", 0)
	v.SetDefault("redis.fail_open", false)

	// App defaults
	v.SetDefault("app.name", "Maigo")
	v.SetDefault("app.environment", "development")
	v.SetDefault("app.base_domain", "maigo.dev")
	v.SetDefault("app.domain", "maigo.dev")
	v.SetDefault("app.trusted_proxies", "")
	v.SetDefault("app.tls", false)
	v.SetDefault("app.short_code_length", 6)
	v.SetDefault("app.rate_limit.requests", 100)
	v.SetDefault("app.rate_limit.window", "1h")
	v.SetDefault("app.auth_rate_limit.requests", 20)
	v.SetDefault("app.auth_rate_limit.window", "15m")
	v.SetDefault("app.debug", false)
	v.SetDefault("app.cors_enabled", false)
	v.SetDefault("app.cors_origins", "")

	// Log defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
}

// bindEnvVars binds environment variables to configuration keys
func bindEnvVars(v *viper.Viper) {
	envVars := map[string]string{
		// 12-factor DATABASE_URL support (highest priority)
		"DATABASE_URL": "database.url",

		// Individual database parameters (12-factor compatible)
		"DB_HOST":     "database.host",
		"DB_PORT":     "database.port",
		"DB_NAME":     "database.name",
		"DB_USER":     "database.user",
		"DB_PASSWORD": "database.password",
		"DB_SSL_MODE": "database.ssl_mode",

		// Server configuration (12-factor compatible)
		"PORT":      "server.port", // Standard Heroku PORT variable
		"HTTP_PORT": "server.port", // Alternative naming
		"HOST":      "server.host",

		// OAuth2 configuration
		"OAUTH2_CLIENT_ID":     "oauth2.client_id",
		"OAUTH2_CLIENT_SECRET": "oauth2.client_secret",
		"OAUTH2_REDIRECT_URI":  "oauth2.redirect_uri",

		// JWT configuration
		"JWT_SECRET":     "jwt.secret",
		"JWT_EXPIRATION": "jwt.expiration",

		// Redis configuration
		"REDIS_ENABLED":   "redis.enabled",
		"REDIS_HOST":      "redis.host",
		"REDIS_PORT":      "redis.port",
		"REDIS_PASSWORD":  "redis.password",
		"REDIS_DB":        "redis.db",
		"REDIS_FAIL_OPEN": "redis.fail_open",

		// Application configuration
		"APP_ENV":                  "app.environment",
		"BASE_DOMAIN":              "app.base_domain",
		"TRUSTED_PROXIES":          "app.trusted_proxies",
		"APP_TLS":                  "app.tls",
		"SHORT_CODE_LENGTH":        "app.short_code_length",
		"RATE_LIMIT_REQUESTS":      "app.rate_limit.requests",
		"RATE_LIMIT_WINDOW":        "app.rate_limit.window",
		"AUTH_RATE_LIMIT_REQUESTS": "app.auth_rate_limit.requests",
		"AUTH_RATE_LIMIT_WINDOW":   "app.auth_rate_limit.window",
		"DEBUG":                    "app.debug",
		"CORS_ENABLED":             "app.cors_enabled",
		"CORS_ORIGINS":             "app.cors_origins",

		// Logging configuration
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
	// Database validation - either DATABASE_URL or individual parameters required
	if cfg.Database.URL == "" {
		if cfg.Database.Host == "" {
			return fmt.Errorf("database host is required (or set DATABASE_URL)")
		}
		if cfg.Database.Name == "" {
			return fmt.Errorf("database name is required (or set DATABASE_URL)")
		}
		if cfg.Database.User == "" {
			return fmt.Errorf("database user is required (or set DATABASE_URL)")
		}
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
	if strings.EqualFold(strings.TrimSpace(cfg.App.Environment), "production") {
		if cfg.App.Debug {
			return fmt.Errorf("debug must be disabled in production")
		}
		if len([]byte(cfg.JWT.Secret)) < 32 {
			return fmt.Errorf("jwt secret must be at least 32 bytes in production")
		}
		if isPlaceholderJWTSecret(cfg.JWT.Secret) {
			return fmt.Errorf("jwt secret must be replaced with a unique secret in production")
		}
		if isPlaceholderDatabasePassword(databasePasswordForValidation(cfg)) {
			return fmt.Errorf("database password must be replaced with a unique secret in production")
		}
		if cfg.Redis.Enabled && isPlaceholderRedisPassword(cfg.Redis.Password) {
			return fmt.Errorf("redis password must be replaced with a unique secret in production")
		}
	}
	if cfg.App.BaseDomain == "" {
		return fmt.Errorf("base domain is required")
	}
	for _, proxy := range cfg.App.TrustedProxyList() {
		if net.ParseIP(proxy) == nil {
			if _, _, err := net.ParseCIDR(proxy); err != nil {
				return fmt.Errorf("invalid trusted proxy %q: expected an IP address or CIDR", proxy)
			}
		}
	}
	if cfg.Redis.Enabled {
		if cfg.Redis.Host == "" {
			return fmt.Errorf("redis host is required when Redis is enabled")
		}
		if cfg.Redis.Port < 1 || cfg.Redis.Port > 65535 {
			return fmt.Errorf("redis port must be between 1 and 65535")
		}
		if cfg.Redis.DB < 0 {
			return fmt.Errorf("redis database number cannot be negative")
		}
	}
	if cfg.App.CORSEnabled {
		origins := cfg.App.AllowedCORSOrigins()
		if len(origins) == 0 && !cfg.App.Debug {
			return fmt.Errorf("cors origins are required when CORS is enabled with debug disabled")
		}
		for _, origin := range origins {
			if err := validateCORSOrigin(origin); err != nil {
				return err
			}
			if !cfg.App.Debug && origin == "*" {
				return fmt.Errorf("wildcard CORS origin is not allowed with debug disabled")
			}
		}
	}
	if cfg.App.ShortCodeLength < 3 || cfg.App.ShortCodeLength > 10 {
		return fmt.Errorf("short code length must be between 3 and 10")
	}

	return nil
}

// AllowedCORSOrigins returns the configured browser origins. Origins are
// comma-separated so they can be supplied through a single environment
// variable in a 12-factor deployment.
func (c AppConfig) AllowedCORSOrigins() []string {
	var origins []string
	for _, origin := range strings.Split(c.CORSOrigins, ",") {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			origins = append(origins, origin)
		}
	}

	return origins
}

// TrustedProxyList returns the configured proxy IPs or CIDR ranges. An empty
// list intentionally disables forwarded-client-IP trust.
func (c AppConfig) TrustedProxyList() []string {
	var proxies []string
	for _, proxy := range strings.Split(c.TrustedProxies, ",") {
		proxy = strings.TrimSpace(proxy)
		if proxy != "" {
			proxies = append(proxies, proxy)
		}
	}

	return proxies
}

func isPlaceholderJWTSecret(secret string) bool {
	switch strings.TrimSpace(strings.ToLower(secret)) {
	case "dev_jwt_secret_change_in_production",
		"change-this-in-production",
		"your-secure-jwt-secret-minimum-32-characters":
		return true
	default:
		return false
	}
}

func databasePasswordForValidation(cfg *Config) string {
	if cfg.Database.URL != "" {
		if parsedURL, err := url.Parse(cfg.Database.URL); err == nil && parsedURL.User != nil {
			if password, ok := parsedURL.User.Password(); ok {
				return password
			}
		}
	}

	return cfg.Database.Password
}

func isPlaceholderDatabasePassword(password string) bool {
	switch strings.TrimSpace(strings.ToLower(password)) {
	case "password", "maigo_secret", "your-secure-database-password-here":
		return true
	default:
		return false
	}
}

func isPlaceholderRedisPassword(password string) bool {
	switch strings.TrimSpace(strings.ToLower(password)) {
	case "redis_secret", "your-secure-redis-password":
		return true
	default:
		return false
	}
}

func validateCORSOrigin(origin string) error {
	if origin == "*" {
		return nil
	}

	parsed, err := url.Parse(origin)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return fmt.Errorf("invalid CORS origin %q: expected an http(s) origin without a path", origin)
	}

	return nil
}

// DatabaseURL returns the database connection URL
func (c *Config) DatabaseURL() string {
	// If DATABASE_URL is set, use it directly (12-factor app style)
	if c.Database.URL != "" {
		return c.Database.URL
	}

	// Otherwise, construct a URL using net/url so credentials, database names,
	// and IPv6 hosts are escaped correctly.
	databaseURL := &url.URL{
		Scheme:   "postgres",
		Host:     net.JoinHostPort(c.Database.Host, strconv.Itoa(c.Database.Port)),
		Path:     "/" + c.Database.Name,
		RawQuery: url.Values{"sslmode": {c.Database.SSLMode}}.Encode(),
	}
	if c.Database.Password == "" {
		databaseURL.User = url.User(c.Database.User)
	} else {
		databaseURL.User = url.UserPassword(c.Database.User, c.Database.Password)
	}

	return databaseURL.String()
}

// ServerAddr returns the server address
func (c *Config) ServerAddr() string {
	return net.JoinHostPort(c.Server.Host, strconv.Itoa(c.Server.Port))
}

// ParseDatabaseURL parses DATABASE_URL and populates individual database fields
func (c *Config) ParseDatabaseURL() error {
	if c.Database.URL == "" {
		return nil // No DATABASE_URL to parse
	}

	parsedURL, err := url.Parse(c.Database.URL)
	if err != nil {
		return fmt.Errorf("invalid DATABASE_URL format: %w", err)
	}
	if (parsedURL.Scheme != "postgres" && parsedURL.Scheme != "postgresql") ||
		parsedURL.Hostname() == "" || strings.Trim(parsedURL.Path, "/") == "" {
		return fmt.Errorf("invalid DATABASE_URL format: expected postgres://user:password@host:port/database")
	}

	populateHost(&c.Database, parsedURL)
	populatePort(&c.Database, parsedURL)
	populateName(&c.Database, parsedURL)
	populateUser(&c.Database, parsedURL)
	populatePassword(&c.Database, parsedURL)
	populateSSLMode(&c.Database, parsedURL)

	return nil
}

func populateHost(db *DatabaseConfig, u *url.URL) {
	if db.Host == "" && u.Hostname() != "" {
		db.Host = u.Hostname()
	}
}

func populatePort(db *DatabaseConfig, u *url.URL) {
	if db.Port == 0 && u.Port() != "" {
		if port, err := strconv.Atoi(u.Port()); err == nil {
			db.Port = port
		}
	}
}

func populateName(db *DatabaseConfig, u *url.URL) {
	if db.Name == "" && u.Path != "" {
		dbName := strings.TrimPrefix(u.Path, "/")
		if dbName != "" {
			db.Name = dbName
		}
	}
}

func populateUser(db *DatabaseConfig, u *url.URL) {
	if db.User == "" && u.User != nil {
		db.User = u.User.Username()
	}
}

func populatePassword(db *DatabaseConfig, u *url.URL) {
	if db.Password == "" && u.User != nil {
		if password, ok := u.User.Password(); ok {
			db.Password = password
		}
	}
}

func populateSSLMode(db *DatabaseConfig, u *url.URL) {
	if db.SSLMode == "" {
		if sslMode := u.Query().Get("sslmode"); sslMode != "" {
			db.SSLMode = sslMode
		}
	}
}
