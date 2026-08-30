// Package server starts and configures the Maigo HTTP server.
package server

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/server/handlers"
	"github.com/yukaii/maigo/internal/server/middleware"
)

//go:embed templates/*
var templatesFS embed.FS

// HTTPServer wraps Gin engine with our configuration
type HTTPServer struct {
	engine *gin.Engine
	config *config.Config
	db     *pgxpool.Pool
	redis  *redis.Client
	logger *logger.Logger
}

// NewHTTPServer creates a new HTTP server instance
func NewHTTPServer(cfg *config.Config, db *pgxpool.Pool, log *logger.Logger) *HTTPServer {
	return NewHTTPServerWithRedis(cfg, db, log, nil)
}

// NewHTTPServerWithRedis creates an HTTP server with an optional verified Redis
// client for distributed rate limiting.
func NewHTTPServerWithRedis(
	cfg *config.Config,
	db *pgxpool.Pool,
	log *logger.Logger,
	redisClient *redis.Client,
) *HTTPServer {
	// Create Gin engine
	engine := gin.New()
	if err := engine.SetTrustedProxies(cfg.App.TrustedProxyList()); err != nil {
		// Configuration is validated before this constructor is called. Keep a
		// safe direct-connection policy if a caller constructs Config manually.
		log.Error("Invalid trusted proxy configuration; forwarded headers disabled", "error", err)
		_ = engine.SetTrustedProxies(nil)
	}

	// Load HTML templates from embedded filesystem
	templ := template.Must(template.New("").ParseFS(templatesFS,
		"templates/layouts/*.tmpl",
		"templates/styles/*.css",
		"templates/oauth/*.tmpl"))
	engine.SetHTMLTemplate(templ)

	// Add custom middleware
	engine.Use(middleware.Logger(log))
	engine.Use(middleware.Recovery(log))
	engine.Use(middleware.RequestID())

	// Add CORS middleware if enabled
	if cfg.App.CORSEnabled {
		corsConfig := cors.DefaultConfig()
		corsOrigins := cfg.App.AllowedCORSOrigins()
		if len(corsOrigins) == 0 && cfg.App.Debug {
			corsOrigins = []string{"*"}
		}
		if len(corsOrigins) > 0 {
			corsConfig.AllowOrigins = corsOrigins
			corsConfig.AllowCredentials = !containsWildcard(corsOrigins)
			corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
			corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Authorization", "X-Request-ID"}
			corsConfig.ExposeHeaders = []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"}
			engine.Use(cors.New(corsConfig))
		}
	}

	server := &HTTPServer{
		engine: engine,
		config: cfg,
		db:     db,
		redis:  redisClient,
		logger: log,
	}

	// Setup routes
	server.setupRoutes()

	return server
}

func containsWildcard(origins []string) bool {
	for _, origin := range origins {
		if origin == "*" {
			return true
		}
	}
	return false
}

// ServeHTTP implements http.Handler interface
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.engine.ServeHTTP(w, r)
}

func (s *HTTPServer) rateLimiter(rateLimitConfig config.RateLimitConfig, keyPrefix string) gin.HandlerFunc {
	if s.redis != nil {
		return middleware.RateLimiter(middleware.RateLimitConfig{
			Limit:       rateLimitConfig.Requests,
			Window:      rateLimitConfig.Window,
			RedisClient: s.redis,
			KeyPrefix:   keyPrefix,
			FailOpen:    s.config.Redis.FailOpen,
		})
	}

	return middleware.RateLimit(rateLimitConfig)
}

// setupRoutes configures all HTTP routes
func (s *HTTPServer) setupRoutes() {
	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(s.db, s.logger, s.redis)
	urlHandler := handlers.NewURLHandler(s.db, s.config, s.logger)
	authHandler := handlers.NewAuthHandler(s.db, s.config, s.logger)
	oauthHandler := handlers.NewOAuthHandler(s.db, s.config, s.logger)
	authRateLimiter := s.rateLimiter(s.config.App.AuthRateLimit, "ratelimit:auth")
	urlRateLimiter := s.rateLimiter(s.config.App.RateLimit, "ratelimit:url")

	// Health check endpoint
	s.engine.GET("/health", healthHandler.HealthCheck)
	s.engine.HEAD("/health", healthHandler.HealthCheck)
	s.engine.GET("/health/ready", healthHandler.ReadinessCheck)
	s.engine.HEAD("/health/ready", healthHandler.ReadinessCheck)

	// OAuth 2.0 endpoints
	oauth := s.engine.Group("/oauth")
	oauth.GET("/authorize", authRateLimiter, oauthHandler.AuthorizeEndpoint)
	oauth.POST("/authorize", authRateLimiter, oauthHandler.AuthorizePostEndpoint)
	oauth.POST("/token", authRateLimiter, oauthHandler.TokenEndpoint)
	oauth.POST("/revoke", authRateLimiter, oauthHandler.RevokeEndpoint)

	// API v1 routes
	v1 := s.engine.Group("/api/v1")

	// URL shortening endpoints
	urls := v1.Group("/urls")
	urls.POST("", middleware.Auth(s.config), urlRateLimiter, urlHandler.CreateShortURL)
	urls.GET("/:code", urlHandler.GetURL)
	urls.GET("/:code/stats", middleware.Auth(s.config), urlHandler.GetURLStats)
	urls.DELETE("/:code", middleware.Auth(s.config), urlHandler.DeleteURL)

	// Authentication endpoints (legacy - keeping for backward compatibility)
	auth := v1.Group("/auth")
	auth.POST("/register", authRateLimiter, authHandler.Register)
	auth.POST("/login", authRateLimiter, authHandler.Login)
	auth.POST("/token", authRateLimiter, authHandler.RefreshToken)
	auth.POST("/logout", middleware.Auth(s.config), authHandler.Logout)

	// Protected user endpoints
	user := v1.Group("/user", middleware.Auth(s.config))
	user.GET("/profile", authHandler.GetProfile)
	user.GET("/urls", urlHandler.GetUserURLs)

	// Short URL redirect (should be on root domain)
	s.engine.GET("/:code", urlHandler.RedirectShortURL)

	// Static files (if any)
	s.engine.Static("/static", "./web/static")

	// 404 handler
	s.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "Not Found",
			"message": "The requested resource was not found",
		})
	})
}

// Shutdown gracefully shuts down the server
func (s *HTTPServer) Shutdown() error {
	if s.redis != nil {
		if err := s.redis.Close(); err != nil {
			return err
		}
		s.redis = nil
	}
	// Any cleanup logic can go here
	s.logger.Info("HTTP server shutdown completed")
	return nil
}
