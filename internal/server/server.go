package server

import (
	"embed"
	"html/template"
	"net/http"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
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
	logger *logger.Logger
}

// NewHTTPServer creates a new HTTP server instance
func NewHTTPServer(cfg *config.Config, db *pgxpool.Pool, log *logger.Logger) *HTTPServer {
	// Create Gin engine
	engine := gin.New()

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
		corsConfig.AllowOrigins = []string{"*"} // Configure this properly for production
		corsConfig.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
		corsConfig.AllowHeaders = []string{"Origin", "Content-Type", "Authorization"}
		engine.Use(cors.New(corsConfig))
	}

	server := &HTTPServer{
		engine: engine,
		config: cfg,
		db:     db,
		logger: log,
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// ServeHTTP implements http.Handler interface
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.engine.ServeHTTP(w, r)
}

// setupRoutes configures all HTTP routes
func (s *HTTPServer) setupRoutes() {
	// Initialize handlers
	healthHandler := handlers.NewHealthHandler(s.db, s.logger)
	urlHandler := handlers.NewURLHandler(s.db, s.config, s.logger)
	authHandler := handlers.NewAuthHandler(s.db, s.config, s.logger)
	oauthHandler := handlers.NewOAuthHandler(s.db, s.config, s.logger)

	// Health check endpoint
	s.engine.GET("/health", healthHandler.HealthCheck)
	s.engine.GET("/health/ready", healthHandler.ReadinessCheck)

	// OAuth 2.0 endpoints
	oauth := s.engine.Group("/oauth")
	{
		oauth.GET("/authorize", oauthHandler.AuthorizeEndpoint)
		oauth.POST("/authorize", oauthHandler.AuthorizePostEndpoint)
		oauth.POST("/token", oauthHandler.TokenEndpoint)
		oauth.POST("/revoke", oauthHandler.RevokeEndpoint)
	}

	// API v1 routes
	v1 := s.engine.Group("/api/v1")
	{
		// URL shortening endpoints
		urls := v1.Group("/urls")
		{
			urls.POST("", middleware.RateLimit(s.config.App.RateLimit), middleware.Auth(s.config), urlHandler.CreateShortURL)
			urls.GET("/:code", urlHandler.GetURL)
			urls.GET("/:code/stats", middleware.Auth(s.config), urlHandler.GetURLStats)
			urls.DELETE("/:code", middleware.Auth(s.config), urlHandler.DeleteURL)
		}

		// Authentication endpoints (legacy - keeping for backward compatibility)
		auth := v1.Group("/auth")
		{
			auth.POST("/register", authHandler.Register)
			auth.POST("/login", authHandler.Login)
			auth.POST("/token", authHandler.RefreshToken)
			auth.POST("/logout", middleware.Auth(s.config), authHandler.Logout)
		}

		// Protected user endpoints
		user := v1.Group("/user", middleware.Auth(s.config))
		{
			user.GET("/profile", authHandler.GetProfile)
			user.GET("/urls", urlHandler.GetUserURLs)
		}
	}

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
	// Any cleanup logic can go here
	s.logger.Info("HTTP server shutdown completed")
	return nil
}
