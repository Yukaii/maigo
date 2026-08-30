// Package server starts and configures the Maigo Core HTTP server.
package server

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/server/handlers"
	"github.com/yukaii/maigo/internal/server/middleware"
)

// HTTPServer wraps the Gin engine and Core dependencies.
type HTTPServer struct {
	engine *gin.Engine
	config *config.Config
	db     *sql.DB
	logger *logger.Logger
}

// NewHTTPServer creates a Core HTTP server backed by SQLite.
func NewHTTPServer(cfg *config.Config, db *sql.DB, log *logger.Logger) *HTTPServer {
	if !cfg.App.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	engine := gin.New()
	server := &HTTPServer{
		engine: engine,
		config: cfg,
		db:     db,
		logger: log,
	}

	engine.Use(middleware.Logger(log))
	engine.Use(middleware.Recovery(log))
	engine.Use(middleware.RequestID())
	server.setupRoutes()
	return server
}

// ServeHTTP implements http.Handler.
func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.engine.ServeHTTP(w, r)
}

func (s *HTTPServer) setupRoutes() {
	healthHandler := handlers.NewHealthHandler(s.db, s.logger)
	urlHandler := handlers.NewURLHandler(s.db, s.config, s.logger)
	apiKey := middleware.APIKey(s.config)

	s.engine.GET("/health", healthHandler.HealthCheck)
	s.engine.HEAD("/health", healthHandler.HealthCheck)
	s.engine.GET("/health/ready", healthHandler.ReadinessCheck)
	s.engine.HEAD("/health/ready", healthHandler.ReadinessCheck)

	v1 := s.engine.Group("/api/v1")
	urls := v1.Group("/urls")
	urls.POST("", apiKey, urlHandler.CreateShortURL)
	urls.GET("", apiKey, urlHandler.ListURLs)
	urls.GET("/:code", urlHandler.GetURL)
	urls.GET("/:code/stats", apiKey, urlHandler.GetURLStats)
	urls.DELETE("/:code", apiKey, urlHandler.DeleteURL)

	// Short links stay at the public root so the configured PUBLIC_URL can be
	// put directly behind a reverse proxy or a DNS record.
	s.engine.GET("/:code", urlHandler.RedirectShortURL)

	s.engine.NoRoute(func(c *gin.Context) {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "The requested resource was not found",
		})
	})
}
