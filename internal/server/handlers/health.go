package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	db     *pgxpool.Pool
	logger *logger.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *pgxpool.Pool, log *logger.Logger) *HealthHandler {
	return &HealthHandler{
		db:     db,
		logger: log,
	}
}

// HealthCheck provides a basic health check endpoint
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "maigo",
		"version": "dev",
		"message": "Server is healthy and running",
	})
}

// ReadinessCheck provides a readiness check that includes database connectivity
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	// Check database health
	if err := database.Health(h.db); err != nil {
		h.logger.Error("Database health check failed", "error", err)
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"status":   "error",
			"service":  "maigo",
			"database": "unhealthy",
			"error":    err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"service":  "maigo",
		"database": "healthy",
	})
}
