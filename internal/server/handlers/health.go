// Package handlers contains HTTP handlers for Maigo Core endpoints.
package handlers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
)

// HealthHandler handles health check endpoints.
type HealthHandler struct {
	db     *sql.DB
	logger *logger.Logger
}

// NewHealthHandler creates a health handler for the SQLite database.
func NewHealthHandler(db *sql.DB, log *logger.Logger) *HealthHandler {
	return &HealthHandler{db: db, logger: log}
}

// HealthCheck provides a basic process health check.
func (h *HealthHandler) HealthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"service": "maigo",
	})
}

// ReadinessCheck verifies that the SQLite database is reachable.
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	if err := database.Health(h.db); err != nil {
		if h.logger != nil {
			h.logger.Error("Database health check failed", "error", err)
		}
		SendAPIError(c, http.StatusServiceUnavailable, "service_unavailable",
			"Database health check failed", gin.H{"database": "unhealthy"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":   "ready",
		"service":  "maigo",
		"database": "healthy",
	})
}
