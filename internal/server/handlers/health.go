// Package handlers contains HTTP handlers for Maigo server endpoints.
package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
)

// HealthHandler handles health check endpoints
type HealthHandler struct {
	db     *pgxpool.Pool
	redis  *redis.Client
	logger *logger.Logger
}

// NewHealthHandler creates a new health handler
func NewHealthHandler(db *pgxpool.Pool, log *logger.Logger, redisClients ...*redis.Client) *HealthHandler {
	var redisClient *redis.Client
	if len(redisClients) > 0 {
		redisClient = redisClients[0]
	}

	return &HealthHandler{
		db:     db,
		redis:  redisClient,
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

// ReadinessCheck provides a readiness check that includes configured dependency connectivity.
func (h *HealthHandler) ReadinessCheck(c *gin.Context) {
	// Check database health
	if err := database.Health(h.db); err != nil {
		h.logger.Error("Database health check failed", "error", err)
		SendAPIError(c, http.StatusServiceUnavailable, "service_unavailable",
			"Database health check failed", gin.H{
				"service":  "maigo",
				"database": "unhealthy",
			})
		return
	}

	if h.redis != nil {
		redisCtx, cancel := context.WithTimeout(c.Request.Context(), 2*time.Second)
		err := h.redis.Ping(redisCtx).Err()
		cancel()
		if err != nil {
			h.logger.Error("Redis health check failed", "error", err)
			SendAPIError(c, http.StatusServiceUnavailable, "service_unavailable",
				"Redis health check failed", gin.H{
					"service":  "maigo",
					"database": "healthy",
					"redis":    "unhealthy",
				})
			return
		}
	}

	response := gin.H{
		"status":   "ready",
		"service":  "maigo",
		"database": "healthy",
	}
	if h.redis != nil {
		response["redis"] = "healthy"
	}
	c.JSON(http.StatusOK, response)
}
