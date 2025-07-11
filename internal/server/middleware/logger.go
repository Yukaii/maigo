package middleware

import (
	"log/slog"

	"github.com/gin-gonic/gin"
	"github.com/yukaii/maigo/internal/logger"
)

// Logger returns a gin.HandlerFunc (middleware) that logs requests using slog.
func Logger(log *logger.Logger) gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log.Info("HTTP request",
			slog.String("method", param.Method),
			slog.String("path", param.Path),
			slog.Int("status", param.StatusCode),
			slog.Duration("latency", param.Latency),
			slog.String("client_ip", param.ClientIP),
			slog.String("user_agent", param.Request.UserAgent()),
			slog.Int("body_size", param.BodySize),
		)
		return ""
	})
}
