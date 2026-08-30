package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/yukaii/maigo/internal/metrics"
)

// MetricsHandler serves process-local operational counters for scraping.
type MetricsHandler struct {
	metrics *metrics.Metrics
}

// NewMetricsHandler creates a metrics endpoint handler.
func NewMetricsHandler(telemetry *metrics.Metrics) *MetricsHandler {
	if telemetry == nil {
		telemetry = metrics.New()
	}

	return &MetricsHandler{metrics: telemetry}
}

// ServeMetrics returns counters in Prometheus text exposition format.
func (h *MetricsHandler) ServeMetrics(c *gin.Context) {
	c.Data(http.StatusOK, "text/plain; version=0.0.4; charset=utf-8", []byte(h.metrics.RenderPrometheus()))
}
