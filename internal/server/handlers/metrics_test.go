package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/metrics"
)

func TestMetricsHandlerServesPrometheusCounters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	telemetry := metrics.New()
	telemetry.IncClickEventRecordFailures()

	router := gin.New()
	router.GET("/metrics", NewMetricsHandler(telemetry).ServeMetrics)
	request := httptest.NewRequest(http.MethodGet, "/metrics", http.NoBody)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "text/plain; version=0.0.4; charset=utf-8", response.Header().Get("Content-Type"))
	assert.Contains(t, response.Body.String(), "maigo_click_event_record_failures_total 1")
}
