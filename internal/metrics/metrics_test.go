package metrics

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRenderPrometheusIncludesAtomicCounters(t *testing.T) {
	telemetry := New()
	telemetry.IncRedirects()
	telemetry.IncClickEventsRecorded()
	telemetry.IncClickEventRecordFailures()
	telemetry.IncClickRetentionRuns()
	telemetry.IncClickRetentionFailures()
	telemetry.AddClickEventsDeleted(4)
	telemetry.IncSessionCleanupRuns()
	telemetry.IncSessionCleanupFailures()
	telemetry.AddSessionsDeleted(3)
	telemetry.AddClickEventsDeleted(-1)
	telemetry.AddSessionsDeleted(-1)

	rendered := telemetry.RenderPrometheus()
	for _, expected := range []string{
		"# TYPE maigo_redirects_total counter",
		"maigo_redirects_total 1",
		"maigo_click_events_recorded_total 1",
		"maigo_click_event_record_failures_total 1",
		"maigo_click_retention_runs_total 1",
		"maigo_click_retention_failures_total 1",
		"maigo_click_events_deleted_total 4",
		"maigo_session_cleanup_runs_total 1",
		"maigo_session_cleanup_failures_total 1",
		"maigo_sessions_deleted_total 3",
	} {
		assert.Contains(t, rendered, expected)
	}
	assert.True(t, strings.HasSuffix(rendered, "\n"))
}
