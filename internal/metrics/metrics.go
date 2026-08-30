// Package metrics provides process-local operational counters for Maigo.
package metrics

import (
	"fmt"
	"sync/atomic"
)

// Metrics contains counters that are safe to update from concurrent requests
// and background workers.
type Metrics struct {
	redirectsTotal                atomic.Uint64
	clickEventsRecordedTotal      atomic.Uint64
	clickEventRecordFailuresTotal atomic.Uint64
	clickRetentionRunsTotal       atomic.Uint64
	clickRetentionFailuresTotal   atomic.Uint64
	clickEventsDeletedTotal       atomic.Uint64
}

// New creates an empty metrics registry.
func New() *Metrics {
	return &Metrics{}
}

// IncRedirects increments the number of non-expired redirect attempts.
func (m *Metrics) IncRedirects() {
	m.redirectsTotal.Add(1)
}

// IncClickEventsRecorded increments the number of click events committed.
func (m *Metrics) IncClickEventsRecorded() {
	m.clickEventsRecordedTotal.Add(1)
}

// IncClickEventRecordFailures increments failed click-event writes.
func (m *Metrics) IncClickEventRecordFailures() {
	m.clickEventRecordFailuresTotal.Add(1)
}

// IncClickRetentionRuns increments cleanup attempts.
func (m *Metrics) IncClickRetentionRuns() {
	m.clickRetentionRunsTotal.Add(1)
}

// IncClickRetentionFailures increments failed cleanup attempts.
func (m *Metrics) IncClickRetentionFailures() {
	m.clickRetentionFailuresTotal.Add(1)
}

// AddClickEventsDeleted records events removed by retention cleanup.
func (m *Metrics) AddClickEventsDeleted(count int64) {
	if count > 0 {
		m.clickEventsDeletedTotal.Add(uint64(count))
	}
}

// RenderPrometheus renders counters in the Prometheus text exposition format.
func (m *Metrics) RenderPrometheus() string {
	return fmt.Sprintf(`# HELP maigo_redirects_total Non-expired redirect attempts.
# TYPE maigo_redirects_total counter
maigo_redirects_total %d
# HELP maigo_click_events_recorded_total Click events committed successfully.
# TYPE maigo_click_events_recorded_total counter
maigo_click_events_recorded_total %d
# HELP maigo_click_event_record_failures_total Click-event persistence failures.
# TYPE maigo_click_event_record_failures_total counter
maigo_click_event_record_failures_total %d
# HELP maigo_click_retention_runs_total Click-event retention cleanup attempts.
# TYPE maigo_click_retention_runs_total counter
maigo_click_retention_runs_total %d
# HELP maigo_click_retention_failures_total Click-event retention cleanup failures.
# TYPE maigo_click_retention_failures_total counter
maigo_click_retention_failures_total %d
# HELP maigo_click_events_deleted_total Click events deleted by retention cleanup.
# TYPE maigo_click_events_deleted_total counter
maigo_click_events_deleted_total %d
`,
		m.redirectsTotal.Load(),
		m.clickEventsRecordedTotal.Load(),
		m.clickEventRecordFailuresTotal.Load(),
		m.clickRetentionRunsTotal.Load(),
		m.clickRetentionFailuresTotal.Load(),
		m.clickEventsDeletedTotal.Load(),
	)
}
