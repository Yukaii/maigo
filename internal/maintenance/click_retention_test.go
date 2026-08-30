package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/metrics"
)

type fakeClickEventRepository struct {
	deleted int64
	err     error
	cutoff  time.Time
}

func (f *fakeClickEventRepository) DeleteClickEventsBefore(_ context.Context, cutoff time.Time) (int64, error) {
	f.cutoff = cutoff
	return f.deleted, f.err
}

func TestClickRetentionWorkerRunOnceRecordsDeletedEvents(t *testing.T) {
	repository := &fakeClickEventRepository{deleted: 7}
	telemetry := metrics.New()
	worker := NewClickRetentionWorker(
		repository,
		24*time.Hour,
		time.Hour,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)
	worker.now = func() time.Time { return time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC) }

	require.NoError(t, worker.RunOnce(context.Background()))
	assert.Equal(t, time.Date(2026, time.August, 29, 12, 0, 0, 0, time.UTC), repository.cutoff)
	rendered := telemetry.RenderPrometheus()
	assert.Contains(t, rendered, "maigo_click_retention_runs_total 1")
	assert.Contains(t, rendered, "maigo_click_events_deleted_total 7")
	assert.Contains(t, rendered, "maigo_click_retention_failures_total 0")
}

func TestClickRetentionWorkerRunOnceRecordsFailures(t *testing.T) {
	repository := &fakeClickEventRepository{err: errors.New("database unavailable")}
	telemetry := metrics.New()
	worker := NewClickRetentionWorker(
		repository,
		24*time.Hour,
		time.Hour,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)

	err := worker.RunOnce(context.Background())
	require.Error(t, err)
	rendered := telemetry.RenderPrometheus()
	assert.Contains(t, rendered, "maigo_click_retention_runs_total 1")
	assert.Contains(t, rendered, "maigo_click_retention_failures_total 1")
}

func TestClickRetentionWorkerCanBeDisabled(t *testing.T) {
	repository := &fakeClickEventRepository{deleted: 3}
	telemetry := metrics.New()
	worker := NewClickRetentionWorker(
		repository,
		0,
		time.Hour,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)

	assert.False(t, worker.Enabled())
	require.NoError(t, worker.RunOnce(context.Background()))
	assert.Empty(t, repository.cutoff)
	assert.Contains(t, telemetry.RenderPrometheus(), "maigo_click_retention_runs_total 0")
}
