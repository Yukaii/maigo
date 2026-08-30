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

type fakeSessionRepository struct {
	deleted int64
	err     error
	cutoff  time.Time
}

func (f *fakeSessionRepository) DeleteExpiredSessions(_ context.Context, cutoff time.Time) (int64, error) {
	f.cutoff = cutoff
	return f.deleted, f.err
}

func TestSessionCleanupWorkerRunOnceRecordsDeletedSessions(t *testing.T) {
	repository := &fakeSessionRepository{deleted: 4}
	telemetry := metrics.New()
	worker := NewSessionCleanupWorker(
		repository,
		time.Hour,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)
	worker.now = func() time.Time { return time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC) }

	require.NoError(t, worker.RunOnce(context.Background()))
	assert.Equal(t, time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC), repository.cutoff)
	rendered := telemetry.RenderPrometheus()
	assert.Contains(t, rendered, "maigo_session_cleanup_runs_total 1")
	assert.Contains(t, rendered, "maigo_sessions_deleted_total 4")
	assert.Contains(t, rendered, "maigo_session_cleanup_failures_total 0")
}

func TestSessionCleanupWorkerRunOnceRecordsFailures(t *testing.T) {
	repository := &fakeSessionRepository{err: errors.New("database unavailable")}
	telemetry := metrics.New()
	worker := NewSessionCleanupWorker(
		repository,
		time.Hour,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)

	err := worker.RunOnce(context.Background())
	require.Error(t, err)
	rendered := telemetry.RenderPrometheus()
	assert.Contains(t, rendered, "maigo_session_cleanup_runs_total 1")
	assert.Contains(t, rendered, "maigo_session_cleanup_failures_total 1")
}

func TestSessionCleanupWorkerCanBeDisabled(t *testing.T) {
	repository := &fakeSessionRepository{deleted: 3}
	telemetry := metrics.New()
	worker := NewSessionCleanupWorker(
		repository,
		0,
		logger.NewLogger(logger.Config{Level: "error", Format: "text"}),
		telemetry,
	)

	assert.False(t, worker.Enabled())
	require.NoError(t, worker.RunOnce(context.Background()))
	assert.Empty(t, repository.cutoff)
	assert.Contains(t, telemetry.RenderPrometheus(), "maigo_session_cleanup_runs_total 0")
}
