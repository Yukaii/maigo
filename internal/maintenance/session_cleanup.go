// Package maintenance contains background operational jobs for Maigo.
package maintenance

import (
	"context"
	"time"

	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/metrics"
)

const sessionCleanupTimeout = 30 * time.Second

// SessionRepository is the database operation required by the session cleanup
// worker. Keeping this interface small makes scheduler behavior easy to test.
type SessionRepository interface {
	DeleteExpiredSessions(ctx context.Context, cutoff time.Time) (int64, error)
}

// SessionCleanupWorker periodically deletes expired refresh sessions.
type SessionCleanupWorker struct {
	repository SessionRepository
	interval   time.Duration
	logger     *logger.Logger
	metrics    *metrics.Metrics
	now        func() time.Time
}

// NewSessionCleanupWorker creates a refresh-session cleanup worker. A
// nonpositive interval disables the worker.
func NewSessionCleanupWorker(
	repository SessionRepository,
	interval time.Duration,
	log *logger.Logger,
	telemetry *metrics.Metrics,
) *SessionCleanupWorker {
	if telemetry == nil {
		telemetry = metrics.New()
	}

	return &SessionCleanupWorker{
		repository: repository,
		interval:   interval,
		logger:     log,
		metrics:    telemetry,
		now:        time.Now,
	}
}

// Enabled reports whether the worker has a valid schedule.
func (w *SessionCleanupWorker) Enabled() bool {
	return w.interval > 0
}

// Run starts the initial cleanup and then repeats it on the configured
// interval until the context is canceled.
func (w *SessionCleanupWorker) Run(ctx context.Context) {
	if !w.Enabled() {
		return
	}

	w.runOnce(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

func (w *SessionCleanupWorker) runOnce(ctx context.Context) {
	if err := w.RunOnce(ctx); err != nil && ctx.Err() != nil {
		return
	}
}

// RunOnce performs one bounded cleanup attempt and records its outcome.
func (w *SessionCleanupWorker) RunOnce(ctx context.Context) error {
	if !w.Enabled() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.metrics.IncSessionCleanupRuns()
	cleanupCtx, cancel := context.WithTimeout(ctx, sessionCleanupTimeout)
	defer cancel()

	cutoff := w.now().UTC()
	deleted, err := w.repository.DeleteExpiredSessions(cleanupCtx, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			w.metrics.IncSessionCleanupFailures()
			if w.logger != nil {
				w.logger.Error("Expired-session cleanup failed", "cutoff", cutoff, "error", err)
			}
		}
		return err
	}

	w.metrics.AddSessionsDeleted(deleted)
	if deleted > 0 && w.logger != nil {
		w.logger.Info("Expired-session cleanup completed", "deleted", deleted, "cutoff", cutoff)
	}

	return nil
}
