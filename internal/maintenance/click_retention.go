// Package maintenance contains background operational jobs for Maigo.
package maintenance

import (
	"context"
	"time"

	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/metrics"
)

const clickRetentionCleanupTimeout = 30 * time.Second

// ClickEventRepository is the database operation required by the retention
// worker. Keeping this small makes the scheduling and failure behavior easy to
// test without a live database.
type ClickEventRepository interface {
	DeleteClickEventsBefore(ctx context.Context, cutoff time.Time) (int64, error)
}

// ClickRetentionWorker periodically deletes click events older than the
// configured retention period.
type ClickRetentionWorker struct {
	repository ClickEventRepository
	retention  time.Duration
	interval   time.Duration
	logger     *logger.Logger
	metrics    *metrics.Metrics
	now        func() time.Time
}

// NewClickRetentionWorker creates a click-event retention worker. A nonpositive
// retention period disables the worker.
func NewClickRetentionWorker(
	repository ClickEventRepository,
	retention time.Duration,
	interval time.Duration,
	log *logger.Logger,
	telemetry *metrics.Metrics,
) *ClickRetentionWorker {
	if telemetry == nil {
		telemetry = metrics.New()
	}

	return &ClickRetentionWorker{
		repository: repository,
		retention:  retention,
		interval:   interval,
		logger:     log,
		metrics:    telemetry,
		now:        time.Now,
	}
}

// Enabled reports whether the worker has a valid schedule.
func (w *ClickRetentionWorker) Enabled() bool {
	return w.retention > 0 && w.interval > 0
}

// Run starts the initial cleanup and then repeats it on the configured
// interval until the context is canceled.
func (w *ClickRetentionWorker) Run(ctx context.Context) {
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

func (w *ClickRetentionWorker) runOnce(ctx context.Context) {
	if err := w.RunOnce(ctx); err != nil && ctx.Err() != nil {
		return
	}
}

// RunOnce performs one bounded cleanup attempt and records its outcome.
func (w *ClickRetentionWorker) RunOnce(ctx context.Context) error {
	if !w.Enabled() {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	w.metrics.IncClickRetentionRuns()
	cleanupCtx, cancel := context.WithTimeout(ctx, clickRetentionCleanupTimeout)
	defer cancel()

	cutoff := w.now().UTC().Add(-w.retention)
	deleted, err := w.repository.DeleteClickEventsBefore(cleanupCtx, cutoff)
	if err != nil {
		if ctx.Err() == nil {
			w.metrics.IncClickRetentionFailures()
			w.logger.Error("Click-event retention cleanup failed", "cutoff", cutoff, "error", err)
		}
		return err
	}

	w.metrics.AddClickEventsDeleted(deleted)
	if deleted > 0 {
		w.logger.Info("Click-event retention cleanup completed", "deleted", deleted, "cutoff", cutoff)
	}

	return nil
}
