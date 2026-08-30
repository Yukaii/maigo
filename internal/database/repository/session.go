// Package repository contains PostgreSQL persistence operations.
package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const sessionDeleteBatchSize int64 = 1000

// SessionRepository provides operations for refresh-session maintenance.
type SessionRepository struct {
	db *pgxpool.Pool
}

// NewSessionRepository creates a repository for refresh-session operations.
func NewSessionRepository(db *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{db: db}
}

// DeleteExpiredSessions removes expired refresh sessions in bounded batches.
// The cutoff is supplied by the caller to make scheduling and tests
// deterministic.
func (r *SessionRepository) DeleteExpiredSessions(ctx context.Context, cutoff time.Time) (int64, error) {
	const query = `
		DELETE FROM sessions
		WHERE id IN (
			SELECT id
			FROM sessions
			WHERE expires_at <= $1
			ORDER BY expires_at, id
			LIMIT $2
		)`

	var deletedTotal int64
	for {
		result, err := r.db.Exec(ctx, query, cutoff, sessionDeleteBatchSize)
		if err != nil {
			return deletedTotal, fmt.Errorf("failed to delete expired sessions: %w", err)
		}

		deleted := result.RowsAffected()
		deletedTotal += deleted
		if deleted < sessionDeleteBatchSize {
			return deletedTotal, nil
		}
	}
}
