// Package repository contains SQLite persistence operations.
package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/yukaii/maigo/internal/database/models"
)

// ErrNotFound identifies a missing short link.
var ErrNotFound = errors.New("URL not found")

// URLRepository handles Core URL operations.
type URLRepository struct {
	db *sql.DB
}

// NewURLRepository creates a URL repository.
func NewURLRepository(db *sql.DB) *URLRepository {
	return &URLRepository{db: db}
}

// Create persists a short link.
func (r *URLRepository) Create(
	ctx context.Context,
	shortCode, targetURL string,
	expiresAt *time.Time,
) (*models.URL, error) {
	createdAt := time.Now().UTC()
	var expiresValue any
	if expiresAt != nil {
		expiresValue = formatTime(*expiresAt)
	}

	result, err := r.db.ExecContext(ctx, `
		INSERT INTO urls (short_code, target_url, created_at, expires_at)
		VALUES (?, ?, ?, ?)`,
		shortCode, targetURL, formatTime(createdAt), expiresValue)
	if err != nil {
		return nil, fmt.Errorf("failed to create URL: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to read created URL ID: %w", err)
	}

	return &models.URL{
		ID:        id,
		ShortCode: shortCode,
		TargetURL: targetURL,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	}, nil
}

// GetByID retrieves a link by its numeric ID.
func (r *URLRepository) GetByID(ctx context.Context, id int64) (*models.URL, error) {
	return r.get(ctx, `WHERE id = ?`, id)
}

// GetByShortCode retrieves a link by its public code.
func (r *URLRepository) GetByShortCode(ctx context.Context, shortCode string) (*models.URL, error) {
	return r.get(ctx, `WHERE short_code = ?`, shortCode)
}

func (r *URLRepository) get(ctx context.Context, predicate string, arg any) (*models.URL, error) {
	var (
		url       models.URL
		createdAt string
		expiresAt sql.NullString
	)
	err := r.db.QueryRowContext(ctx, `
		SELECT id, short_code, target_url, created_at, expires_at, hits
		FROM urls `+predicate, arg).Scan(
		&url.ID,
		&url.ShortCode,
		&url.TargetURL,
		&createdAt,
		&expiresAt,
		&url.Hits,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get URL: %w", err)
	}

	url.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL creation time: %w", err)
	}
	if expiresAt.Valid && expiresAt.String != "" {
		parsed, parseErr := parseTime(expiresAt.String)
		if parseErr != nil {
			return nil, fmt.Errorf("failed to parse URL expiration time: %w", parseErr)
		}
		url.ExpiresAt = &parsed
	}

	return &url, nil
}

// List retrieves all links with simple pagination.
func (r *URLRepository) List(ctx context.Context, page, pageSize int) (urls []models.URL, total int64, err error) {
	if countErr := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM urls`).Scan(&total); countErr != nil {
		return nil, 0, fmt.Errorf("failed to count URLs: %w", countErr)
	}

	offset := (page - 1) * pageSize
	rows, queryErr := r.db.QueryContext(ctx, `
		SELECT id, short_code, target_url, created_at, expires_at, hits
		FROM urls
		ORDER BY created_at DESC, id DESC
		LIMIT ? OFFSET ?`, pageSize, offset)
	if queryErr != nil {
		return nil, 0, fmt.Errorf("failed to list URLs: %w", queryErr)
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil && err == nil {
			err = fmt.Errorf("failed to close URL rows: %w", closeErr)
		}
	}()

	urls = make([]models.URL, 0, pageSize)
	for rows.Next() {
		var (
			url       models.URL
			createdAt string
			expiresAt sql.NullString
		)
		if scanErr := rows.Scan(
			&url.ID,
			&url.ShortCode,
			&url.TargetURL,
			&createdAt,
			&expiresAt,
			&url.Hits,
		); scanErr != nil {
			return nil, 0, fmt.Errorf("failed to scan URL: %w", scanErr)
		}
		createdAtTime, parseErr := parseTime(createdAt)
		if parseErr != nil {
			return nil, 0, fmt.Errorf("failed to parse URL creation time: %w", parseErr)
		}
		url.CreatedAt = createdAtTime
		if expiresAt.Valid && expiresAt.String != "" {
			parsed, parseErr := parseTime(expiresAt.String)
			if parseErr != nil {
				return nil, 0, fmt.Errorf("failed to parse URL expiration time: %w", parseErr)
			}
			url.ExpiresAt = &parsed
		}
		urls = append(urls, url)
	}
	if rowsErr := rows.Err(); rowsErr != nil {
		return nil, 0, fmt.Errorf("failed to iterate URLs: %w", rowsErr)
	}

	return urls, total, nil
}

// Delete removes a link by its numeric ID.
func (r *URLRepository) Delete(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, `DELETE FROM urls WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to delete URL: %w", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
		return fmt.Errorf("failed to inspect deleted URL: %w", affectedErr)
	} else if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// RecordClick atomically increments the lifetime hit count.
func (r *URLRepository) RecordClick(ctx context.Context, id int64) error {
	result, err := r.db.ExecContext(ctx, `UPDATE urls SET hits = hits + 1 WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("failed to record URL click: %w", err)
	}
	if affected, affectedErr := result.RowsAffected(); affectedErr != nil {
		return fmt.Errorf("failed to inspect URL click: %w", affectedErr)
	} else if affected != 1 {
		return ErrNotFound
	}
	return nil
}

// ShortCodeExists checks whether a code is already assigned.
func (r *URLRepository) ShortCodeExists(ctx context.Context, shortCode string) (bool, error) {
	var exists bool
	if err := r.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM urls WHERE short_code = ?)`, shortCode).Scan(&exists); err != nil {
		return false, fmt.Errorf("failed to check short code existence: %w", err)
	}
	return exists, nil
}

// IsConflict reports whether an insert failed because its short code is used.
func IsConflict(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed: urls.short_code")
}

func formatTime(value time.Time) string {
	return value.UTC().Format(time.RFC3339Nano)
}

func parseTime(value string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, value)
}
