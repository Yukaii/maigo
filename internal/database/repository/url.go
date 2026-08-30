// Package repository provides database repositories for Maigo.
package repository

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/yukaii/maigo/internal/database/models"
)

// URLRepository handles URL database operations
type URLRepository struct {
	db *pgxpool.Pool
}

// NewURLRepository creates a new URL repository
func NewURLRepository(db *pgxpool.Pool) *URLRepository {
	return &URLRepository{db: db}
}

// Create creates a new short URL
func (r *URLRepository) Create(
	ctx context.Context,
	shortCode, targetURL string,
	userID *int64,
	expiresAt *time.Time,
) (*models.URL, error) {
	url := &models.URL{
		ShortCode: shortCode,
		TargetURL: targetURL,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Hits:      0,
		CreatedAt: time.Now(),
	}

	query := `
		INSERT INTO urls (short_code, target_url, user_id, hits, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id`

	err := r.db.QueryRow(ctx, query,
		url.ShortCode, url.TargetURL, url.UserID, url.Hits, url.CreatedAt, url.ExpiresAt,
	).Scan(&url.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to create URL: %w", err)
	}

	return url, nil
}

// getByField retrieves a URL by a given field and value
func (r *URLRepository) getByField(ctx context.Context, field string, value any) (*models.URL, error) {
	url := &models.URL{}
	query := `SELECT id, short_code, target_url, created_at, expires_at, hits, user_id FROM urls WHERE ` + field + ` = $1`
	err := r.db.QueryRow(ctx, query, value).Scan(
		&url.ID,
		&url.ShortCode,
		&url.TargetURL,
		&url.CreatedAt,
		&url.ExpiresAt,
		&url.Hits,
		&url.UserID,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("URL not found")
		}
		return nil, fmt.Errorf("failed to get URL: %w", err)
	}
	return url, nil
}

// GetByID retrieves a URL by ID
func (r *URLRepository) GetByID(ctx context.Context, id int64) (*models.URL, error) {
	return r.getByField(ctx, "id", id)
}

// GetByShortCode retrieves a URL by short code
func (r *URLRepository) GetByShortCode(ctx context.Context, shortCode string) (*models.URL, error) {
	return r.getByField(ctx, "short_code", shortCode)
}

// GetByUserID retrieves URLs for a specific user with pagination
func (r *URLRepository) GetByUserID(
	ctx context.Context,
	userID int64,
	page int,
	pageSize int,
) ([]models.URL, int64, error) {
	// Get total count for the user
	var total int64
	countQuery := `SELECT COUNT(*) FROM urls WHERE user_id = $1`
	err := r.db.QueryRow(ctx, countQuery, userID).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count user URLs: %w", err)
	}

	// Get URLs with pagination
	offset := (page - 1) * pageSize
	query := `
		SELECT id, short_code, target_url, created_at, expires_at, hits, user_id
		FROM urls
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2 OFFSET $3`

	rows, err := r.db.Query(ctx, query, userID, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list user URLs: %w", err)
	}
	defer rows.Close()

	var urls []models.URL
	for rows.Next() {
		var url models.URL
		err := rows.Scan(
			&url.ID,
			&url.ShortCode,
			&url.TargetURL,
			&url.CreatedAt,
			&url.ExpiresAt,
			&url.Hits,
			&url.UserID,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan URL: %w", err)
		}
		urls = append(urls, url)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating URLs: %w", err)
	}

	return urls, total, nil
}

// Update updates URL information
func (r *URLRepository) Update(ctx context.Context, id int64, updates map[string]any) (*models.URL, error) {
	if len(updates) == 0 {
		return r.GetByID(ctx, id)
	}

	// Build dynamic query
	setParts := make([]string, 0, len(updates))
	args := make([]any, 0, len(updates)+1)
	argIndex := 1

	for field, value := range updates {
		if field == "target_url" {
			setParts = append(setParts, fmt.Sprintf("%s = $%d", field, argIndex))
			args = append(args, value)
			argIndex++
		}
	}

	if len(setParts) == 0 {
		return r.GetByID(ctx, id)
	}

	args = append(args, id)
	query := fmt.Sprintf(`
		UPDATE urls
		SET %s
		WHERE id = $%d`,
		strings.Join(setParts, ", "), argIndex)

	_, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to update URL: %w", err)
	}

	return r.GetByID(ctx, id)
}

// Delete deletes a URL
func (r *URLRepository) Delete(ctx context.Context, id int64) error {
	query := `DELETE FROM urls WHERE id = $1`

	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete URL: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("URL not found")
	}

	return nil
}

// DeleteByUserAndID deletes a URL owned by a specific user
func (r *URLRepository) DeleteByUserAndID(ctx context.Context, userID, urlID int64) error {
	query := `DELETE FROM urls WHERE id = $1 AND user_id = $2`

	result, err := r.db.Exec(ctx, query, urlID, userID)
	if err != nil {
		return fmt.Errorf("failed to delete URL: %w", err)
	}

	if result.RowsAffected() == 0 {
		return fmt.Errorf("URL not found or not owned by user")
	}

	return nil
}

// RecordClick stores a click event and updates the URL aggregate atomically.
func (r *URLRepository) RecordClick(ctx context.Context, urlID int64) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("failed to begin click transaction: %w", err)
	}
	rollback := true
	defer func() {
		if rollback {
			if rollbackErr := tx.Rollback(ctx); rollbackErr != nil {
				slog.Debug("Failed to rollback click transaction", "error", rollbackErr)
			}
		}
	}()

	if _, execErr := tx.Exec(ctx,
		`INSERT INTO click_events (url_id) VALUES ($1)`, urlID,
	); execErr != nil {
		return fmt.Errorf("failed to record click event: %w", execErr)
	}

	result, err := tx.Exec(ctx,
		`UPDATE urls SET hits = hits + 1 WHERE id = $1`, urlID,
	)
	if err != nil {
		return fmt.Errorf("failed to update URL hit count: %w", err)
	}
	if result.RowsAffected() != 1 {
		return fmt.Errorf("URL not found")
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("failed to commit click transaction: %w", err)
	}
	rollback = false

	return nil
}

// GetClickTimeline returns click counts grouped by UTC calendar day.
func (r *URLRepository) GetClickTimeline(
	ctx context.Context,
	urlID int64,
) ([]models.ClickTimelinePoint, error) {
	query := `
		SELECT date_trunc('day', clicked_at AT TIME ZONE 'UTC') AS date,
		       COUNT(*)::bigint AS hits
		FROM click_events
		WHERE url_id = $1
		GROUP BY 1
		ORDER BY 1`

	rows, err := r.db.Query(ctx, query, urlID)
	if err != nil {
		return nil, fmt.Errorf("failed to query click timeline: %w", err)
	}
	defer rows.Close()

	var timeline []models.ClickTimelinePoint
	for rows.Next() {
		var point models.ClickTimelinePoint
		if err := rows.Scan(&point.Date, &point.Hits); err != nil {
			return nil, fmt.Errorf("failed to scan click timeline: %w", err)
		}
		timeline = append(timeline, point)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating click timeline: %w", err)
	}

	return timeline, nil
}

// List retrieves URLs with pagination
func (r *URLRepository) List(ctx context.Context, page, pageSize int) ([]models.URL, int64, error) {
	// Get total count
	var total int64
	countQuery := `SELECT COUNT(*) FROM urls`
	err := r.db.QueryRow(ctx, countQuery).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count URLs: %w", err)
	}

	// Get URLs with pagination
	offset := (page - 1) * pageSize
	query := `
		SELECT id, short_code, target_url, created_at, expires_at, hits, user_id
		FROM urls
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`

	rows, err := r.db.Query(ctx, query, pageSize, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to list URLs: %w", err)
	}
	defer rows.Close()

	var urls []models.URL
	for rows.Next() {
		var url models.URL
		err := rows.Scan(
			&url.ID,
			&url.ShortCode,
			&url.TargetURL,
			&url.CreatedAt,
			&url.ExpiresAt,
			&url.Hits,
			&url.UserID,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to scan URL: %w", err)
		}
		urls = append(urls, url)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("error iterating URLs: %w", err)
	}

	return urls, total, nil
}

// ShortCodeExists checks if a short code already exists
func (r *URLRepository) ShortCodeExists(ctx context.Context, shortCode string) (bool, error) {
	var count int
	query := `SELECT COUNT(*) FROM urls WHERE short_code = $1`

	err := r.db.QueryRow(ctx, query, shortCode).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check short code existence: %w", err)
	}

	return count > 0, nil
}

// GetTopURLs retrieves most popular URLs
func (r *URLRepository) GetTopURLs(ctx context.Context, limit int) ([]models.URL, error) {
	query := `
		SELECT id, short_code, target_url, created_at, expires_at, hits, user_id
		FROM urls
		ORDER BY hits DESC
		LIMIT $1`

	rows, err := r.db.Query(ctx, query, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to get top URLs: %w", err)
	}
	defer rows.Close()

	var urls []models.URL
	for rows.Next() {
		var url models.URL
		err := rows.Scan(
			&url.ID,
			&url.ShortCode,
			&url.TargetURL,
			&url.CreatedAt,
			&url.ExpiresAt,
			&url.Hits,
			&url.UserID,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan URL: %w", err)
		}
		urls = append(urls, url)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating URLs: %w", err)
	}

	return urls, nil
}
