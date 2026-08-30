// Package database manages Maigo Core's embedded SQLite database.
package database

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/yukaii/maigo/internal/config"
)

const schema = `
CREATE TABLE IF NOT EXISTS urls (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    short_code TEXT NOT NULL UNIQUE,
    target_url TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    hits INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_urls_created_at ON urls (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_urls_expires_at ON urls (expires_at);
`

const memoryPath = ":memory:"

// Connect opens the configured SQLite database and initializes its schema.
func Connect(cfg *config.Config) (*sql.DB, error) {
	return NewConnection(cfg.Database.Path)
}

// NewConnection opens a SQLite database at path. Use :memory: for isolated
// tests; regular deployments should place the file on a persistent volume.
func NewConnection(path string) (*sql.DB, error) {
	if path == "" {
		return nil, fmt.Errorf("database path is required")
	}
	if path != memoryPath {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, fmt.Errorf("failed to create database directory: %w", err)
		}
	}

	dsn := path
	if path == memoryPath {
		dsn = "file:maigo-memory?mode=memory&cache=shared"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open SQLite database: %w", err)
	}

	// A single writer connection avoids lock contention for this intentionally
	// small self-hosted service while WAL still lets readers proceed safely.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to ping SQLite database: %w (close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("failed to ping SQLite database: %w", err)
	}
	if path != memoryPath {
		if _, err := db.ExecContext(ctx, "PRAGMA journal_mode = WAL"); err != nil {
			if closeErr := db.Close(); closeErr != nil {
				return nil, fmt.Errorf("failed to enable SQLite WAL mode: %w (close: %v)", err, closeErr)
			}
			return nil, fmt.Errorf("failed to enable SQLite WAL mode: %w", err)
		}
	}
	if _, err := db.ExecContext(ctx, "PRAGMA busy_timeout = 5000"); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("failed to set SQLite busy timeout: %w (close: %v)", err, closeErr)
		}
		return nil, fmt.Errorf("failed to set SQLite busy timeout: %w", err)
	}
	if err := InitializeSchema(ctx, db); err != nil {
		if closeErr := db.Close(); closeErr != nil {
			return nil, fmt.Errorf("%w (close: %v)", err, closeErr)
		}
		return nil, err
	}

	return db, nil
}

// InitializeSchema creates the current idempotent Core schema. Core intentionally
// has one schema bootstrap instead of a migration tool and a migration table.
func InitializeSchema(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, schema); err != nil {
		return fmt.Errorf("failed to initialize SQLite schema: %w", err)
	}
	return nil
}

// Health checks the database connection.
func Health(db *sql.DB) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		return fmt.Errorf("database health check failed: %w", err)
	}
	return nil
}
