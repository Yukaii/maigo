// Package database manages database connections and migrations for Maigo.
package database

import (
	"context"
	"embed"
	"fmt"
	"log/slog"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	_ "github.com/lib/pq" // PostgreSQL driver for golang-migrate

	"github.com/yukaii/maigo/internal/config"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

// Connect creates a new database connection using config
func Connect(cfg *config.Config) (*pgxpool.Pool, error) {
	return NewConnection(cfg.DatabaseURL())
}

// NewConnection creates a new database connection pool
func NewConnection(databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse database URL: %w", err)
	}

	// Configure connection pool for optimal performance
	// MaxConns: Maximum number of connections in the pool
	// For a typical web application: (core_count * 2) + effective_spindle_count
	config.MaxConns = 25

	// MinConns: Minimum number of connections to maintain
	// Keeps connections warm for faster response times
	config.MinConns = 5

	// MaxConnLifetime: Maximum lifetime of a connection
	// Helps with load balancer connection rotation and prevents stale connections
	config.MaxConnLifetime = time.Hour

	// MaxConnIdleTime: Maximum time a connection can be idle
	// Closes idle connections to reduce resource usage
	config.MaxConnIdleTime = time.Minute * 30

	// HealthCheckPeriod: How often to check connection health
	// Detects and removes broken connections from the pool
	config.HealthCheckPeriod = time.Minute

	// ConnectTimeout: Maximum time to wait for a new connection
	config.ConnConfig.ConnectTimeout = 10 * time.Second

	// Create connection pool
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	// Test the connection
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	slog.Info("Database connection pool initialized",
		"max_conns", config.MaxConns,
		"min_conns", config.MinConns,
		"max_lifetime", config.MaxConnLifetime,
		"max_idle_time", config.MaxConnIdleTime,
	)

	return pool, nil
}

// RunMigrations runs database migrations
func RunMigrations(pool *pgxpool.Pool) error {
	// Get a single connection for migrations
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		return fmt.Errorf("failed to acquire connection: %w", err)
	}
	defer conn.Release()

	// Convert pgx connection to sql.DB for migrate
	db := stdlib.OpenDBFromPool(pool)
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			// Log error but don't fail the migration process
			fmt.Printf("Warning: failed to close database connection: %v\n", closeErr)
		}
	}()

	// Create postgres driver instance
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("failed to create postgres driver: %w", err)
	}

	// Create migration source from embedded files
	source, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	// Create migrate instance
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	// Ensure migrate instance is properly closed
	defer func() {
		if sourceErr, dbErr := m.Close(); sourceErr != nil || dbErr != nil {
			fmt.Printf("Warning: failed to close migrate instance (source: %v, db: %v)\n", sourceErr, dbErr)
		}
	}()

	// Run migrations
	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	slog.Info("Database migrations completed successfully")
	return nil
}

// GetDB returns a database connection from the pool
func GetDB(pool *pgxpool.Pool) *pgxpool.Conn {
	conn, err := pool.Acquire(context.Background())
	if err != nil {
		slog.Error("Failed to acquire database connection", "error", err)
		return nil
	}
	return conn
}

// Health checks the database health
func Health(pool *pgxpool.Pool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}

	return nil
}
