package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/lib/pq" // PostgreSQL driver for golang-migrate

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
)

func main() {
	fmt.Println("🌱 Seeding database with initial data...")

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Connect to database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	ctx := context.Background()

	// Seed CLI OAuth client
	if err := seedCLIClient(ctx, db); err != nil {
		log.Fatalf("Failed to seed CLI client: %v", err) //nolint:gocritic // database connection will be closed by defer
	}

	// Seed test users (optional for development)
	if err := seedTestUsers(ctx, db); err != nil {
		log.Printf("Warning: Failed to seed test users: %v", err)
	}

	fmt.Println("✅ Database seeding completed successfully!")
}

// seedCLIClient ensures the CLI OAuth client exists in the database
func seedCLIClient(ctx context.Context, db *pgxpool.Pool) error {
	fmt.Println("📱 Seeding CLI OAuth client...")

	query := `
		INSERT INTO oauth_clients (id, secret, name, redirect_uri, created_at) 
		VALUES ($1, $2, $3, $4, NOW()) 
		ON CONFLICT (id) DO UPDATE SET
			secret = EXCLUDED.secret,
			name = EXCLUDED.name,
			redirect_uri = EXCLUDED.redirect_uri,
			created_at = oauth_clients.created_at`

	_, err := db.Exec(ctx, query,
		"maigo-cli",
		"cli-client-secret-not-used-with-pkce",
		"Maigo CLI Application",
		"http://localhost:8000/callback",
	)

	if err != nil {
		return fmt.Errorf("failed to insert CLI client: %w", err)
	}

	fmt.Println("  ✓ CLI OAuth client seeded")
	return nil
}

// seedTestUsers creates test users for development (optional)
func seedTestUsers(ctx context.Context, db *pgxpool.Pool) error {
	fmt.Println("👤 Seeding test users...")

	// Only seed test users if not in production
	if os.Getenv("APP_ENV") == "production" {
		fmt.Println("  ⚠️  Skipping test users in production environment")
		return nil
	}

	testUsers := []struct {
		Username string
		Email    string
		Password string
	}{
		{"testuser", "test@example.com", "password123"},
		{"admin", "admin@example.com", "admin123"},
	}

	query := `
		INSERT INTO users (username, email, password_hash, created_at) 
		VALUES ($1, $2, $3, NOW()) 
		ON CONFLICT (username) DO NOTHING`

	for _, user := range testUsers {
		_, err := db.Exec(ctx, query, user.Username, user.Email, user.Password)
		if err != nil {
			return fmt.Errorf("failed to insert user %s: %w", user.Username, err)
		}
		fmt.Printf("  ✓ Test user '%s' seeded\n", user.Username)
	}

	return nil
}
