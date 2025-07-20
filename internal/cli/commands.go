// Package cli implements the Maigo command-line interface.
package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/database/models"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
	"github.com/yukaii/maigo/internal/server"
)

// NewServerCommand creates the server command
func NewServerCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the HTTP server",
		Long:  "Start the HTTP server for the Maigo URL shortener",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Override config with command-line flags if provided
			if err := overrideConfigFromFlags(cmd, cfg); err != nil {
				return fmt.Errorf("failed to override config from flags: %w", err)
			}
			return runServer(cfg, log)
		},
	}

	// Add database configuration flags (12-factor app style)
	cmd.Flags().String("database-url", "", "Database connection URL (overrides individual DB flags)")
	cmd.Flags().String("db-host", "", "Database host")
	cmd.Flags().Int("db-port", 0, "Database port")
	cmd.Flags().String("db-name", "", "Database name")
	cmd.Flags().String("db-user", "", "Database user")
	cmd.Flags().String("db-password", "", "Database password")
	cmd.Flags().String("db-ssl-mode", "", "Database SSL mode (disable, require, etc.)")

	// Add server configuration flags
	cmd.Flags().IntP("port", "p", 0, "HTTP server port")
	cmd.Flags().String("host", "", "HTTP server host")

	return cmd
}

// overrideConfigFromFlags overrides configuration values with command-line flags
func overrideConfigFromFlags(cmd *cobra.Command, cfg *config.Config) error {
	// Database configuration overrides
	if databaseURL, err := cmd.Flags().GetString("database-url"); err == nil && databaseURL != "" {
		cfg.Database.URL = databaseURL
	}
	if dbHost, err := cmd.Flags().GetString("db-host"); err == nil && dbHost != "" {
		cfg.Database.Host = dbHost
	}
	if dbPort, err := cmd.Flags().GetInt("db-port"); err == nil && cmd.Flags().Changed("db-port") {
		cfg.Database.Port = dbPort
	}
	if dbName, err := cmd.Flags().GetString("db-name"); err == nil && dbName != "" {
		cfg.Database.Name = dbName
	}
	if dbUser, err := cmd.Flags().GetString("db-user"); err == nil && dbUser != "" {
		cfg.Database.User = dbUser
	}
	if dbPassword, err := cmd.Flags().GetString("db-password"); err == nil && dbPassword != "" {
		cfg.Database.Password = dbPassword
	}
	if dbSSLMode, err := cmd.Flags().GetString("db-ssl-mode"); err == nil && dbSSLMode != "" {
		cfg.Database.SSLMode = dbSSLMode
	}

	// Server configuration overrides
	if port, err := cmd.Flags().GetInt("port"); err == nil && cmd.Flags().Changed("port") {
		cfg.Server.Port = port
	}
	if host, err := cmd.Flags().GetString("host"); err == nil && host != "" {
		cfg.Server.Host = host
	}

	// Re-parse DATABASE_URL if it was set via flag
	if err := cfg.ParseDatabaseURL(); err != nil {
		return fmt.Errorf("failed to parse DATABASE_URL from flag: %w", err)
	}

	return nil
}

// NewAuthCommand creates the auth command
func NewAuthCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Authentication operations",
		Long:  "Manage authentication and OAuth2 operations",
	}

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:   "login [username]",
			Short: "Login to get access token",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runLogin(cfg, log, args[0])
			},
		},
		&cobra.Command{
			Use:   "register [username] [email]",
			Short: "Register a new account",
			Args:  cobra.ExactArgs(2),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runRegister(cfg, log, args[0], args[1])
			},
		},
		&cobra.Command{
			Use:   "logout",
			Short: "Logout and revoke tokens",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runLogout(cfg, log)
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show authentication status",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runAuthStatus(cfg)
			},
		},
	)

	return cmd
}

// NewShortenCommand creates the shorten command (imperative)
func NewShortenCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shorten [URL]",
		Short: "Create a short URL",
		Long:  "Create a short URL from a long URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			custom, err := cmd.Flags().GetString("custom")
			if err != nil {
				return fmt.Errorf("failed to get custom flag: %w", err)
			}

			ttl, err := cmd.Flags().GetInt64("ttl")
			if err != nil {
				return fmt.Errorf("failed to get ttl flag: %w", err)
			}

			return runCreateShortURL(cfg, log, args[0], custom, ttl)
		},
	}

	// Add flags
	cmd.Flags().String("custom", "", "Custom short code")
	cmd.Flags().Int64("ttl", 0, "Time to live in seconds (0 = no expiration)")

	return cmd
}

// NewListCommand creates the list command (imperative)
func NewListCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List your short URLs",
		Long:  "List all short URLs belonging to the authenticated user",
		RunE: func(cmd *cobra.Command, args []string) error {
			page, err := cmd.Flags().GetInt("page")
			if err != nil {
				return fmt.Errorf("failed to get page flag: %w", err)
			}
			pageSize, err := cmd.Flags().GetInt("page-size")
			if err != nil {
				return fmt.Errorf("failed to get page-size flag: %w", err)
			}
			limit, err := cmd.Flags().GetInt("limit")
			if err != nil {
				return fmt.Errorf("failed to get limit flag: %w", err)
			}
			if limit > 0 {
				pageSize = limit
			}
			return runListURLs(cfg, log, page, pageSize)
		},
	}

	// Add flags
	cmd.Flags().Int("page", 1, "Page number")
	cmd.Flags().Int("page-size", 20, "Items per page")
	cmd.Flags().Int("limit", 0, "Limit number of results (alias for page-size)")

	return cmd
}

// NewDeleteCommand creates the delete command (imperative)
func NewDeleteCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [short-code]",
		Short: "Delete a short URL",
		Long:  "Delete a short URL by its short code",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Add confirmation prompt for destructive operation
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("failed to get force flag: %w", err)
			}
			if !force {
				fmt.Printf("Are you sure you want to delete short URL '%s'? (y/N): ", args[0])
				var response string
				_, err := fmt.Scanln(&response)
				if err != nil {
					fmt.Println("❌ Error reading input. Deletion canceled.")
					return nil
				}
				if response != "y" && response != "Y" && response != "yes" {
					fmt.Println("❌ Deletion canceled.")
					return nil
				}
			}
			return runDeleteURL(cfg, log, args[0])
		},
	}

	// Add flags
	cmd.Flags().BoolP("force", "f", false, "Force deletion without confirmation")

	return cmd
}

// NewGetCommand creates the get command (imperative)
func NewGetCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [short-code]",
		Short: "Get details of a short URL",
		Long:  "Get detailed information about a short URL by its short code",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGetURL(cfg, log, args[0])
		},
	}

	return cmd
}

// NewStatsCommand creates the stats command (imperative)
func NewStatsCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats [short-code]",
		Short: "Show analytics for a short URL",
		Long:  "Show detailed analytics and statistics for a short URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGetURLStats(cfg, log, args[0])
		},
	}

	return cmd
}

// NewMigrateCommand creates the database migration command
func NewMigrateCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration operations",
		Long:  "Run database migrations",
	}

	// Create migrate up command with database flags
	upCmd := &cobra.Command{
		Use:   "up",
		Short: "Run all pending migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Override config with command-line flags if provided
			if err := overrideConfigFromFlags(cmd, cfg); err != nil {
				return fmt.Errorf("failed to override config from flags: %w", err)
			}
			return runMigrations(cfg, log)
		},
	}

	// Add database configuration flags to migrate up command
	upCmd.Flags().String("database-url", "", "Database connection URL (overrides individual DB flags)")
	upCmd.Flags().String("db-host", "", "Database host")
	upCmd.Flags().Int("db-port", 0, "Database port")
	upCmd.Flags().String("db-name", "", "Database name")
	upCmd.Flags().String("db-user", "", "Database user")
	upCmd.Flags().String("db-password", "", "Database password")
	upCmd.Flags().String("db-ssl-mode", "", "Database SSL mode (disable, require, etc.)")

	// Add subcommands
	cmd.AddCommand(
		upCmd,
		&cobra.Command{
			Use:   "status",
			Short: "Show migration status",
			RunE: func(cmd *cobra.Command, args []string) error {
				return showMigrationStatus(cfg, log)
			},
		},
	)

	return cmd
}

// NewVersionCommand creates the version command
func NewVersionCommand(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Maigo URL Shortener\n")
			fmt.Printf("Version: %s\n", version)
			fmt.Printf("Commit: %s\n", commit)
			fmt.Printf("Built: %s\n", date)
		},
	}
}

// runServer starts the HTTP server (moved from cmd/server/main.go)
func runServer(cfg *config.Config, log *logger.Logger) error {
	log.Info("Starting Maigo server",
		"version", "dev",
		"config", cfg.ServerAddr(),
	)

	// Set Gin mode based on debug setting
	if !cfg.App.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	log.Info("Connected to database", "host", cfg.Database.Host, "port", cfg.Database.Port)

	// Initialize OAuth server and ensure CLI client exists
	oauthServer := oauth.NewServer(db, cfg, log.Logger)

	ctx := context.Background()
	if err := oauthServer.EnsureDefaultOAuthClient(ctx); err != nil {
		log.Error("Failed to ensure default OAuth client exists", "error", err)
		return fmt.Errorf("failed to initialize OAuth client: %w", err)
	}
	log.Info("OAuth CLI client initialized successfully")

	// Initialize HTTP server
	httpServer := server.NewHTTPServer(cfg, db, log)

	// Create HTTP server instance
	srv := &http.Server{
		Addr:         cfg.ServerAddr(),
		Handler:      httpServer,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	// Start server in a goroutine
	go func() {
		log.Info("Starting HTTP server", "address", cfg.ServerAddr())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Failed to start HTTP server", "error", err)
		}
	}()

	log.Info("Maigo server started successfully")

	// Setup signal context for graceful shutdown
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Wait for interrupt signal to gracefully shutdown the server
	<-ctx.Done()

	// Stop listening for more signals to allow forced termination on subsequent Ctrl+C
	stop()

	log.Info("Shutting down server...")

	// Give the server 30 seconds to finish processing requests
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("Server forced to shutdown", "error", err)
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Info("Server exited")
	return nil
}

// runMigrations runs database migrations
func runMigrations(cfg *config.Config, log *logger.Logger) error {
	log.Info("Running database migrations")

	// Initialize database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Run migrations
	if err := database.RunMigrations(db); err != nil {
		log.Error("Failed to run database migrations", "error", err)
		return fmt.Errorf("failed to run database migrations: %w", err)
	}

	log.Info("Database migrations completed successfully")
	return nil
}

// showMigrationStatus shows the current migration status
func showMigrationStatus(cfg *config.Config, log *logger.Logger) error {
	log.Info("Checking migration status")

	// Initialize database
	db, err := database.Connect(cfg)
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer db.Close()

	// Check database health
	if err := database.Health(db); err != nil {
		fmt.Printf("❌ Database connection failed: %v\n", err)
		return err
	}

	fmt.Println("✅ Database connection: OK")
	fmt.Println("✅ Migrations: Ready to run")
	return nil
}

// runLogin handles user login using OAuth 2.0 flow
func runLogin(cfg *config.Config, log *logger.Logger, username string) error {
	client := NewAPIClient(cfg)

	// Check if already authenticated
	tokens, err := client.LoadTokens()
	if err == nil && tokens != nil && !client.IsTokenExpired(tokens) {
		fmt.Printf("✅ Already authenticated as user (expires in %d minutes)\n",
			(tokens.ExpiresAt-time.Now().Unix())/60)
		return nil
	}

	// Create OAuth client
	oauthClient := NewOAuthClient(cfg, log)

	// Perform OAuth 2.0 flow
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	fmt.Printf("🔐 Starting OAuth 2.0 authentication for user: %s\n", username)

	tokenResponse, err := oauthClient.PerformOAuthFlow(ctx)
	if err != nil {
		log.Error("OAuth flow failed", "username", username, "error", err)
		return fmt.Errorf("OAuth authentication failed: %w", err)
	}

	// Save tokens
	if err := client.SaveTokens(tokenResponse); err != nil {
		log.Error("Failed to save tokens", "error", err)
		return fmt.Errorf("failed to save authentication tokens: %w", err)
	}

	log.Info("OAuth login successful", "username", username)
	fmt.Printf("✅ OAuth authentication successful! Tokens saved.\n")
	fmt.Printf("📱 You can now use Maigo CLI commands.\n")
	return nil
}

// runRegister handles user registration using direct API call
func runRegister(cfg *config.Config, log *logger.Logger, username, email string) error {
	fmt.Printf("🔐 Creating account for Maigo\n")
	fmt.Printf("� Username: %s\n", username)
	fmt.Printf("📧 Email: %s\n", email)
	fmt.Printf("\n")

	// Prompt for password
	fmt.Printf("🔒 Please enter a password (minimum 6 characters): ")

	var password string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		// Use secure password input when running in a terminal
		passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			fmt.Printf("\n❌ Failed to read password: %v\n", err)
			return fmt.Errorf("failed to read password: %w", err)
		}
		password = string(passwordBytes)
		fmt.Println() // Add newline after password input
	} else {
		// Fallback to regular input when not in a terminal (for testing/scripting)
		_, err := fmt.Scanln(&password)
		if err != nil {
			return fmt.Errorf("failed to read password: %w", err)
		}
	}

	if len(password) < 6 {
		fmt.Printf("❌ Password must be at least 6 characters long.\n")
		return fmt.Errorf("password too short")
	}

	// Create API client
	client := NewAPIClient(cfg)

	// Register user
	fmt.Printf("📝 Creating account...\n")
	response, err := client.Register(username, email, password)
	if err != nil {
		log.Error("Registration failed", "username", username, "email", email, "error", err)
		return fmt.Errorf("registration failed: %w", err)
	}

	// Extract tokens from response
	if tokensInterface, ok := response["tokens"]; ok {
		if tokensMap, ok := tokensInterface.(map[string]interface{}); ok {
			// Convert to TokenResponse structure
			accessToken, ok := tokensMap["access_token"].(string)
			if !ok {
				return fmt.Errorf("invalid access_token type")
			}
			refreshToken, ok := tokensMap["refresh_token"].(string)
			if !ok {
				return fmt.Errorf("invalid refresh_token type")
			}
			tokenType, ok := tokensMap["token_type"].(string)
			if !ok {
				return fmt.Errorf("invalid token_type type")
			}
			expiresInFloat, ok := tokensMap["expires_in"].(float64)
			if !ok {
				return fmt.Errorf("invalid expires_in type")
			}

			tokenResponse := &models.TokenResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				TokenType:    tokenType,
				ExpiresIn:    int(expiresInFloat),
			}

			// Save tokens
			if err := client.SaveTokens(tokenResponse); err != nil {
				log.Error("Failed to save tokens after registration", "error", err)
				return fmt.Errorf("failed to save authentication tokens: %w", err)
			}
		}
	}

	log.Info("Registration successful", "username", username, "email", email)
	fmt.Printf("✅ Registration successful!\n")
	fmt.Printf("🎉 Welcome to Maigo, %s!\n", username)
	fmt.Printf("📱 You can now use Maigo CLI commands.\n")
	return nil
}

// runLogout handles user logout
func runLogout(cfg *config.Config, log *logger.Logger) error {
	client := NewAPIClient(cfg)

	// Clear stored tokens
	if err := client.ClearTokens(); err != nil {
		log.Error("Failed to clear tokens", "error", err)
		return fmt.Errorf("failed to clear tokens: %w", err)
	}

	log.Info("Logout successful")
	fmt.Println("✅ Logout successful! Tokens cleared.")
	return nil
}

// runAuthStatus shows current authentication status
func runAuthStatus(cfg *config.Config) error {
	client := NewAPIClient(cfg)

	status, err := client.GetTokenStatus()
	if err != nil {
		fmt.Printf("❌ Error checking authentication status: %v\n", err)
		return nil
	}

	tokenExists, ok := status["token_exists"].(bool)
	if !ok || !tokenExists {
		fmt.Println("❌ Not authenticated")
		fmt.Println("Run 'maigo auth login <username>' to authenticate")
		return nil
	}

	fmt.Printf("✅ Authenticated\n")

	if expired, ok := status["expired"].(bool); ok && expired {
		fmt.Printf("❌ Token Status: Expired\n")
		fmt.Println("🔄 Refresh token available - will be used automatically on next API call")
	} else {
		fmt.Printf("✅ Token Status: Valid\n")
		if timeLeft, ok := status["time_left"].(string); ok && timeLeft != "" {
			fmt.Printf("⏱️  Time remaining: %s\n", timeLeft)
		}
	}

	if expiresAt, ok := status["expires_at"].(string); ok && expiresAt != "" {
		fmt.Printf("📅 Expires at: %s\n", expiresAt)
	}

	return nil
}

// runCreateShortURL creates a new short URL
func runCreateShortURL(cfg *config.Config, log *logger.Logger, url, custom string, ttl int64) error {
	client := NewAPIClient(cfg)

	log.Info("Creating short URL", "url", url, "custom", custom, "ttl", ttl)
	response, err := client.CreateShortURL(url, custom, ttl)
	if err != nil {
		log.Error("Failed to create short URL", "url", url, "error", err)
		return fmt.Errorf("failed to create short URL: %w", err)
	}

	log.Info("Short URL created successfully")

	// Display result
	fmt.Printf("✅ Short URL created successfully!\n\n")
	fmt.Printf("Original URL: %s\n", response["url"])
	fmt.Printf("Short Code:   %s\n", response["short_code"])
	fmt.Printf("Short URL:    %s\n", response["short_url"])
	fmt.Printf("Created:      %s\n", response["created_at"])

	return nil
}

// runListURLs lists user's short URLs
func runListURLs(cfg *config.Config, log *logger.Logger, page, pageSize int) error {
	client := NewAPIClient(cfg)

	// Set defaults if not provided
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = 20
	}

	log.Info("Listing URLs", "page", page, "page_size", pageSize)
	response, err := client.GetUserURLs(page, pageSize)
	if err != nil {
		log.Error("Failed to list URLs", "error", err)
		return fmt.Errorf("failed to list URLs: %w", err)
	}

	if len(response.URLs) == 0 {
		fmt.Println("No URLs found.")
		return nil
	}

	// Display results
	fmt.Printf("📋 Your Short URLs (Page %d of %d)\n\n",
		response.Pagination.Page, response.Pagination.Pages)

	for i, url := range response.URLs {
		fmt.Printf("%d. %s\n", i+1, url.ShortCode)
		fmt.Printf("   URL: %s\n", url.TargetURL)
		fmt.Printf("   Hits: %d | Created: %s\n\n", url.Hits, url.CreatedAt.Format("2006-01-02 15:04"))
	}

	fmt.Printf("Total: %d URLs\n", response.Pagination.Total)

	return nil
}

// runDeleteURL deletes a short URL
func runDeleteURL(cfg *config.Config, log *logger.Logger, shortCode string) error {
	client := NewAPIClient(cfg)

	log.Info("Deleting URL", "short_code", shortCode)
	err := client.DeleteURL(shortCode)
	if err != nil {
		log.Error("Failed to delete URL", "short_code", shortCode, "error", err)
		return fmt.Errorf("failed to delete URL: %w", err)
	}

	log.Info("URL deleted successfully", "short_code", shortCode)
	fmt.Printf("✅ Short URL '%s' deleted successfully!\n", shortCode)

	return nil
}

// runGetURL gets details of a specific short URL
func runGetURL(cfg *config.Config, log *logger.Logger, shortCode string) error {
	client := NewAPIClient(cfg)

	log.Info("Getting URL details", "short_code", shortCode)
	response, err := client.GetURL(shortCode)
	if err != nil {
		log.Error("Failed to get URL details", "short_code", shortCode, "error", err)
		return fmt.Errorf("failed to get URL details: %w", err)
	}

	// Display result
	fmt.Printf("📋 URL Details for '%s'\n\n", shortCode)
	fmt.Printf("Short Code:   %s\n", response["short_code"])
	fmt.Printf("Target URL:   %s\n", response["url"])
	fmt.Printf("Short URL:    %s\n", response["short_url"])
	fmt.Printf("Hits:         %v\n", response["hits"])
	fmt.Printf("Created:      %s\n", response["created_at"])

	return nil
}

// runGetURLStats gets analytics for a specific short URL
func runGetURLStats(cfg *config.Config, log *logger.Logger, shortCode string) error {
	client := NewAPIClient(cfg)

	log.Info("Getting URL statistics", "short_code", shortCode)
	response, err := client.GetURLStats(shortCode)
	if err != nil {
		log.Error("Failed to get URL statistics", "short_code", shortCode, "error", err)
		return fmt.Errorf("failed to get URL statistics: %w", err)
	}

	// Display statistics
	fmt.Printf("📊 Analytics for '%s'\n\n", shortCode)
	fmt.Printf("Target URL:   %s\n", response["url"])
	fmt.Printf("Total Hits:   %v\n", response["hits"])
	fmt.Printf("Created:      %s\n", response["created_at"])

	if lastHit, ok := response["last_hit"]; ok && lastHit != nil {
		fmt.Printf("Last Hit:     %s\n", lastHit)
	} else {
		fmt.Printf("Last Hit:     Never\n")
	}

	// Show hit timeline if available
	if timeline, ok := response["timeline"]; ok && timeline != nil {
		fmt.Printf("\n📈 Recent Activity:\n")
		if timelineData, ok := timeline.([]interface{}); ok {
			for _, entry := range timelineData {
				if entryMap, ok := entry.(map[string]interface{}); ok {
					fmt.Printf("  %s: %v hits\n", entryMap["date"], entryMap["hits"])
				}
			}
		}
	}

	return nil
}
