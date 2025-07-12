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
	"github.com/yukaii/maigo/internal/server"
	"github.com/yukaii/maigo/internal/ssh"
)

// NewServerCommand creates the server command
func NewServerCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the HTTP server",
		Long:  "Start the HTTP server for the Maigo URL shortener",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cfg, log)
		},
	}

	return cmd
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
				return runAuthStatus(cfg, log)
			},
		},
	)

	return cmd
}

// NewShortCommand creates the URL shortening command
func NewShortCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "short",
		Short: "URL shortening operations",
		Long:  "Create and manage short URLs",
	}

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:   "create [URL]",
			Short: "Create a short URL",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				custom, _ := cmd.Flags().GetString("custom")
				return runCreateShortURL(cfg, log, args[0], custom)
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List your short URLs",
			RunE: func(cmd *cobra.Command, args []string) error {
				page, _ := cmd.Flags().GetInt("page")
				pageSize, _ := cmd.Flags().GetInt("page-size")
				return runListURLs(cfg, log, page, pageSize)
			},
		},
		&cobra.Command{
			Use:   "delete [short-code]",
			Short: "Delete a short URL",
			Args:  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return runDeleteURL(cfg, log, args[0])
			},
		},
	)

	// Add flags
	createCmd := cmd.Commands()[0] // create command
	createCmd.Flags().String("custom", "", "Custom short code")
	
	listCmd := cmd.Commands()[1] // list command
	listCmd.Flags().Int("page", 1, "Page number")
	listCmd.Flags().Int("page-size", 20, "Items per page")

	return cmd
}

// NewSSHCommand creates the SSH server command
func NewSSHCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssh",
		Short: "SSH server operations",
		Long:  "Start and manage the SSH terminal interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Info("Starting SSH TUI server", "address", cfg.SSHAddr())

			// Initialize database connection
			db, err := database.Connect(cfg)
			if err != nil {
				return fmt.Errorf("failed to connect to database: %w", err)
			}
			defer db.Close()

			// Create and start SSH server
			sshServer := ssh.NewServer(cfg, db, log)

			// Generate host key if needed
			if err := sshServer.GenerateHostKey(); err != nil {
				log.Error("Failed to generate host key", "error", err)
				return fmt.Errorf("failed to generate host key: %w", err)
			}

			// Setup signal handling
			ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()

			// Start the server (this blocks until shutdown signal)
			if err := sshServer.Start(ctx); err != nil {
				log.Error("SSH server failed", "error", err)
				return fmt.Errorf("SSH server failed: %w", err)
			}

			return nil
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

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:   "up",
			Short: "Run all pending migrations",
			RunE: func(cmd *cobra.Command, args []string) error {
				return runMigrations(cfg, log)
			},
		},
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

// runLogin handles user login
func runLogin(cfg *config.Config, log *logger.Logger, username string) error {
	client := NewAPIClient(cfg)
	
	// Check if already authenticated
	tokens, err := client.LoadTokens()
	if err == nil && tokens != nil && !client.IsTokenExpired(tokens) {
		fmt.Printf("✅ Already authenticated as user (expires in %d minutes)\n", 
			(tokens.ExpiresAt-time.Now().Unix())/60)
		return nil
	}

	// Get password from user
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := string(passwordBytes)
	fmt.Println() // New line after password input

	// Authenticate
	log.Info("Attempting to login", "username", username)
	response, err := client.Login(username, password)
	if err != nil {
		log.Error("Login failed", "username", username, "error", err)
		return fmt.Errorf("login failed: %w", err)
	}

	// Save tokens
	if err := client.SaveTokens(response); err != nil {
		log.Error("Failed to save tokens", "error", err)
		return fmt.Errorf("failed to save authentication tokens: %w", err)
	}

	log.Info("Login successful", "username", username)
	fmt.Printf("✅ Login successful! Tokens saved.\n")
	return nil
}

// runRegister handles user registration
func runRegister(cfg *config.Config, log *logger.Logger, username, email string) error {
	client := NewAPIClient(cfg)

	// Get password from user
	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}
	password := string(passwordBytes)
	fmt.Println() // New line after password input

	// Register
	log.Info("Attempting to register", "username", username, "email", email)
	response, err := client.Register(username, email, password)
	if err != nil {
		log.Error("Registration failed", "username", username, "email", email, "error", err)
		return fmt.Errorf("registration failed: %w", err)
	}

	log.Info("Registration successful", "username", username)
	fmt.Printf("✅ Registration successful!\n")

	// Check if tokens were returned and save them
	if tokensData, ok := (*response)["tokens"]; ok {
		if tokensMap, ok := tokensData.(map[string]interface{}); ok {
			// Extract token data
			accessToken, _ := tokensMap["access_token"].(string)
			refreshToken, _ := tokensMap["refresh_token"].(string)
			tokenType, _ := tokensMap["token_type"].(string)
			expiresIn, _ := tokensMap["expires_in"].(float64)

			if accessToken != "" {
				tokens := &models.TokenResponse{
					AccessToken:  accessToken,
					RefreshToken: refreshToken,
					TokenType:    tokenType,
					ExpiresIn:    int(expiresIn),
				}

				if err := client.SaveTokens(tokens); err != nil {
					log.Warn("Failed to save tokens after registration", "error", err)
					fmt.Println("⚠️  Registration successful but failed to save tokens. Please login manually.")
				} else {
					fmt.Println("✅ Tokens saved automatically.")
				}
			}
		}
	}

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
func runAuthStatus(cfg *config.Config, log *logger.Logger) error {
	client := NewAPIClient(cfg)

	tokens, err := client.LoadTokens()
	if err != nil {
		fmt.Printf("❌ Error loading tokens: %v\n", err)
		return nil
	}

	if tokens == nil {
		fmt.Println("❌ Not authenticated")
		fmt.Println("Run 'maigo auth login <username>' to authenticate")
		return nil
	}

	fmt.Printf("✅ Authenticated\n")
	fmt.Printf("Token Type: %s\n", tokens.TokenType)
	
	if client.IsTokenExpired(tokens) {
		fmt.Printf("❌ Token Status: Expired\n")
		if tokens.RefreshToken != "" {
			fmt.Println("🔄 Refresh token available - will be used automatically")
		} else {
			fmt.Println("❌ No refresh token available - please login again")
		}
	} else {
		expiresIn := tokens.ExpiresAt - time.Now().Unix()
		fmt.Printf("✅ Token Status: Valid (expires in %d minutes)\n", expiresIn/60)
	}

	return nil
}

// runCreateShortURL creates a new short URL
func runCreateShortURL(cfg *config.Config, log *logger.Logger, url, custom string) error {
	client := NewAPIClient(cfg)

	log.Info("Creating short URL", "url", url, "custom", custom)
	response, err := client.CreateShortURL(url, custom)
	if err != nil {
		log.Error("Failed to create short URL", "url", url, "error", err)
		return fmt.Errorf("failed to create short URL: %w", err)
	}

	log.Info("Short URL created successfully")
	
	// Display result
	fmt.Printf("✅ Short URL created successfully!\n\n")
	fmt.Printf("Original URL: %s\n", (*response)["url"])
	fmt.Printf("Short Code:   %s\n", (*response)["short_code"])
	fmt.Printf("Short URL:    %s\n", (*response)["short_url"])
	fmt.Printf("Created:      %s\n", (*response)["created_at"])

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
