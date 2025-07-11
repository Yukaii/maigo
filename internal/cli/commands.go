package cli

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/ssh"
)

// NewServerCommand creates the server command
func NewServerCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the HTTP server",
		Long:  "Start the HTTP server for the Maigo URL shortener",
		RunE: func(cmd *cobra.Command, args []string) error {
			// TODO: Start the server (this logic should be moved from cmd/server/main.go)
			log.Info("Starting server command")
			fmt.Println("Server command not yet implemented - use 'go run cmd/server/main.go' for now")
			return nil
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
			Use:   "login",
			Short: "Login to get access token",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: Implement CLI login
				fmt.Println("CLI login not yet implemented")
				return nil
			},
		},
		&cobra.Command{
			Use:   "logout",
			Short: "Logout and revoke tokens",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: Implement CLI logout
				fmt.Println("CLI logout not yet implemented")
				return nil
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
				// TODO: Implement URL shortening
				fmt.Printf("Creating short URL for: %s\n", args[0])
				fmt.Println("URL shortening not yet implemented")
				return nil
			},
		},
		&cobra.Command{
			Use:   "list",
			Short: "List your short URLs",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: Implement URL listing
				fmt.Println("URL listing not yet implemented")
				return nil
			},
		},
	)

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
			
			// Start the server (this blocks until shutdown)
			if err := sshServer.Start(); err != nil {
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
				// TODO: Implement migration up
				fmt.Println("Migration up not yet implemented")
				return nil
			},
		},
		&cobra.Command{
			Use:   "down",
			Short: "Rollback the last migration",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: Implement migration down
				fmt.Println("Migration down not yet implemented")
				return nil
			},
		},
		&cobra.Command{
			Use:   "status",
			Short: "Show migration status",
			RunE: func(cmd *cobra.Command, args []string) error {
				// TODO: Implement migration status
				fmt.Println("Migration status not yet implemented")
				return nil
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
