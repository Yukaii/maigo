package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/yukaii/maigo/internal/cli"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.NewLogger(logger.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
	})
	logger.SetGlobalLogger(log)

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "maigo",
		Short: "A modern terminal-first URL shortener",
		Long: `Maigo is a modern terminal-first URL shortener with OAuth2 authentication.
It provides imperative CLI commands for direct URL management and analytics.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Add subcommands
	rootCmd.AddCommand(
		cli.NewServerCommand(cfg, log),
		cli.NewAuthCommand(cfg, log),
		cli.NewShortenCommand(cfg, log),
		cli.NewListCommand(cfg, log),
		cli.NewDeleteCommand(cfg, log),
		cli.NewGetCommand(cfg, log),
		cli.NewStatsCommand(cfg, log),
		cli.NewMigrateCommand(cfg, log),
		cli.NewVersionCommand(version, commit, date),
	)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
