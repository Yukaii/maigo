package main

import (
	"fmt"
	"os"
	"strings"

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
	var (
		configFile string
		serverURL  string
		apiKey     string
	)

	// Create root command
	rootCmd := &cobra.Command{
		Use:   "maigo",
		Short: "A small self-hosted URL shortener",
		Long: `Maigo Core is a single-owner URL shortener with a SQLite database,
one API key, a simple CLI, and a local stdio MCP server.`,
		Version: fmt.Sprintf("%s (commit: %s, built: %s)", version, commit, date),
	}

	// Add persistent flags
	rootCmd.PersistentFlags().StringVar(
		&configFile,
		"config",
		"",
		"config file path (default searches for maigo.yaml in current directory and $HOME/.maigo/)",
	)
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", "", "Maigo server URL (overrides PUBLIC_URL)")
	rootCmd.PersistentFlags().StringVar(&apiKey, "api-key", "", "Maigo API key (overrides API_KEY)")

	// Read the config path before Cobra executes the command. Cobra still
	// parses and validates the flag later, but doing this here lets every
	// command use the selected configuration during initialization.
	configFile = configPathFromArgs(os.Args[1:])
	serverURL = valueFromArgs(os.Args[1:], "--server")
	apiKey = valueFromArgs(os.Args[1:], "--api-key")

	// Load configuration with optional config file path
	cfg, err := config.Load(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load configuration: %v\n", err)
		os.Exit(1)
	}
	if serverURL != "" {
		cfg.App.PublicURL = strings.TrimRight(serverURL, "/")
	}
	if apiKey != "" {
		cfg.Auth.APIKey = apiKey
	}
	if err := config.Validate(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Initialize logger
	log := logger.NewLogger(logger.Config{
		Level:  cfg.Log.Level,
		Format: cfg.Log.Format,
	})
	logger.SetGlobalLogger(log)

	// Add subcommands
	rootCmd.AddCommand(
		cli.NewServerCommand(cfg, log),
		cli.NewShortenCommand(cfg, log),
		cli.NewListCommand(cfg, log),
		cli.NewDeleteCommand(cfg, log),
		cli.NewGetCommand(cfg, log),
		cli.NewStatsCommand(cfg, log),
		cli.NewMCPCommand(cfg, log),
		cli.NewVersionCommand(version, commit, date),
	)

	// Execute root command
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func valueFromArgs(args []string, flagName string) string {
	for i, arg := range args {
		if arg == flagName && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, flagName+"=") {
			return strings.TrimPrefix(arg, flagName+"=")
		}
	}
	return ""
}

// configPathFromArgs extracts the persistent --config flag without parsing
// the rest of the command line. Parsing the full argument list here would
// make normal Cobra help requests look like fatal errors.
func configPathFromArgs(args []string) string {
	for i, arg := range args {
		if arg == "--config" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--config=") {
			return strings.TrimPrefix(arg, "--config=")
		}
	}

	return ""
}
