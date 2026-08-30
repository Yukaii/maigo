package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/spf13/cobra"

	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/mcpserver"
	"github.com/yukaii/maigo/internal/server"
)

// NewServerCommand creates the local HTTP server command.
func NewServerCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "server",
		Short: "Start the Maigo HTTP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("port") {
				port, err := cmd.Flags().GetInt("port")
				if err != nil {
					return fmt.Errorf("read port flag: %w", err)
				}
				cfg.Server.Port = port
			}
			if cmd.Flags().Changed("host") {
				host, err := cmd.Flags().GetString("host")
				if err != nil {
					return fmt.Errorf("read host flag: %w", err)
				}
				cfg.Server.Host = host
			}
			if err := config.Validate(cfg); err != nil {
				return fmt.Errorf("invalid server configuration: %w", err)
			}
			return runServer(cfg, log)
		},
	}
	cmd.Flags().IntP("port", "p", cfg.Server.Port, "HTTP server port")
	cmd.Flags().String("host", cfg.Server.Host, "HTTP server host")
	return cmd
}

// NewShortenCommand creates the URL creation command.
func NewShortenCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "shorten [URL]",
		Short: "Create a short URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			custom, err := cmd.Flags().GetString("custom")
			if err != nil {
				return fmt.Errorf("read custom flag: %w", err)
			}
			ttl, err := cmd.Flags().GetInt64("ttl")
			if err != nil {
				return fmt.Errorf("read ttl flag: %w", err)
			}
			asJSON, err := cmd.Flags().GetBool("json")
			if err != nil {
				return fmt.Errorf("read json flag: %w", err)
			}
			return runCreateShortURL(cfg, log, args[0], custom, ttl, asJSON)
		},
	}
	cmd.Flags().String("custom", "", "Custom short code")
	cmd.Flags().Int64("ttl", 0, "Time to live in seconds (minimum 60; 0 means never expires)")
	cmd.Flags().Bool("json", false, "Print the raw JSON response")
	return cmd
}

// NewListCommand creates the link listing command.
func NewListCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List short URLs",
		RunE: func(cmd *cobra.Command, args []string) error {
			page, err := cmd.Flags().GetInt("page")
			if err != nil {
				return fmt.Errorf("read page flag: %w", err)
			}
			pageSize, err := cmd.Flags().GetInt("page-size")
			if err != nil {
				return fmt.Errorf("read page-size flag: %w", err)
			}
			limit, err := cmd.Flags().GetInt("limit")
			if err != nil {
				return fmt.Errorf("read limit flag: %w", err)
			}
			if limit > 0 {
				pageSize = limit
			}
			asJSON, err := cmd.Flags().GetBool("json")
			if err != nil {
				return fmt.Errorf("read json flag: %w", err)
			}
			return runListURLs(cfg, log, page, pageSize, asJSON)
		},
	}
	cmd.Flags().Int("page", 1, "Page number")
	cmd.Flags().Int("page-size", 20, "Items per page")
	cmd.Flags().Int("limit", 0, "Alias for page-size")
	cmd.Flags().Bool("json", false, "Print the raw JSON response")
	return cmd
}

// NewDeleteCommand creates the link deletion command.
func NewDeleteCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete [short-code]",
		Short: "Delete a short URL",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return fmt.Errorf("read force flag: %w", err)
			}
			asJSON, err := cmd.Flags().GetBool("json")
			if err != nil {
				return fmt.Errorf("read json flag: %w", err)
			}
			if !force && !asJSON && !confirmDelete(args[0]) {
				fmt.Println("Deletion canceled.")
				return nil
			}
			return runDeleteURL(cfg, log, args[0], asJSON)
		},
	}
	cmd.Flags().BoolP("force", "f", false, "Delete without confirmation")
	cmd.Flags().Bool("json", false, "Print the raw JSON response")
	return cmd
}

// NewGetCommand creates the link metadata command.
func NewGetCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get [short-code]",
		Short: "Show short URL details",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := jsonFlag(cmd)
			if err != nil {
				return err
			}
			return runGetURL(cfg, log, args[0], asJSON)
		},
	}
	cmd.Flags().Bool("json", false, "Print the raw JSON response")
	return cmd
}

// NewStatsCommand creates the lifetime hit-count command.
func NewStatsCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "stats [short-code]",
		Short: "Show lifetime hit count",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			asJSON, err := jsonFlag(cmd)
			if err != nil {
				return err
			}
			return runGetURLStats(cfg, log, args[0], asJSON)
		},
	}
	cmd.Flags().Bool("json", false, "Print the raw JSON response")
	return cmd
}

// NewMCPCommand runs the local Model Context Protocol stdio server.
func NewMCPCommand(cfg *config.Config, log *logger.Logger) *cobra.Command {
	return &cobra.Command{
		Use:   "mcp",
		Short: "Run the local stdio MCP server",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := NewAPIClient(cfg)
			return mcpserver.Run(context.Background(), client)
		},
	}
}

// NewVersionCommand creates the version command.
func NewVersionCommand(version, commit, date string) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("Maigo Core %s (commit: %s, built: %s)\n", version, commit, date)
		},
	}
}

func runServer(cfg *config.Config, log *logger.Logger) error {
	if !cfg.App.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	db, err := database.Connect(cfg)
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	defer func() {
		if closeErr := db.Close(); closeErr != nil {
			log.Error("Failed to close database", "error", closeErr)
		}
	}()

	httpHandler := server.NewHTTPServer(cfg, db, log)
	srv := &http.Server{
		Addr:         cfg.ServerAddr(),
		Handler:      httpHandler,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeout) * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Info("Maigo server listening", "address", cfg.ServerAddr(), "database", cfg.Database.Path)
		if listenErr := srv.ListenAndServe(); listenErr != nil && listenErr != http.ErrServerClosed {
			serverErr <- listenErr
		}
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-serverErr:
		return fmt.Errorf("server stopped unexpectedly: %w", err)
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown server: %w", err)
		}
		log.Info("Maigo server stopped")
		return nil
	}
}

func runCreateShortURL(cfg *config.Config, log *logger.Logger, targetURL, custom string, ttl int64, asJSON bool) error {
	response, err := NewAPIClient(cfg).CreateShortURL(targetURL, custom, ttl)
	if err != nil {
		return fmt.Errorf("create short URL: %w", err)
	}
	if asJSON {
		return printJSON(response)
	}
	log.Info("Created short URL", "short_code", response["short_code"])
	fmt.Printf("Short URL: %v\n", response["short_url"])
	fmt.Printf("Target:    %v\n", response["target_url"])
	if expiresAt, ok := response["expires_at"]; ok && expiresAt != nil {
		fmt.Printf("Expires:   %v\n", expiresAt)
	}
	return nil
}

func runListURLs(cfg *config.Config, log *logger.Logger, page, pageSize int, asJSON bool) error {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	response, err := NewAPIClient(cfg).ListURLs(page, pageSize)
	if err != nil {
		return fmt.Errorf("list URLs: %w", err)
	}
	if asJSON {
		return printJSON(response)
	}
	if len(response.URLs) == 0 {
		fmt.Println("No short URLs found.")
		return nil
	}
	for _, item := range response.URLs {
		fmt.Printf("%s  %s  hits=%d\n", item.ShortCode, item.TargetURL, item.Hits)
	}
	fmt.Printf("Page %d/%d · %d total\n", response.Pagination.Page, response.Pagination.Pages, response.Pagination.Total)
	log.Debug("Listed URLs", "page", page, "page_size", pageSize)
	return nil
}

func runDeleteURL(cfg *config.Config, log *logger.Logger, shortCode string, asJSON bool) error {
	if err := NewAPIClient(cfg).DeleteURL(shortCode); err != nil {
		return fmt.Errorf("delete URL: %w", err)
	}
	if asJSON {
		return printJSON(map[string]any{"deleted": true, "short_code": shortCode})
	}
	log.Info("Deleted short URL", "short_code", shortCode)
	fmt.Printf("Deleted %s\n", shortCode)
	return nil
}

func runGetURL(cfg *config.Config, log *logger.Logger, shortCode string, asJSON bool) error {
	response, err := NewAPIClient(cfg).GetURL(shortCode)
	if err != nil {
		return fmt.Errorf("get URL: %w", err)
	}
	if asJSON {
		return printJSON(response)
	}
	fmt.Printf("Short URL: %v\n", response["short_url"])
	fmt.Printf("Target:    %v\n", response["target_url"])
	fmt.Printf("Hits:      %v\n", response["hits"])
	fmt.Printf("Created:   %v\n", response["created_at"])
	if expiresAt, ok := response["expires_at"]; ok && expiresAt != nil {
		fmt.Printf("Expires:   %v\n", expiresAt)
	}
	log.Debug("Fetched URL", "short_code", shortCode)
	return nil
}

func runGetURLStats(cfg *config.Config, log *logger.Logger, shortCode string, asJSON bool) error {
	response, err := NewAPIClient(cfg).GetURLStats(shortCode)
	if err != nil {
		return fmt.Errorf("get URL stats: %w", err)
	}
	if asJSON {
		return printJSON(response)
	}
	fmt.Printf("Short code: %v\n", response["short_code"])
	fmt.Printf("Target:     %v\n", response["url"])
	fmt.Printf("Hits:       %v\n", response["hits"])
	log.Debug("Fetched URL stats", "short_code", shortCode)
	return nil
}

func confirmDelete(shortCode string) bool {
	fmt.Printf("Delete %q? [y/N] ", shortCode)
	answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer = strings.TrimSpace(strings.ToLower(answer))
	return answer == "y" || answer == "yes"
}

func jsonFlag(cmd *cobra.Command) (bool, error) {
	asJSON, err := cmd.Flags().GetBool("json")
	if err != nil {
		return false, fmt.Errorf("read json flag: %w", err)
	}
	return asJSON, nil
}

func printJSON(value any) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
