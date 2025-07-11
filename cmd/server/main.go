package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/database"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/server"
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

	log.Info("Starting Maigo server", 
		"version", "dev",
		"config", cfg.ServerAddr(),
	)

	// Set Gin mode based on debug setting
	if !cfg.App.Debug {
		gin.SetMode(gin.ReleaseMode)
	}

	// Initialize database
	db, err := database.NewConnection(cfg.DatabaseURL())
	if err != nil {
		log.Error("Failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	log.Info("Connected to database", "host", cfg.Database.Host, "port", cfg.Database.Port)

	// Run database migrations
	if err := database.RunMigrations(db); err != nil {
		log.Error("Failed to run database migrations", "error", err)
		os.Exit(1)
	}

	log.Info("Database migrations completed")

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
			os.Exit(1)
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
		os.Exit(1)
	}

	log.Info("Server exited")
}
