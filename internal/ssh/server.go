package ssh

import (
	"context"
	"fmt"
	"os"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/ssh"
	"github.com/charmbracelet/wish"
	"github.com/charmbracelet/wish/bubbletea"
	"github.com/charmbracelet/wish/logging"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
	"github.com/yukaii/maigo/internal/ssh/tui"
)

// Server represents the SSH TUI server
type Server struct {
	config      *config.Config
	db          *pgxpool.Pool
	logger      *logger.Logger
	oauthServer *oauth.Server
	sshServer   *ssh.Server
}

// NewServer creates a new SSH TUI server
func NewServer(cfg *config.Config, db *pgxpool.Pool, log *logger.Logger) *Server {
	return &Server{
		config:      cfg,
		db:          db,
		logger:      log,
		oauthServer: oauth.NewServer(db, cfg),
	}
}

// Start starts the SSH TUI server with the provided context
func (s *Server) Start(ctx context.Context) error {
	s.logger.Info("Starting SSH TUI server", "port", s.config.SSH.Port)

	// Create SSH server with middleware
	sshServer, err := wish.NewServer(
		wish.WithAddress(fmt.Sprintf(":%d", s.config.SSH.Port)),
		wish.WithHostKeyPath(s.config.SSH.HostKeyPath),
		wish.WithMiddleware(
			bubbletea.Middleware(s.teaHandler),
			logging.Middleware(),
		),
	)
	if err != nil {
		return fmt.Errorf("failed to create SSH server: %w", err)
	}

	s.sshServer = sshServer

	// Start server in a goroutine
	go func() {
		if err := sshServer.ListenAndServe(); err != nil && err != ssh.ErrServerClosed {
			s.logger.Error("SSH server error", "error", err)
		}
	}()

	s.logger.Info("SSH TUI server started successfully")

	// Wait for shutdown signal from context
	<-ctx.Done()
	s.logger.Info("SSH TUI server shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return sshServer.Shutdown(shutdownCtx)
}

// Stop gracefully stops the SSH server
func (s *Server) Stop() error {
	if s.sshServer == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return s.sshServer.Shutdown(ctx)
}

// teaHandler returns the appropriate Bubble Tea model based on the session
func (s *Server) teaHandler(sshSession ssh.Session) (tea.Model, []tea.ProgramOption) {
	// Get client information
	clientAddr := sshSession.RemoteAddr().String()
	user := sshSession.User()
	
	s.logger.Info("New SSH session", "user", user, "addr", clientAddr)

	// Create and return the main TUI model
	model := tui.NewMainModel(s.db, s.config, s.oauthServer, s.logger, sshSession)
	return model, []tea.ProgramOption{tea.WithAltScreen()}
}

// GenerateHostKey generates a new host key if it doesn't exist
func (s *Server) GenerateHostKey() error {
	hostKeyPath := s.config.SSH.HostKeyPath
	
	// Check if host key already exists
	if _, err := os.Stat(hostKeyPath); err == nil {
		s.logger.Info("Host key already exists", "path", hostKeyPath)
		return nil
	}

	// Generate new host key
	s.logger.Info("Generating new SSH host key", "path", hostKeyPath)
	
	// Create directory if it doesn't exist
	if err := os.MkdirAll(fmt.Sprintf("%s/../", hostKeyPath), 0700); err != nil {
		return fmt.Errorf("failed to create host key directory: %w", err)
	}

	// For now, just log the need to generate a key
	// TODO: Implement proper host key generation
	s.logger.Info("Host key generation needs to be implemented")

	return nil
}

// GetServerInfo returns server information for display
func (s *Server) GetServerInfo() map[string]interface{} {
	var addr string
	if s.sshServer != nil {
		addr = s.config.SSHAddr()
	}

	return map[string]interface{}{
		"address":     addr,
		"port":        s.config.SSH.Port,
		"host_key":    s.config.SSH.HostKeyPath,
		"status":      "running",
		"connections": 0, // TODO: Implement connection tracking
	}
}
