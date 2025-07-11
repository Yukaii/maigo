package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/ssh"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// Model interface for all TUI models
type Model interface {
	tea.Model
}

// MainModel represents the main TUI interface
type MainModel struct {
	db          *pgxpool.Pool
	config      *config.Config
	oauthServer *oauth.Server
	logger      *logger.Logger
	session     ssh.Session
	
	// UI state
	currentView string
	width       int
	height      int
	
	// Authentication state
	isAuthenticated bool
	currentUser     *UserInfo
	
	// Sub-models
	loginModel    *LoginModel
	registerModel *RegisterModel
	dashModel     *DashboardModel
	urlModel      *URLManagementModel
}

// UserInfo holds authenticated user information
type UserInfo struct {
	ID       int64
	Username string
	Email    string
}

// NewMainModel creates a new main TUI model
func NewMainModel(db *pgxpool.Pool, cfg *config.Config, oauth *oauth.Server, logger *logger.Logger, session ssh.Session) MainModel {
	m := MainModel{
		db:          db,
		config:      cfg,
		oauthServer: oauth,
		logger:      logger,
		session:     session,
		currentView: "welcome",
		width:       80,
		height:      24,
	}
	
	// Initialize sub-models
	m.loginModel = NewLoginModel(oauth, logger)
	m.registerModel = NewRegisterModel(oauth, logger)
	m.dashModel = NewDashboardModel(db, oauth, logger)
	m.urlModel = NewURLManagementModel(db, cfg, logger)
	
	return m
}

// Init initializes the model
func (m MainModel) Init() tea.Cmd {
	return tea.SetWindowTitle("Maigo - URL Shortener")
}

// Update handles messages and updates the model
func (m MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
		
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.currentView == "welcome" || !m.isAuthenticated {
				return m, tea.Quit
			}
			// Navigate back or logout
			if m.isAuthenticated {
				m.currentView = "dashboard"
				return m, nil
			}
		case "1":
			if m.currentView == "welcome" {
				m.currentView = "login"
				return m, nil
			}
		case "2":
			if m.currentView == "welcome" {
				m.currentView = "register"
				return m, nil
			}
		case "esc":
			if m.isAuthenticated {
				m.currentView = "dashboard"
			} else {
				m.currentView = "welcome"
			}
			return m, nil
		}
		
	case AuthSuccessMsg:
		m.isAuthenticated = true
		m.currentUser = &UserInfo{
			ID:       msg.UserID,
			Username: msg.Username,
			Email:    msg.Email,
		}
		m.currentView = "dashboard"
		m.logger.Info("User authenticated via SSH TUI", "username", msg.Username)
		return m, nil
		
	case NavigateMsg:
		m.currentView = msg.View
		return m, nil
	}
	
	// Handle view-specific updates
	switch m.currentView {
	case "login":
		model, cmd := m.loginModel.Update(msg)
		m.loginModel = model.(*LoginModel)
		return m, cmd
	case "register":
		model, cmd := m.registerModel.Update(msg)
		m.registerModel = model.(*RegisterModel)
		return m, cmd
	case "dashboard":
		if m.isAuthenticated {
			model, cmd := m.dashModel.Update(msg)
			m.dashModel = model.(*DashboardModel)
			return m, cmd
		}
	case "urls":
		if m.isAuthenticated {
			model, cmd := m.urlModel.Update(msg)
			m.urlModel = model.(*URLManagementModel)
			return m, cmd
		}
	}
	
	return m, nil
}

// View renders the current view
func (m MainModel) View() string {
	switch m.currentView {
	case "welcome":
		return m.welcomeView()
	case "login":
		return m.loginModel.View()
	case "register":
		return m.registerModel.View()
	case "dashboard":
		if m.isAuthenticated {
			return m.dashModel.View()
		}
		return m.welcomeView()
	case "urls":
		if m.isAuthenticated {
			return m.urlModel.View()
		}
		return m.welcomeView()
	default:
		return m.welcomeView()
	}
}

// welcomeView renders the welcome screen
func (m MainModel) welcomeView() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render("🔗 Maigo URL Shortener")
	
	subtitle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render("Terminal-based URL shortening service")
	
	menu := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(`Welcome to Maigo! Please choose an option:

1. Login to existing account
2. Register new account
q. Quit

Use arrow keys to navigate, Enter to select, Ctrl+C to quit.`)
	
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Render("Connected via SSH • Press 'q' to quit")
	
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		title,
		"",
		subtitle,
		"",
		"",
		menu,
		"",
		"",
		footer,
	)
	
	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		content,
	)
}

// Message types for internal communication
type AuthSuccessMsg struct {
	UserID   int64
	Username string
	Email    string
}

type NavigateMsg struct {
	View string
}
