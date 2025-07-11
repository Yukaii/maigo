package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/config"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/database/models"
)

// URLManagementModel handles URL creation and management
type URLManagementModel struct {
	db     *pgxpool.Pool
	config *config.Config
	logger *logger.Logger
	
	// UI state
	width    int
	height   int
	mode     string // "list", "create"
	selected int
	
	// Create URL form
	urlInput  textinput.Model
	loading   bool
	error     string
	success   string
	
	// URL list
	urls []models.URL
}

// NewURLManagementModel creates a new URL management model
func NewURLManagementModel(db *pgxpool.Pool, cfg *config.Config, logger *logger.Logger) *URLManagementModel {
	urlInput := textinput.New()
	urlInput.Placeholder = "Enter URL to shorten (e.g., https://example.com)"
	urlInput.CharLimit = 2048
	urlInput.Width = 50
	
	return &URLManagementModel{
		db:       db,
		config:   cfg,
		logger:   logger,
		width:    80,
		height:   24,
		mode:     "list",
		urlInput: urlInput,
	}
}

// Init initializes the URL management model
func (m *URLManagementModel) Init() tea.Cmd {
	return m.loadURLs()
}

// Update handles messages and updates the model
func (m *URLManagementModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q", "esc":
			if m.mode == "create" {
				m.mode = "list"
				m.urlInput.SetValue("")
				m.error = ""
				m.success = ""
			} else {
				return m, func() tea.Msg { return NavigateMsg{View: "dashboard"} }
			}
		case "n":
			if m.mode == "list" {
				m.mode = "create"
				m.urlInput.Focus()
				m.error = ""
				m.success = ""
			}
		case "r":
			if m.mode == "list" {
				return m, m.loadURLs()
			}
		case "up", "k":
			if m.mode == "list" && m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.mode == "list" && m.selected < len(m.urls)-1 {
				m.selected++
			}
		case "enter":
			if m.mode == "create" && !m.loading {
				return m, m.createURL()
			}
		}
		
	case urlsLoadedMsg:
		m.urls = msg.urls
		m.loading = false
		
	case urlCreatedMsg:
		m.loading = false
		if msg.err != nil {
			m.error = msg.err.Error()
			m.success = ""
		} else {
			m.error = ""
			m.success = fmt.Sprintf("URL shortened! Short code: %s", msg.shortCode)
			m.urlInput.SetValue("")
			// Reload URLs after creation
			cmds = append(cmds, m.loadURLs())
		}
	}
	
	// Update URL input
	if m.mode == "create" {
		var cmd tea.Cmd
		m.urlInput, cmd = m.urlInput.Update(msg)
		cmds = append(cmds, cmd)
	}
	
	return m, tea.Batch(cmds...)
}

// View renders the URL management interface
func (m *URLManagementModel) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render("🔗 URL Management")
	
	switch m.mode {
	case "create":
		return m.createView(title)
	default:
		return m.listView(title)
	}
}

// listView renders the URL list
func (m *URLManagementModel) listView(title string) string {
	var urlList string
	if len(m.urls) == 0 {
		urlList = lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("No URLs created yet. Press 'n' to create your first URL!")
	} else {
		var items []string
		for i, url := range m.urls {
			style := lipgloss.NewStyle().Padding(0, 1)
			if i == m.selected {
				style = style.Background(lipgloss.Color("205")).Foreground(lipgloss.Color("255"))
			}
			
			shortURL := fmt.Sprintf("%s://%s/%s", 
				func() string { if m.config.App.TLS { return "https" } else { return "http" } }(),
				m.config.App.Domain,
				url.ShortCode,
			)
			
			item := fmt.Sprintf("🔗 %s → %s (Hits: %d)", 
				shortURL, 
				url.TargetURL, 
				url.Hits,
			)
			items = append(items, style.Render(item))
		}
		urlList = lipgloss.JoinVertical(lipgloss.Left, items...)
	}
	
	list := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Height(10).
		Render(urlList)
	
	controls := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(`Controls:
n - Create new URL
r - Refresh list
↑/↓ or j/k - Navigate
q/Esc - Back to dashboard`)
	
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		title,
		"",
		list,
		"",
		controls,
	)
	
	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		content,
	)
}

// createView renders the URL creation form
func (m *URLManagementModel) createView(title string) string {
	var status string
	if m.loading {
		status = lipgloss.NewStyle().
			Foreground(lipgloss.Color("yellow")).
			Render("🔄 Creating short URL...")
	} else if m.error != "" {
		status = lipgloss.NewStyle().
			Foreground(lipgloss.Color("red")).
			Render("❌ " + m.error)
	} else if m.success != "" {
		status = lipgloss.NewStyle().
			Foreground(lipgloss.Color("green")).
			Render("✅ " + m.success)
	}
	
	form := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(fmt.Sprintf(`Enter URL to shorten:

%s

%s

Press Enter to create, Esc to cancel`,
		m.urlInput.View(),
		func() string {
			if m.loading {
				return "⏳ Creating..."
			}
			return "Press Enter to create short URL"
		}(),
	))
	
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		title,
		"",
		form,
		"",
		status,
	)
	
	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		content,
	)
}

// loadURLs loads the user's URLs
func (m *URLManagementModel) loadURLs() tea.Cmd {
	return func() tea.Msg {
		// For now, return empty list
		// TODO: Implement actual URL loading from database with user filtering
		return urlsLoadedMsg{urls: []models.URL{}}
	}
}

// createURL creates a new short URL
func (m *URLManagementModel) createURL() tea.Cmd {
	url := strings.TrimSpace(m.urlInput.Value())
	
	if url == "" {
		return func() tea.Msg {
			return urlCreatedMsg{err: fmt.Errorf("URL is required")}
		}
	}
	
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return func() tea.Msg {
			return urlCreatedMsg{err: fmt.Errorf("URL must start with http:// or https://")}
		}
	}
	
	m.loading = true
	m.error = ""
	
	return func() tea.Msg {
		// For now, return a placeholder
		// TODO: Implement actual URL creation logic
		return urlCreatedMsg{shortCode: "abc123"}
	}
}

// Message types for URL management
type urlsLoadedMsg struct {
	urls []models.URL
}

type urlCreatedMsg struct {
	shortCode string
	err       error
}
