package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// DashboardModel represents the user dashboard
type DashboardModel struct {
	db          *pgxpool.Pool
	oauthServer *oauth.Server
	logger      *logger.Logger
	
	// UI state
	width     int
	height    int
	selected  int
	
	// Data
	urlCount  int
	hitCount  int64
	loading   bool
}

// NewDashboardModel creates a new dashboard model
func NewDashboardModel(db *pgxpool.Pool, oauth *oauth.Server, logger *logger.Logger) *DashboardModel {
	return &DashboardModel{
		db:          db,
		oauthServer: oauth,
		logger:      logger,
		width:       80,
		height:      24,
		selected:    0,
		loading:     true,
	}
}

// Init initializes the dashboard model
func (m *DashboardModel) Init() tea.Cmd {
	return m.loadStats()
}

// Update handles messages and updates the model
func (m *DashboardModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q", "esc":
			return m, func() tea.Msg { return NavigateMsg{View: "welcome"} }
		case "up", "k":
			if m.selected > 0 {
				m.selected--
			}
		case "down", "j":
			if m.selected < 2 { // 3 menu items (0, 1, 2)
				m.selected++
			}
		case "enter", " ":
			switch m.selected {
			case 0: // Manage URLs
				return m, func() tea.Msg { return NavigateMsg{View: "urls"} }
			case 1: // Refresh stats
				return m, m.loadStats()
			case 2: // Logout
				return m, func() tea.Msg { return NavigateMsg{View: "welcome"} }
			}
		}
		
	case statsLoadedMsg:
		m.loading = false
		m.urlCount = msg.urlCount
		m.hitCount = msg.hitCount
		
	case statsErrorMsg:
		m.loading = false
		m.logger.Error("Failed to load dashboard stats", "error", msg.err)
	}
	
	return m, nil
}

// View renders the dashboard
func (m *DashboardModel) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render("📊 Maigo Dashboard")
	
	var stats string
	if m.loading {
		stats = lipgloss.NewStyle().
			Foreground(lipgloss.Color("yellow")).
			Render("🔄 Loading statistics...")
	} else {
		stats = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(1, 2).
			Render(fmt.Sprintf(`📈 Your Statistics

🔗 URLs Created: %d
👆 Total Clicks: %d
⚡ Active URLs: %d`,
			m.urlCount,
			m.hitCount,
			m.urlCount, // Assuming all URLs are active for now
		))
	}
	
	menuItems := []string{
		"🔗 Manage URLs",
		"🔄 Refresh Stats",
		"🚪 Logout",
	}
	
	var menuOptions []string
	for i, item := range menuItems {
		style := lipgloss.NewStyle().Padding(0, 2)
		if i == m.selected {
			style = style.Background(lipgloss.Color("205")).Foreground(lipgloss.Color("255"))
		}
		menuOptions = append(menuOptions, style.Render(item))
	}
	
	menu := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(1, 2).
		Render(fmt.Sprintf(`Navigation:

%s

Use ↑/↓ or j/k to navigate, Enter to select, q to quit`,
		lipgloss.JoinVertical(lipgloss.Left, menuOptions...),
	))
	
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		title,
		"",
		stats,
		"",
		menu,
	)
	
	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		content,
	)
}

// loadStats loads user statistics
func (m *DashboardModel) loadStats() tea.Cmd {
	return func() tea.Msg {
		// For now, return placeholder data
		// TODO: Implement actual stats loading from database
		return statsLoadedMsg{
			urlCount: 5,
			hitCount: 127,
		}
	}
}

// Message types for stats loading
type statsLoadedMsg struct {
	urlCount int
	hitCount int64
}

type statsErrorMsg struct {
	err error
}
