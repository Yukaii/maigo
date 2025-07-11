package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/yukaii/maigo/internal/logger"
	"github.com/yukaii/maigo/internal/oauth"
)

// RegisterModel handles user registration
type RegisterModel struct {
	oauthServer *oauth.Server
	logger      *logger.Logger
	
	// Form inputs
	usernameInput textinput.Model
	emailInput    textinput.Model
	passwordInput textinput.Model
	
	// UI state
	focused     int
	width       int
	height      int
	loading     bool
	error       string
	success     string
}

// NewRegisterModel creates a new register model
func NewRegisterModel(oauth *oauth.Server, logger *logger.Logger) *RegisterModel {
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Enter username (3-50 chars)"
	usernameInput.Focus()
	usernameInput.CharLimit = 50
	usernameInput.Width = 30
	
	emailInput := textinput.New()
	emailInput.Placeholder = "Enter email address"
	emailInput.CharLimit = 100
	emailInput.Width = 30
	
	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter password (min 6 chars)"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 30
	
	return &RegisterModel{
		oauthServer:   oauth,
		logger:        logger,
		usernameInput: usernameInput,
		emailInput:    emailInput,
		passwordInput: passwordInput,
		focused:       0,
		width:         80,
		height:        24,
	}
}

// Init initializes the register model
func (m *RegisterModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages and updates the model
func (m *RegisterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "esc":
			return m, func() tea.Msg { return NavigateMsg{View: "welcome"} }
		case "tab", "down":
			m.focused = (m.focused + 1) % 3
			m.updateFocus()
		case "shift+tab", "up":
			m.focused = (m.focused - 1 + 3) % 3
			m.updateFocus()
		case "enter":
			if !m.loading {
				return m, m.attemptRegister()
			}
		}
		
	case registerResultMsg:
		m.loading = false
		if msg.err != nil {
			m.error = msg.err.Error()
			m.success = ""
			m.logger.Error("Registration attempt failed", "error", msg.err)
		} else {
			m.error = ""
			m.success = "Registration successful! Logging you in..."
			m.logger.Info("User registered via SSH TUI", "username", msg.username)
			return m, func() tea.Msg {
				return AuthSuccessMsg{
					UserID:   msg.userID,
					Username: msg.username,
					Email:    msg.email,
				}
			}
		}
	}
	
	// Update inputs
	var cmd tea.Cmd
	m.usernameInput, cmd = m.usernameInput.Update(msg)
	cmds = append(cmds, cmd)
	
	m.emailInput, cmd = m.emailInput.Update(msg)
	cmds = append(cmds, cmd)
	
	m.passwordInput, cmd = m.passwordInput.Update(msg)
	cmds = append(cmds, cmd)
	
	return m, tea.Batch(cmds...)
}

// View renders the registration form
func (m *RegisterModel) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render("📝 Register for Maigo")
	
	var status string
	if m.loading {
		status = lipgloss.NewStyle().
			Foreground(lipgloss.Color("yellow")).
			Render("🔄 Creating account...")
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
		Render(fmt.Sprintf(`Username:
%s

Email:
%s

Password:
%s

%s

Press Enter to register, Tab to switch fields, Esc to go back`,
		m.usernameInput.View(),
		m.emailInput.View(),
		m.passwordInput.View(),
		func() string {
			if m.loading {
				return "⏳ Creating account..."
			}
			return "Press Enter to register"
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

// updateFocus updates the focus state of input fields
func (m *RegisterModel) updateFocus() {
	m.usernameInput.Blur()
	m.emailInput.Blur()
	m.passwordInput.Blur()
	
	switch m.focused {
	case 0:
		m.usernameInput.Focus()
	case 1:
		m.emailInput.Focus()
	case 2:
		m.passwordInput.Focus()
	}
}

// attemptRegister attempts to register a new user
func (m *RegisterModel) attemptRegister() tea.Cmd {
	username := strings.TrimSpace(m.usernameInput.Value())
	email := strings.TrimSpace(m.emailInput.Value())
	password := strings.TrimSpace(m.passwordInput.Value())
	
	// Basic validation
	if username == "" || email == "" || password == "" {
		return func() tea.Msg {
			return registerResultMsg{err: fmt.Errorf("all fields are required")}
		}
	}
	
	if len(username) < 3 {
		return func() tea.Msg {
			return registerResultMsg{err: fmt.Errorf("username must be at least 3 characters")}
		}
	}
	
	if len(password) < 6 {
		return func() tea.Msg {
			return registerResultMsg{err: fmt.Errorf("password must be at least 6 characters")}
		}
	}
	
	if !strings.Contains(email, "@") {
		return func() tea.Msg {
			return registerResultMsg{err: fmt.Errorf("please enter a valid email address")}
		}
	}
	
	m.loading = true
	m.error = ""
	
	return func() tea.Msg {
		ctx := context.Background()
		user, err := m.oauthServer.RegisterUser(ctx, username, email, password)
		if err != nil {
			return registerResultMsg{err: err}
		}
		
		return registerResultMsg{
			userID:   user.ID,
			username: user.Username,
			email:    user.Email,
		}
	}
}

// registerResultMsg represents the result of a registration attempt
type registerResultMsg struct {
	userID   int64
	username string
	email    string
	err      error
}
