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

// LoginModel handles user login
type LoginModel struct {
	oauthServer *oauth.Server
	logger      *logger.Logger
	
	// Form inputs
	usernameInput textinput.Model
	passwordInput textinput.Model
	
	// UI state
	focused     int
	width       int
	height      int
	loading     bool
	error       string
	success     string
}

// NewLoginModel creates a new login model
func NewLoginModel(oauth *oauth.Server, logger *logger.Logger) *LoginModel {
	usernameInput := textinput.New()
	usernameInput.Placeholder = "Enter username"
	usernameInput.Focus()
	usernameInput.CharLimit = 50
	usernameInput.Width = 30
	
	passwordInput := textinput.New()
	passwordInput.Placeholder = "Enter password"
	passwordInput.EchoMode = textinput.EchoPassword
	passwordInput.EchoCharacter = '•'
	passwordInput.CharLimit = 100
	passwordInput.Width = 30
	
	return &LoginModel{
		oauthServer:   oauth,
		logger:        logger,
		usernameInput: usernameInput,
		passwordInput: passwordInput,
		focused:       0,
		width:         80,
		height:        24,
	}
}

// Init initializes the login model
func (m *LoginModel) Init() tea.Cmd {
	return textinput.Blink
}

// Update handles messages and updates the model
func (m *LoginModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
			m.focused = (m.focused + 1) % 2
			if m.focused == 0 {
				m.usernameInput.Focus()
				m.passwordInput.Blur()
			} else {
				m.usernameInput.Blur()
				m.passwordInput.Focus()
			}
		case "shift+tab", "up":
			m.focused = (m.focused - 1 + 2) % 2
			if m.focused == 0 {
				m.usernameInput.Focus()
				m.passwordInput.Blur()
			} else {
				m.usernameInput.Blur()
				m.passwordInput.Focus()
			}
		case "enter":
			if !m.loading {
				return m, m.attemptLogin()
			}
		}
		
	case loginResultMsg:
		m.loading = false
		if msg.err != nil {
			m.error = "Invalid username or password"
			m.success = ""
			m.logger.Error("Login attempt failed", "error", msg.err)
		} else {
			m.error = ""
			m.success = "Login successful!"
			m.logger.Info("User logged in via SSH TUI", "username", msg.username)
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
	
	m.passwordInput, cmd = m.passwordInput.Update(msg)
	cmds = append(cmds, cmd)
	
	return m, tea.Batch(cmds...)
}

// View renders the login form
func (m *LoginModel) View() string {
	title := lipgloss.NewStyle().
		Bold(true).
		Foreground(lipgloss.Color("205")).
		Render("🔐 Login to Maigo")
	
	var status string
	if m.loading {
		status = lipgloss.NewStyle().
			Foreground(lipgloss.Color("yellow")).
			Render("🔄 Authenticating...")
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

Password:
%s

%s

Press Enter to login, Tab to switch fields, Esc to go back`,
		m.usernameInput.View(),
		m.passwordInput.View(),
		func() string {
			if m.loading {
				return "⏳ Logging in..."
			}
			return "Press Enter to login"
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

// attemptLogin attempts to authenticate the user
func (m *LoginModel) attemptLogin() tea.Cmd {
	username := strings.TrimSpace(m.usernameInput.Value())
	password := strings.TrimSpace(m.passwordInput.Value())
	
	if username == "" || password == "" {
		return func() tea.Msg {
			return loginResultMsg{err: fmt.Errorf("username and password are required")}
		}
	}
	
	m.loading = true
	m.error = ""
	
	return func() tea.Msg {
		ctx := context.Background()
		tokens, err := m.oauthServer.AuthenticateUser(ctx, username, password)
		if err != nil {
			return loginResultMsg{err: err}
		}
		
		// Validate the access token to get user info
		claims, err := m.oauthServer.ValidateAccessToken(tokens.AccessToken)
		if err != nil {
			return loginResultMsg{err: err}
		}
		
		return loginResultMsg{
			userID:   claims.UserID,
			username: claims.Username,
			email:    claims.Email,
		}
	}
}

// loginResultMsg represents the result of a login attempt
type loginResultMsg struct {
	userID   int64
	username string
	email    string
	err      error
}
