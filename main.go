package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
)

// Styles
var (
	styleLoginBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(1, 2)

	styleChatBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("63")).
		Padding(0, 1)

	styleUserMessage = lipgloss.NewStyle().
		Foreground(lipgloss.Color("229"))

	styleBotMessage = lipgloss.NewStyle().
		Foreground(lipgloss.Color("86"))

	styleCommandBar = lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Padding(0, 1)

	
)

type (
	loginSuccessMsg   struct{}
	resetSuccessMsg   struct{}
	disconnectMsg     struct{}
	autoLoginMsg      struct{ username, password, serverURL, sessionCookie string; useSession bool }
	notifMsg          string
	statusMsg         string
	serverResponseMsg string
	errorMsg          struct{ error }
	serverResponse    struct {
		Response string `json:"response"`
	}
	tasksResponse struct {
		BackgroundTasks []notification `json:"background_tasks"`
		ID              int            `json:"id"`
	}
	notification struct {
		Module string `json:"module"`
		Status string `json:"status"`
	}
	statusResponse struct {
		Modules []moduleStatus `json:"modules"`
	}
	moduleStatus struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	credentials struct {
		Username      string `json:"username"`
		Password      string `json:"password"`
		ServerURL     string `json:"server_url"`
		SessionCookie string `json:"session_cookie"`
	}
)



const (
	viewConnecting = iota
	viewLogin
	viewChat
)

type model struct {
	currentView     int
	spinner         spinner.Model
	usernameInput   textinput.Model
	passwordInput   textinput.Model
	serverInput     textinput.Model
	viewport        viewport.Model
	chatInput       textinput.Model
	messages        []string
	client          *http.Client
	err             error
	width, height   int
	mdRenderer      *glamour.TermRenderer
	serverURL       string
	history         []string
	historyIndex    int
	currentInput    string
}

func initialModel() model {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Minute,
	}

	username := textinput.New()
	username.Placeholder = "Username"
	username.Focus()
	username.Width = 20

	password := textinput.New()
	password.Placeholder = "Password"
	password.EchoMode = textinput.EchoPassword
	password.Width = 20

	server := textinput.New()
	server.Placeholder = "Server URL"
	server.Width = 20

	chat := textinput.New()
	chat.Placeholder = ""

	mdRenderer, _ := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(0),
	)

	// Load history
	history, err := loadHistory()
	if err != nil {
		history = []string{}
	}

	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	return model{
		currentView:   viewConnecting,
		spinner:       s,
		usernameInput: username,
		passwordInput: password,
		serverInput:   server,
		chatInput:     chat,
		client:        client,
		mdRenderer:    mdRenderer,
		history:       history,
		historyIndex:  len(history),
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(m.spinner.Tick, checkAuth)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.err != nil {
		if _, ok := msg.(tea.KeyMsg); ok {
			return m, tea.Quit
		}
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		commandBarHeight := lipgloss.Height(m.commandBarView())
		verticalMarginHeight := headerHeight + footerHeight + commandBarHeight

		if m.currentView == viewChat {
			m.viewport.Width = m.width
			m.viewport.Height = m.height - verticalMarginHeight
			m.viewport.YPosition = headerHeight
			m.viewport.SetContent(m.renderMessages())
		}

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		case tea.KeyEnter:
							if m.currentView == viewLogin {
					m.currentView = viewConnecting
					m.serverInput.SetValue(strings.TrimSuffix(m.serverInput.Value(), "/"))
					return m, tea.Batch(m.spinner.Tick, login(m))
				} else if m.currentView == viewChat {
				userInput := m.chatInput.Value()
				m.chatInput.Reset()

				if strings.TrimSpace(userInput) == "" {
					return m, nil
				}
				
				// Reset history navigation
				m.historyIndex = len(m.history)
				m.currentInput = ""

				if strings.HasPrefix(userInput, "/") {
					return m.handleCommand(userInput)
				}

				m.messages = append(m.messages, "You: "+userInput)
				m.viewport.SetContent(m.renderMessages())
				m.viewport.GotoBottom()
				return m, sendMessage(m, userInput)
			}
		case tea.KeyUp:
			if m.currentView == viewChat && m.chatInput.Focused() {
				if m.historyIndex > 0 {
					// Save current input if we're at the end of history
					if m.historyIndex == len(m.history) {
						m.currentInput = m.chatInput.Value()
					}
					m.historyIndex--
					m.chatInput.SetValue(m.history[m.historyIndex])
					m.chatInput.CursorEnd()
				}
				return m, nil
			}
		case tea.KeyDown:
			if m.currentView == viewChat && m.chatInput.Focused() {
				if m.historyIndex < len(m.history) {
					m.historyIndex++
					if m.historyIndex == len(m.history) {
						// Restore current input
						m.chatInput.SetValue(m.currentInput)
					} else {
						m.chatInput.SetValue(m.history[m.historyIndex])
					}
					m.chatInput.CursorEnd()
				}
				return m, nil
			}
		case tea.KeyTab:
			if m.currentView == viewLogin {
				if m.usernameInput.Focused() {
					m.usernameInput.Blur()
					m.passwordInput.Focus()
				} else if m.passwordInput.Focused() {
					m.passwordInput.Blur()
					m.serverInput.Focus()
				} else {
					m.serverInput.Blur()
					m.usernameInput.Focus()
				}
			}
		}
	case autoLoginMsg:
		if msg.username != "" && msg.serverURL != "" {
			m.usernameInput.SetValue(msg.username)
			m.passwordInput.SetValue(msg.password)
			m.serverInput.SetValue(msg.serverURL)
			m.serverURL = msg.serverURL
			
			if msg.useSession && msg.sessionCookie != "" {
				// Use session cookie for authentication
				return m, sessionLogin(m, msg.sessionCookie)
			} else {
				// Use username/password for authentication
				return m, login(m)
			}
		} else {
			m.currentView = viewLogin
			return m, nil
		}

	case loginSuccessMsg:
		m.err = nil
		m.currentView = viewChat
		m.chatInput.Focus()
		m.serverURL = m.serverInput.Value()
		headerHeight := lipgloss.Height(m.headerView())
		footerHeight := lipgloss.Height(m.footerView())
		commandBarHeight := lipgloss.Height(m.commandBarView())
		verticalMarginHeight := headerHeight + footerHeight + commandBarHeight
		m.viewport = viewport.New(m.width, m.height-verticalMarginHeight)
		m.viewport.YPosition = headerHeight
		m.messages = []string{"Tom: Welcome! Type /help for a list of commands."}
		m.viewport.SetContent(m.renderMessages())
		return m, tea.Batch(textinput.Blink, resetCmd(m))

	case disconnectMsg:
		m.currentView = viewLogin
		m.usernameInput.Reset()
		m.passwordInput.Reset()
		m.serverInput.Reset()
		m.messages = nil
		m.usernameInput.Focus()
		return m, textinput.Blink

	case serverResponseMsg:
		m.messages = append(m.messages, "Tom: "+string(msg))
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		
		// Reload history to update in-memory history
		if history, err := loadHistory(); err == nil {
			m.history = history
			m.historyIndex = len(m.history)
		}
		
		return m, nil

	case resetSuccessMsg:
		m.messages = []string{"Chat history has been reset."}
		m.viewport.SetContent(m.renderMessages())
		return m, nil

	case statusMsg:
		m.messages = append(m.messages, "Tom: # Modules Status\n"+string(msg))
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		return m, nil

	case notifMsg:
		if string(msg) == "" {
			m.messages = append(m.messages, "Tom: No new notifications.")
		} else {
			m.messages = append(m.messages, "Tom: # Notifications\n"+string(msg))
		}
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		return m, nil

	case errorMsg:
		m.err = msg
		if m.currentView == viewConnecting {
			return m, tea.Batch(m.spinner.Tick, func() tea.Msg {
				time.Sleep(5 * time.Second)
				return checkAuth()
			})
		}
		return m, nil
	}

	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch m.currentView {
	case viewConnecting:
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	case viewLogin:
		m.usernameInput, cmd = m.usernameInput.Update(msg)
		cmds = append(cmds, cmd)
		m.passwordInput, cmd = m.passwordInput.Update(msg)
		cmds = append(cmds, cmd)
		m.serverInput, cmd = m.serverInput.Update(msg)
		cmds = append(cmds, cmd)
	case viewChat:
		m.viewport, cmd = m.viewport.Update(msg)
		cmds = append(cmds, cmd)
		m.chatInput, cmd = m.chatInput.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *model) handleCommand(cmd string) (tea.Model, tea.Cmd) {
	switch cmd {
	case "/quit", "/exit":
		return m, tea.Quit
	case "/reset":
		return m, resetCmd(*m)
	case "/notif":
		return m, fetchNotifsCmd(*m)
	case "/disconnect":
		return m, disconnect
	case "/help":
		m.messages = append(m.messages, "Available commands: /quit, /reset, /notif, /disconnect, /help, /status")
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		return m, nil
	case "/status":
		return m, fetchStatusCmd(*m)
	default:
		m.messages = append(m.messages, fmt.Sprintf("Unknown command: %s", cmd))
		m.viewport.SetContent(m.renderMessages())
		m.viewport.GotoBottom()
		return m, nil
	}
}



func (m model) renderMessages() string {
	var renderedMessages []string
	contentWidth := m.viewport.Width - styleChatBox.GetHorizontalFrameSize()
	for _, msg := range m.messages {
		style := styleBotMessage
		prefix := ""
		messageContent := msg

		if strings.HasPrefix(msg, "You: ") {
			style = styleUserMessage
			prefix = "You: "
			messageContent = strings.TrimPrefix(msg, prefix)
		} else if strings.HasPrefix(msg, "Tom: ") {
			prefix = "Tom: "
			messageContent = strings.TrimPrefix(msg, prefix)
			// Render Markdown for bot messages
			rendered, err := m.mdRenderer.Render(messageContent)
			if err != nil {
				// Fallback to plain text if rendering fails
				rendered = messageContent
				log.Printf("Error rendering markdown: %v", err)
			}
			messageContent = rendered
		} else if strings.HasPrefix(msg, "Notification: ") {
			prefix = "Notification: "
			messageContent = strings.TrimPrefix(msg, prefix)
		} else if strings.HasPrefix(msg, "System: ") {
			prefix = "System: "
			messageContent = strings.TrimPrefix(msg, prefix)
		}

		renderedMessages = append(renderedMessages, style.Copy().Width(contentWidth).Render(prefix+messageContent))
	}
	return strings.Join(renderedMessages, "\n\n")
}

func (m model) View() string {
	if m.err != nil && m.currentView != viewConnecting {
		return fmt.Sprintf("\nError: %v\n\nPress any key to quit.", m.err)
	}

	if m.currentView == viewConnecting {
		var s strings.Builder
		s.WriteString(m.spinner.View())
		s.WriteString(" Connecting to server...")
		if m.err != nil {
            s.WriteString("\n\nConnection failed. Retrying...")
        }
		ui := styleLoginBox.Render(s.String())
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, ui)
	}

	if m.currentView == viewLogin {
		var b strings.Builder
		b.WriteString("Login to Tom\n\n")
		b.WriteString(m.usernameInput.View())
		b.WriteString("\n")
		b.WriteString(m.passwordInput.View())
		b.WriteString("\n")
		b.WriteString(m.serverInput.View())
		b.WriteString("\n\n(tab to switch, enter to login)")
		ui := styleLoginBox.Render(b.String())
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, ui)
	}

	return lipgloss.JoinVertical(lipgloss.Left, m.headerView(), m.viewport.View(), m.footerView(), m.commandBarView())
}

func (m model) headerView() string {
	title := styleChatBox.Render(" Tom ")
	return lipgloss.Place(m.width, lipgloss.Height(title), lipgloss.Center, lipgloss.Top, title)
}

func (m model) footerView() string {
	return styleChatBox.Copy().Width(m.width - 3).Render(m.chatInput.View())
}

func (m model) commandBarView() string {
	return styleCommandBar.Copy().Width(m.width).Render("Commands: /quit, /reset, /notif, /disconnect, /help, /status")
}

func getAuthFilePath() (string, error) {
	usr, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr, ".tom", "auth"), nil
}

func getHistoryFilePath() (string, error) {
	usr, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(usr, ".tom", "history"), nil
}

func saveHistory(prompt string) error {
	historyPath, err := getHistoryFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(historyPath), 0700); err != nil {
		return err
	}

	// Read existing history
	history, err := loadHistory()
	if err != nil {
		history = []string{}
	}

	// Add new prompt to history (avoid duplicates)
	if len(history) == 0 || history[len(history)-1] != prompt {
		history = append(history, prompt)
	}

	// Keep only last 1000 commands
	if len(history) > 1000 {
		history = history[len(history)-1000:]
	}

	// Write history back to file
	data := strings.Join(history, "\n")
	return os.WriteFile(historyPath, []byte(data), 0600)
}

func loadHistory() ([]string, error) {
	historyPath, err := getHistoryFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(historyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return []string{}, nil
		}
		return nil, err
	}

	if len(data) == 0 {
		return []string{}, nil
	}

	history := strings.Split(string(data), "\n")
	// Remove empty lines
	var cleanHistory []string
	for _, line := range history {
		if strings.TrimSpace(line) != "" {
			cleanHistory = append(cleanHistory, line)
		}
	}

	return cleanHistory, nil
}

func saveCredentials(username, password, serverURL, sessionCookie string) error {
	authPath, err := getAuthFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(authPath), 0700); err != nil {
		return err
	}

	creds := credentials{
		Username:      username,
		Password:      password,
		ServerURL:     serverURL,
		SessionCookie: sessionCookie,
	}

	data, err := json.Marshal(creds)
	if err != nil {
		return err
	}

	encodedData := base64.StdEncoding.EncodeToString(data)

	return os.WriteFile(authPath, []byte(encodedData), 0600)
}

func loadCredentials() (string, string, string, string, error) {
	authPath, err := getAuthFilePath()
	if err != nil {
		return "", "", "", "", err
	}

	encodedData, err := os.ReadFile(authPath)
	if err != nil {
		return "", "", "", "", err
	}

	decodedData, err := base64.StdEncoding.DecodeString(string(encodedData))
	if err != nil {
		return "", "", "", "", err	
	}

	var creds credentials
	if err := json.Unmarshal(decodedData, &creds); err != nil {
		return "", "", "", "", err
	}

	return creds.Username, creds.Password, creds.ServerURL, creds.SessionCookie, nil
}

func deleteCredentials() error {
	authPath, err := getAuthFilePath()
	if err != nil {
		return err
	}
	return os.Remove(authPath)
}

func validateSessionCookie(serverURL, sessionCookie string, client *http.Client) bool {
	if sessionCookie == "" {
		return false
	}
	
	// Create a test request to verify the session cookie
	req, err := http.NewRequest("GET", serverURL+"/tasks", nil)
	if err != nil {
		return false
	}
	
	// Set the session cookie
	req.Header.Set("Cookie", sessionCookie)
	
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// If we get a 200 response, the session is valid
	return resp.StatusCode == http.StatusOK
}

func checkAuth() tea.Msg {
	username, password, serverURL, sessionCookie, err := loadCredentials()
	if err != nil {
		return autoLoginMsg{} // No credentials, stay on login view
	}
	
	// Create a temporary client to test the session cookie
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 5 * time.Minute,
	}
	
	// First, try to use the session cookie if it exists
	if sessionCookie != "" && validateSessionCookie(serverURL, sessionCookie, client) {
		return autoLoginMsg{username, password, serverURL, sessionCookie, true}
	}
	
	// If session cookie is invalid or doesn't exist, use username/password
	return autoLoginMsg{username, password, serverURL, sessionCookie, false}
}

func disconnect() tea.Msg {
	if err := deleteCredentials(); err != nil {
		return errorMsg{fmt.Errorf("failed to disconnect: %w", err)}
	}
	return disconnectMsg{}
}

func sessionLogin(m model, sessionCookie string) tea.Cmd {
	return func() tea.Msg {
		// Set the session cookie in the client
		if sessionCookie != "" {
			req, err := http.NewRequest("GET", m.serverURL+"/tasks", nil)
			if err != nil {
				return errorMsg{err}
			}
			req.Header.Set("Cookie", sessionCookie)
			
			// Test the session cookie
			resp, err := m.client.Do(req)
			if err != nil {
				return errorMsg{err}
			}
			defer resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				return loginSuccessMsg{}
			}
		}
		
		// If session cookie is invalid, fall back to username/password login
		return login(m)()
	}
}

func login(m model) tea.Cmd {
	return func() tea.Msg {
		serverURL := m.serverInput.Value()
		if serverURL == "" {
			return errorMsg{fmt.Errorf("server URL is required")}
		}

		resp, err := m.client.PostForm(serverURL+"/login", url.Values{
			"username": {m.usernameInput.Value()},
			"password": {m.passwordInput.Value()},
		})
		if err != nil {
			return errorMsg{err}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			bodyBytes, _ := io.ReadAll(resp.Body)
			return errorMsg{fmt.Errorf("login failed: %s (%s)", resp.Status, string(bodyBytes))}
		}

		// Extract session cookie from response
		sessionCookie := ""
		for _, cookie := range resp.Cookies() {
			if cookie.Name == "session_id" {
				sessionCookie = cookie.String()
				break
			}
		}

		if err := saveCredentials(m.usernameInput.Value(), m.passwordInput.Value(), serverURL, sessionCookie); err != nil {
			return errorMsg{fmt.Errorf("failed to save credentials: %w", err)}
		}

		return loginSuccessMsg{}
	}
}

func sendMessage(m model, userInput string) tea.Cmd {
	return func() tea.Msg {
		// Save to history
		if userInput != "" {
			if err := saveHistory(userInput); err != nil {
				log.Printf("Failed to save history: %v", err)
			}
		}

		postBody, _ := json.Marshal(map[string]interface{}{
			"request":     userInput,
			"tts":         true,
			"client_type": "tui",
		})

		req, err := http.NewRequest("POST", m.serverURL+"/process", bytes.NewBuffer(postBody))
		if err != nil {
			return errorMsg{err}
		}
		req.Header.Set("Content-Type", "application/json")

		resp, err := m.client.Do(req)
		if err != nil {
			return errorMsg{err}
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 500 && resp.StatusCode < 600 {
			body, _ := io.ReadAll(resp.Body)
			errorText := fmt.Sprintf("Error %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			return serverResponseMsg(errorText)
		}

		if resp.StatusCode != http.StatusOK {
			return errorMsg{fmt.Errorf("failed to send message: %s", resp.Status)}
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errorMsg{err}
		}

		var serverResp serverResponse
		if err := json.Unmarshal(body, &serverResp); err != nil {
			return errorMsg{err}
		}

		re := regexp.MustCompile(`\[open:(\S+)\]`)
		matches := re.FindStringSubmatch(serverResp.Response)
		if len(matches) > 1 {
			urlToOpen := matches[1]
			cmd := exec.Command("firefox", urlToOpen)
			cmd.Start()
		}

		cleanedResponse := re.ReplaceAllString(serverResp.Response, "")

		return serverResponseMsg(cleanedResponse)
	}
}

func resetCmd(m model) tea.Cmd {
	return func() tea.Msg {
		req, err := http.NewRequest("POST", m.serverURL+"/reset", nil)
		if err != nil {
			log.Printf("Error creating reset request: %v", err)
			return resetSuccessMsg{}
		}

		resp, err := m.client.Do(req)
		if err != nil {
			log.Printf("Error sending reset request: %v", err)
			return resetSuccessMsg{}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("Reset failed with status: %s", resp.Status)
			return resetSuccessMsg{}
		}

		return resetSuccessMsg{}
	}
}

func fetchNotifsCmd(m model) tea.Cmd {
	return func() tea.Msg {
		req, err := http.NewRequest("GET", m.serverURL+"/tasks", nil)
		if err != nil {
			return errorMsg{err}
		}

		resp, err := m.client.Do(req)
		if err != nil {
			return errorMsg{err}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errorMsg{fmt.Errorf("failed to fetch notifications: %s", resp.Status)}
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errorMsg{err}
		}

		var tasksData tasksResponse
        if err := json.Unmarshal(body, &tasksData); err != nil {
            return errorMsg{err}
        }

        var notifs []string
        for _, task := range tasksData.BackgroundTasks {
            notifs = append(notifs, fmt.Sprintf("- **%s**: %s", task.Module, task.Status))
        }

        return notifMsg(strings.Join(notifs, "\n"))
	}
}

func fetchStatusCmd(m model) tea.Cmd {
	return func() tea.Msg {
		req, err := http.NewRequest("GET", m.serverURL+"/status", nil)
		if err != nil {
			return errorMsg{err}
		}

		resp, err := m.client.Do(req)
		if err != nil {
			return errorMsg{err}
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return errorMsg{fmt.Errorf("failed to fetch status: %s", resp.Status)}
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return errorMsg{err}
		}

		var statusData statusResponse
		if err := json.Unmarshal(body, &statusData); err != nil {
			return errorMsg{err}
		}

		var statuses []string
		for _, mod := range statusData.Modules {
			statuses = append(statuses, fmt.Sprintf("- **%s**: %s", mod.Name, mod.Status))
		}

		return statusMsg(strings.Join(statuses, "\n"))
	}
}

func main() {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatal(err)
	}
}
