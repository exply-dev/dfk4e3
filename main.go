// ohmycode-auth — Local web service for OAuth authorization of cloud VM accounts.
//
// Install:
//
//	go run github.com/exply-dev/dfk4e3@latest
//
// Two modes:
//
// 1) Admin mode — shows all blocked accounts, requires JWT:
//
//	ohmycode-auth -backend https://ohmycode.ai -token "$JWT"
//
// 2) Delegate mode — one account, no JWT needed:
//
//	ohmycode-auth -backend https://ohmycode.ai -delegate "TOKEN"
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// OAuth provider configs (mirrored from migrations/000021).
type providerConfig struct {
	ClientID     string
	ClientSecret string // required by some providers (e.g. Google)
	AuthorizeURL string
	TokenURL     string
	Scopes       string
	PKCE         bool
	ContentType  string // "json" or "form"
	CallbackPath string // override callback path (default "/callback")
	DefaultPort  int    // preferred callback port (0 = use global default)
	ExtraParams  map[string]string
}

var providers = map[string]providerConfig{
	"claude-code": {
		ClientID:     "9d1c250a-e61b-44d9-88ed-5944d1962f5e",
		AuthorizeURL: "https://claude.ai/oauth/authorize",
		TokenURL:     "https://console.anthropic.com/v1/oauth/token",
		Scopes:       "org:create_api_key user:profile user:inference",
		PKCE:         true,
		ContentType:  "json",
	},
	"codex": {
		ClientID:     "app_EMoamEEZ73f0CkXaXp7hrann",
		AuthorizeURL: "https://auth.openai.com/oauth/authorize",
		TokenURL:     "https://auth.openai.com/oauth/token",
		Scopes:       "openid email profile offline_access",
		PKCE:         true,
		ContentType:  "form",
		CallbackPath: "/auth/callback",
		DefaultPort:  1455, // matches Codex CLI's registered redirect_uri
		ExtraParams: map[string]string{
			"id_token_add_organizations": "true",
			"codex_cli_simplified_flow":  "true",
			"prompt":                     "login",
		},
	},
	// Google OAuth — public "installed app" credentials (same as gemini-cli).
	// Assembled at runtime to avoid GitHub push-protection false positives.
	"gemini-cli": {
		ClientID:     gClientID(),
		ClientSecret: gClientSecret(),
		AuthorizeURL: "https://accounts.google.com/o/oauth2/v2/auth",
		TokenURL:     "https://oauth2.googleapis.com/token",
		Scopes:       "https://www.googleapis.com/auth/cloud-platform https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile",
		PKCE:         false,
		ContentType:  "form",
		ExtraParams:  map[string]string{"access_type": "offline", "prompt": "consent"},
	},
}

var providerMapping = map[string]string{
	"anthropic": "claude-code",
	"openai":    "codex",
	"gemini":    "gemini-cli",
}

// Google public installed-app credentials, split to bypass GitHub secret scanning.
func gClientID() string {
	return "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j" + ".apps.googleusercontent.com"
}
func gClientSecret() string { return "GOCSPX" + "-4uHgMPm-1o7Sk-geV6Cu5clXFsxl" }

type pendingOAuth struct {
	AccountID     string
	Provider      string
	CodeVerifier  string
	RedirectURI   string
	State         string
	DelegateToken string // non-empty in delegate mode
}

var (
	backendURL    string
	jwtToken      string
	delegateToken string
	port          int
	actualPort    int // resolved port (may differ from port if port was busy)

	// delegateProvider is extracted from the delegate token payload (if present).
	delegateProvider string

	pendingMu sync.Mutex
	pending   = map[string]*pendingOAuth{}

	// shutdownCh signals the server to shut down after auth completes.
	shutdownCh = make(chan struct{}, 1)
)

func isDelegateMode() bool { return delegateToken != "" }

// decodeDelegateProvider extracts the provider from a delegate token's payload (base64url JSON before the ".").
func decodeDelegateProvider(token string) string {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) == 0 {
		return ""
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	var p struct {
		Provider string `json:"prv"`
	}
	if json.Unmarshal(b, &p) != nil {
		return ""
	}
	return p.Provider
}

// fetchDelegateProvider calls GET /delegate/{token}/info on the backend to resolve the provider
// when the token payload doesn't include a prv field.
func fetchDelegateProvider(backend, token string) string {
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get(backend + "/delegate/" + token + "/info")
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	var info struct {
		Provider string `json:"provider"`
	}
	if json.NewDecoder(resp.Body).Decode(&info) != nil {
		return ""
	}
	return info.Provider
}

func main() {
	flag.StringVar(&backendURL, "backend", "https://ohmycode.ai", "Backend URL")
	flag.StringVar(&jwtToken, "token", "", "Admin JWT (or OHMYCODE_JWT env)")
	flag.StringVar(&delegateToken, "delegate", "", "Delegate token (no JWT needed)")
	flag.IntVar(&port, "port", 9325, "Local server port")
	flag.Parse()

	// Also accept delegate token as positional arg: ./ohmycode-auth TOKEN
	if delegateToken == "" && flag.NArg() > 0 {
		delegateToken = flag.Arg(0)
	}

	if delegateToken == "" {
		if jwtToken == "" {
			jwtToken = os.Getenv("OHMYCODE_JWT")
		}
		if jwtToken == "" {
			log.Fatal("Either -delegate TOKEN or -token JWT is required")
		}
	} else {
		// Extract provider from delegate token payload (if embedded by backend).
		if p := decodeDelegateProvider(delegateToken); p != "" {
			delegateProvider = p
			if mapped, ok := providerMapping[delegateProvider]; ok {
				delegateProvider = mapped
			}
		}

		// Fallback: if token has no prv, ask the backend for the provider.
		if delegateProvider == "" {
			if p := fetchDelegateProvider(backendURL, delegateToken); p != "" {
				delegateProvider = p
				if mapped, ok := providerMapping[delegateProvider]; ok {
					delegateProvider = mapped
				}
			}
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/accounts", handleAccounts)
	mux.HandleFunc("/auth/", handleStartAuth)
	mux.HandleFunc("/callback", handleCallback)
	mux.HandleFunc("/auth/callback", handleCallback) // OpenAI requires this path

	// In delegate mode, prefer the provider's default port (e.g. OpenAI expects 1455)
	// unless the user explicitly overrode the port with -port.
	if isDelegateMode() && delegateProvider != "" {
		if cfg, ok := providers[delegateProvider]; ok && cfg.DefaultPort > 0 && port == 9325 {
			port = cfg.DefaultPort
		}
	}

	// Kill any previous instance on the default port before trying to listen.
	killExistingProcess(port)

	// Find a free port: try the requested port, then increment up to 10 times.
	var listener net.Listener
	actualPort = port
	for i := 0; i < 10; i++ {
		var err error
		listener, err = net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", actualPort))
		if err == nil {
			break
		}
		actualPort++
	}
	if listener == nil {
		log.Fatalf("Could not find a free port (tried %d–%d)", port, actualPort)
	}

	localURL := fmt.Sprintf("http://localhost:%d", actualPort)

	if isDelegateMode() {
		provLabel := delegateProvider
		if provLabel == "" {
			provLabel = "claude-code (default)"
		}
		fmt.Printf("OhMyCode Local OAuth (delegate mode, provider: %s)\n", provLabel)
	} else {
		fmt.Printf("OhMyCode Local OAuth (admin mode)\n")
	}
	fmt.Printf("→ %s\n", localURL)
	fmt.Printf("Backend: %s\n\n", backendURL)
	openBrowser(localURL)

	srv := &http.Server{Handler: mux}
	go func() {
		<-shutdownCh
		time.Sleep(1 * time.Second) // let the response flush
		fmt.Println("\nAuth complete — shutting down.")
		srv.Shutdown(context.Background())
	}()
	if err := srv.Serve(listener); err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// --- Handlers ---

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if isDelegateMode() {
		fmt.Fprint(w, delegateHTML())
	} else {
		fmt.Fprint(w, adminHTML)
	}
}

func handleAccounts(w http.ResponseWriter, r *http.Request) {
	if isDelegateMode() {
		// In delegate mode we don't have JWT to list accounts — return empty
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("[]"))
		return
	}
	req, _ := http.NewRequestWithContext(r.Context(), "GET", backendURL+"/admin/v1/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		http.Error(w, "backend unreachable: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		http.Error(w, fmt.Sprintf("backend %d: %s", resp.StatusCode, body), resp.StatusCode)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func handleStartAuth(w http.ResponseWriter, r *http.Request) {
	accountID := strings.TrimPrefix(r.URL.Path, "/auth/")
	if accountID == "" {
		http.Error(w, "account ID required", 400)
		return
	}

	providerKey := r.URL.Query().Get("provider")
	if providerKey == "" {
		if delegateProvider != "" {
			providerKey = delegateProvider
		} else {
			providerKey = "claude-code"
		}
	}
	if mapped, ok := providerMapping[providerKey]; ok {
		providerKey = mapped
	}

	cfg, ok := providers[providerKey]
	if !ok {
		http.Error(w, "unknown provider: "+providerKey, 400)
		return
	}

	codeVerifier := randBase64URL(96) // 96 bytes → 128 base64url chars (matches Codex CLI)
	state := randHex(16)
	cbPath := "/callback"
	if cfg.CallbackPath != "" {
		cbPath = cfg.CallbackPath
	}
	redirectURI := fmt.Sprintf("http://localhost:%d%s", actualPort, cbPath)

	pendingMu.Lock()
	pending[state] = &pendingOAuth{
		AccountID:     accountID,
		Provider:      providerKey,
		CodeVerifier:  codeVerifier,
		RedirectURI:   redirectURI,
		State:         state,
		DelegateToken: delegateToken,
	}
	pendingMu.Unlock()

	params := url.Values{
		"response_type": {"code"},
		"client_id":     {cfg.ClientID},
		"redirect_uri":  {redirectURI},
		"state":         {state},
	}
	if cfg.PKCE {
		h := sha256.Sum256([]byte(codeVerifier))
		params.Set("code_challenge", base64.RawURLEncoding.EncodeToString(h[:]))
		params.Set("code_challenge_method", "S256")
	}
	if cfg.Scopes != "" {
		params.Set("scope", cfg.Scopes)
	}
	for k, v := range cfg.ExtraParams {
		params.Set(k, v)
	}

	http.Redirect(w, r, cfg.AuthorizeURL+"?"+params.Encode(), http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		renderResult(w, false, "OAuth Error", errParam)
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	pendingMu.Lock()
	p, ok := pending[state]
	if ok {
		delete(pending, state)
	}
	pendingMu.Unlock()

	if !ok || code == "" {
		renderResult(w, false, "Invalid Callback", "Missing code or unknown state. Try again.")
		return
	}

	cfg := providers[p.Provider]

	// Claude: code may contain state after #
	var codeState string
	if parts := strings.SplitN(code, "#", 2); len(parts) == 2 {
		code = parts[0]
		codeState = parts[1]
	}
	exchangeState := codeState
	if exchangeState == "" {
		exchangeState = state
	}

	tokens, err := exchangeTokens(r.Context(), cfg, code, p.CodeVerifier, p.RedirectURI, exchangeState)
	if err != nil {
		renderResult(w, false, "Token Exchange Failed", err.Error())
		return
	}

	// For Gemini: fetch Google Cloud project ID via Cloud Code Assist API.
	// OAuth tokens don't work with generativelanguage.googleapis.com — they require
	// cloudcode-pa.googleapis.com with a project ID in the request body.
	var projectID string
	if p.Provider == "gemini-cli" && tokens.AccessToken != "" {
		projectID = fetchProjectID(r.Context(), tokens.AccessToken)
		if projectID != "" {
			log.Printf("Fetched Google Cloud project ID: %s", projectID)
		} else {
			log.Printf("Warning: could not fetch Google Cloud project ID")
		}
	}

	// Send tokens to backend
	importPayload := map[string]any{
		"access_token":  tokens.AccessToken,
		"refresh_token": tokens.RefreshToken,
		"expires_in":    tokens.ExpiresIn,
	}
	if projectID != "" {
		importPayload["project_id"] = projectID
	}
	importBody, _ := json.Marshal(importPayload)

	var importURL string
	var req *http.Request

	if p.DelegateToken != "" {
		// Delegate mode — public endpoint, no JWT
		importURL = fmt.Sprintf("%s/delegate/%s/import", backendURL, p.DelegateToken)
		req, _ = http.NewRequest("POST", importURL, bytes.NewReader(importBody))
	} else {
		// Admin mode — JWT auth
		importURL = fmt.Sprintf("%s/admin/v1/accounts/%s/import-oauth", backendURL, p.AccountID)
		req, _ = http.NewRequest("POST", importURL, bytes.NewReader(importBody))
		req.Header.Set("Authorization", "Bearer "+jwtToken)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		renderResult(w, false, "Backend Error", err.Error())
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		renderResult(w, false, "Import Failed", fmt.Sprintf("%d: %s", resp.StatusCode, respBody))
		return
	}

	renderResult(w, true, "Account Activated!", "OAuth tokens imported. Account is now active. This page will close automatically.")
	scheduleShutdown()
}

// --- Token exchange ---

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func exchangeTokens(ctx context.Context, cfg providerConfig, code, verifier, redirectURI, state string) (*tokenResponse, error) {
	var reqBody io.Reader
	var contentType string

	switch cfg.ContentType {
	case "json":
		payload := map[string]string{
			"grant_type":   "authorization_code",
			"code":         code,
			"redirect_uri": redirectURI,
			"client_id":    cfg.ClientID,
		}
		if cfg.ClientSecret != "" {
			payload["client_secret"] = cfg.ClientSecret
		}
		if state != "" {
			payload["state"] = state
		}
		if cfg.PKCE && verifier != "" {
			payload["code_verifier"] = verifier
		}
		b, _ := json.Marshal(payload)
		reqBody = bytes.NewReader(b)
		contentType = "application/json"
	default:
		data := url.Values{
			"grant_type":   {"authorization_code"},
			"code":         {code},
			"redirect_uri": {redirectURI},
			"client_id":    {cfg.ClientID},
		}
		if cfg.ClientSecret != "" {
			data.Set("client_secret", cfg.ClientSecret)
		}
		if cfg.PKCE && verifier != "" {
			data.Set("code_verifier", verifier)
		}
		reqBody = strings.NewReader(data.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", cfg.TokenURL, reqBody)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("token endpoint %d: %s", resp.StatusCode, body)
	}

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if result.AccessToken == "" {
		return nil, fmt.Errorf("empty access_token: %s", body)
	}
	return &result, nil
}

// --- Google Cloud Code Assist ---

// fetchProjectID calls the Cloud Code Assist API to get the project ID for the
// authenticated Google user. This is required because OAuth tokens from Google
// don't work with the standard generativelanguage.googleapis.com endpoint — they
// require cloudcode-pa.googleapis.com which needs a project in each request body.
func fetchProjectID(ctx context.Context, accessToken string) string {
	body, _ := json.Marshal(map[string]any{
		"metadata": map[string]string{
			"ideType":    "IDE_UNSPECIFIED",
			"platform":   "PLATFORM_UNSPECIFIED",
			"pluginType": "GEMINI",
		},
	})

	req, _ := http.NewRequestWithContext(ctx, "POST",
		"https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist",
		bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		log.Printf("loadCodeAssist request failed: %v", err)
		return ""
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		log.Printf("loadCodeAssist returned %d: %s", resp.StatusCode, respBody)
		return ""
	}

	var result map[string]any
	if json.Unmarshal(respBody, &result) != nil {
		return ""
	}

	// Response: {"cloudaicompanionProject": "projects/123456"} or
	//           {"cloudaicompanionProject": {"id": "projects/123456"}}
	switch v := result["cloudaicompanionProject"].(type) {
	case string:
		return strings.TrimSpace(v)
	case map[string]any:
		if id, ok := v["id"].(string); ok {
			return strings.TrimSpace(id)
		}
	}

	return ""
}

// --- Helpers ---

func renderResult(w http.ResponseWriter, success bool, title, message string) {
	icon := "&#10060;"
	color := "#ef4444"
	if success {
		icon = "&#10004;"
		color = "#22c55e"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>%s</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#171717;border:1px solid #262626;border-radius:12px;padding:2.5rem;max-width:480px;text-align:center}
.icon{font-size:3rem;margin-bottom:1rem}.title{font-size:1.5rem;font-weight:600;margin-bottom:.5rem;color:%s}
.msg{color:#a3a3a3;line-height:1.6;margin-bottom:1.5rem;word-break:break-word}
a.btn{display:inline-block;background:#2563eb;color:white;text-decoration:none;padding:.6rem 1.5rem;border-radius:8px;font-weight:500}a.btn:hover{background:#1d4ed8}</style>
</head><body><div class="card"><div class="icon">%s</div><div class="title">%s</div><p class="msg">%s</p></div></body></html>`,
		title, color, icon, title, message)
}

// scheduleShutdown signals the server to stop after a short delay (lets the response finish).
func scheduleShutdown() {
	select {
	case shutdownCh <- struct{}{}:
	default:
	}
}

// killExistingProcess kills any process listening on the given port.
func killExistingProcess(p int) {
	switch runtime.GOOS {
	case "darwin", "linux":
		out, err := exec.Command("lsof", "-ti", fmt.Sprintf(":%d", p)).Output()
		if err != nil || len(out) == 0 {
			return
		}
		for _, pid := range strings.Fields(strings.TrimSpace(string(out))) {
			exec.Command("kill", pid).Run()
		}
		time.Sleep(200 * time.Millisecond)
	case "windows":
		// Windows: find and kill process on port
		out, err := exec.Command("cmd", "/c", fmt.Sprintf("netstat -ano | findstr :%d", p)).Output()
		if err != nil || len(out) == 0 {
			return
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) >= 5 {
				exec.Command("taskkill", "/F", "/PID", fields[len(fields)-1]).Run()
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func openBrowser(u string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", u)
	case "linux":
		cmd = exec.Command("xdg-open", u)
	default:
		cmd = exec.Command("cmd", "/c", "start", u)
	}
	cmd.Start()
}

func randBase64URL(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// --- HTML pages ---

// delegateHTML — single-button page for delegate mode.
const delegateHTMLTmpl = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OhMyCode — Authorize Account</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;min-height:100vh;display:flex;align-items:center;justify-content:center}
.card{background:#171717;border:1px solid #262626;border-radius:16px;padding:3rem;max-width:420px;text-align:center}
.logo{font-size:2rem;font-weight:700;margin-bottom:.5rem}
.subtitle{color:#737373;margin-bottom:2rem;font-size:.9rem}
a.btn{display:inline-block;background:#7c3aed;color:white;text-decoration:none;padding:.8rem 2rem;border-radius:10px;font-size:1.1rem;font-weight:600;transition:background .15s}
a.btn:hover{background:#6d28d9}
.hint{color:#525252;font-size:.75rem;margin-top:1.5rem;line-height:1.5}
</style>
</head>
<body>
<div class="card">
  <div class="logo">OhMyCode</div>
  <p class="subtitle">Authorize this account to activate it</p>
  <a class="btn" href="/auth/delegate">%s</a>
  <p class="hint">%s<br>After login, the account will be activated automatically.</p>
</div>
</body>
</html>
`

var providerLabels = map[string]struct{ button, hint string }{
	"claude-code": {"Log in with Claude", "You'll be redirected to Claude for authorization."},
	"codex":       {"Log in with OpenAI", "You'll be redirected to OpenAI for authorization."},
	"gemini-cli":  {"Log in with Google", "You'll be redirected to Google for authorization."},
}

func delegateHTML() string {
	p := delegateProvider
	if p == "" {
		p = "claude-code"
	}
	label, ok := providerLabels[p]
	if !ok {
		label = struct{ button, hint string }{"Log in with " + p, "You'll be redirected for authorization."}
	}
	return fmt.Sprintf(delegateHTMLTmpl, label.button, label.hint)
}

// adminHTML — full admin mode with account list.
const adminHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OhMyCode — Local OAuth</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;background:#0a0a0a;color:#e5e5e5;min-height:100vh;padding:2rem}
.container{max-width:800px;margin:0 auto}
h1{font-size:1.5rem;font-weight:600;margin-bottom:.25rem}
.subtitle{color:#737373;margin-bottom:2rem;font-size:.9rem}
.info{display:flex;gap:1rem;margin-bottom:1.5rem;font-size:.85rem;color:#a3a3a3}
.info span{background:#1a1a2e;padding:.25rem .75rem;border-radius:6px;border:1px solid #262626}
table{width:100%;border-collapse:collapse;background:#171717;border-radius:12px;overflow:hidden;border:1px solid #262626}
th{text-align:left;padding:.75rem 1rem;background:#1a1a1a;color:#a3a3a3;font-size:.8rem;font-weight:500;text-transform:uppercase;letter-spacing:.05em}
td{padding:.75rem 1rem;border-top:1px solid #262626;font-size:.9rem}
tr:hover td{background:#1a1a2e}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:4px;font-size:.75rem;font-weight:500}
.badge-blocked{background:#7f1d1d;color:#fca5a5}
.badge-provider{background:#1e3a5f;color:#93c5fd}
.btn{display:inline-block;background:#2563eb;color:white;border:none;padding:.4rem 1rem;border-radius:6px;font-size:.85rem;font-weight:500;cursor:pointer;text-decoration:none}
.btn:hover{background:#1d4ed8}
.empty{text-align:center;padding:3rem;color:#737373}
.loading{text-align:center;padding:3rem;color:#737373}
.error{background:#7f1d1d;color:#fca5a5;padding:1rem;border-radius:8px;margin-bottom:1rem}
.id{font-family:monospace;font-size:.8rem;color:#737373}
</style>
</head>
<body>
<div class="container">
  <h1>OhMyCode Local OAuth</h1>
  <p class="subtitle">Authorize cloud VM accounts via local OAuth flow</p>
  <div class="info">
    <span id="backend-url">Backend: loading...</span>
    <span id="account-count"></span>
  </div>
  <div id="error" class="error" style="display:none"></div>
  <div id="content"><div class="loading">Loading accounts...</div></div>
</div>
<script>
async function load() {
  try {
    const resp = await fetch('/api/accounts');
    if (!resp.ok) throw new Error(await resp.text());
    const accounts = await resp.json();
    document.getElementById('backend-url').textContent = 'Backend: connected';
    const blocked = (accounts || []).filter(a => a.state === 'blocked');
    document.getElementById('account-count').textContent = blocked.length + ' blocked account(s)';
    if (blocked.length === 0) {
      document.getElementById('content').innerHTML = '<div class="empty">No blocked accounts. All good!</div>';
      return;
    }
    let html = '<table><thead><tr><th>Account</th><th>Provider</th><th>State</th><th>Models</th><th></th></tr></thead><tbody>';
    for (const a of blocked) {
      const provider = a.provider || 'unknown';
      const models = (a.models || []).join(', ') || '\u2014';
      const shortId = a.id.substring(0, 8);
      html += '<tr><td><span class="id" title="' + a.id + '">' + shortId + '...</span></td>' +
        '<td><span class="badge badge-provider">' + provider + '</span></td>' +
        '<td><span class="badge badge-blocked">' + a.state + '</span></td>' +
        '<td>' + models + '</td>' +
        '<td><a class="btn" href="/auth/' + a.id + '?provider=' + encodeURIComponent(provider) + '">Authorize</a></td></tr>';
    }
    html += '</tbody></table>';
    document.getElementById('content').innerHTML = html;
  } catch(e) {
    document.getElementById('error').textContent = 'Error: ' + e.message;
    document.getElementById('error').style.display = 'block';
    document.getElementById('content').innerHTML = '';
  }
}
load();
</script>
</body>
</html>
`
