package app

import (
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/watchpost-ops/watchpost-agent/internal/auth"
	"github.com/watchpost-ops/watchpost-agent/internal/pairing"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

// Options carries remote-management security configuration. Loopback binding
// is the primary access control; the options below harden explicit remote
// exposure.
type Options struct {
	SecureCookies bool
	TrustedProxy  bool
	AllowCIDRs    []*net.IPNet
	DenyCIDRs     []*net.IPNet
}

type App struct {
	state   *state.Store
	auth    *auth.Manager
	version string
	assets  fs.FS
	pairing *pairing.Client
	options Options
}

func New(store *state.Store, version string, assets fs.FS, options Options) *App {
	return &App{state: store, auth: auth.New(store), version: version, assets: assets, pairing: pairing.New(store, version), options: options}
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ready"}) })
	mux.HandleFunc("GET /api/v1/bootstrap", a.bootstrap)
	mux.HandleFunc("POST /api/v1/setup", a.setup)
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.require("viewer", a.logout))
	mux.HandleFunc("GET /api/v1/status", a.require("viewer", a.status))
	mux.HandleFunc("POST /api/v1/pairing/request", a.require("technician", a.requestPairing))
	mux.HandleFunc("POST /api/v1/pairing/poll", a.require("technician", a.pollPairing))
	mux.HandleFunc("GET /api/v1/collectors", a.require("viewer", a.collectorConfig))
	mux.HandleFunc("PUT /api/v1/collectors", a.require("technician", a.collectorConfig))
	mux.HandleFunc("POST /api/v1/unpair", a.require("admin", a.unpair))
	mux.HandleFunc("POST /api/v1/rotate", a.require("admin", a.rotate))
	mux.HandleFunc("POST /api/v1/reset", a.require("admin", a.reset))
	mux.HandleFunc("POST /api/v1/me/password", a.require("viewer", a.changePassword))
	mux.HandleFunc("GET /api/v1/accounts", a.require("admin", a.accounts))
	mux.HandleFunc("POST /api/v1/accounts", a.require("admin", a.createAccount))
	mux.HandleFunc("POST /api/v1/accounts/{id}/revoke-sessions", a.require("admin", a.revokeAccountSessions))
	mux.HandleFunc("GET /api/v1/audit", a.require("admin", a.audit))
	mux.Handle("/", http.FileServer(http.FS(a.assets)))
	return headers(mux)
}

func (a *App) bootstrap(w http.ResponseWriter, r *http.Request) {
	if !a.clientAllowed(r) {
		writeJSON(w, 403, map[string]string{"error": "client address denied"})
		return
	}
	response := map[string]any{"setup_required": a.auth.SetupRequired(), "authenticated": false}
	if cookie, err := r.Cookie("watchpost_agent_session"); err == nil {
		if session, ok := a.auth.Authenticate(cookie.Value); ok {
			response["authenticated"] = true
			response["csrf_token"] = session.CSRF
			response["user"] = session.User
		}
	}
	writeJSON(w, 200, response)
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !a.clientAllowed(r) || !a.sameOrigin(r) {
		writeJSON(w, 403, map[string]string{"error": "origin or address check failed"})
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := a.auth.Setup(input.Password); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if !a.clientAllowed(r) || !a.sameOrigin(r) {
		writeJSON(w, 403, map[string]string{"error": "origin or address check failed"})
		return
	}
	var input struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &input) {
		return
	}
	session, err := a.auth.Login(input.Password)
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
		return
	}
	http.SetCookie(w, auth.Cookie(r, session, a.options.SecureCookies))
	writeJSON(w, 200, map[string]any{"csrf_token": session.CSRF, "user": session.User})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("watchpost_agent_session"); err == nil {
		a.auth.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "watchpost_agent_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func rank(role string) int {
	switch role {
	case "admin":
		return 3
	case "technician":
		return 2
	case "viewer":
		return 1
	}
	return 0
}

func (a *App) require(minRole string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.clientAllowed(r) {
			writeJSON(w, 403, map[string]string{"error": "client address denied"})
			return
		}
		cookie, err := r.Cookie("watchpost_agent_session")
		if err != nil {
			writeJSON(w, 401, map[string]string{"error": "authentication required"})
			return
		}
		session, ok := a.auth.Authenticate(cookie.Value)
		if !ok {
			writeJSON(w, 401, map[string]string{"error": "authentication required"})
			return
		}
		if rank(session.User.Role) < rank(minRole) {
			writeJSON(w, 403, map[string]string{"error": "forbidden"})
			return
		}
		if r.Method != http.MethodGet {
			if !a.sameOrigin(r) || r.Header.Get("X-Watchpost-Agent-CSRF") != session.CSRF {
				writeJSON(w, 403, map[string]string{"error": "request verification failed"})
				return
			}
		}
		next(w, r.WithContext(auth.WithSession(r.Context(), session)))
	}
}

func decode(w http.ResponseWriter, r *http.Request, value any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid request"})
		return false
	}
	return true
}

// sameOrigin accepts a request whose Origin matches the effective scheme and
// host. Forwarded scheme/host are trusted only when TrustedProxy is explicitly
// enabled; they are never trusted by default.
func (a *App) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if a.options.TrustedProxy {
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			scheme = forwarded
		}
		if forwarded := r.Header.Get("X-Forwarded-Host"); forwarded != "" {
			host = forwarded
		}
	}
	return strings.EqualFold(origin, scheme+"://"+host)
}

// clientAllowed applies optional CIDR allow/deny rules to the remote address.
// Loopback is always allowed (loopback binding is the primary control); rules
// only gate explicit remote exposure.
func (a *App) clientAllowed(r *http.Request) bool {
	if len(a.options.AllowCIDRs) == 0 && len(a.options.DenyCIDRs) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsLoopback() {
		return true
	}
	if len(a.options.AllowCIDRs) > 0 && !cidrMatch(a.options.AllowCIDRs, ip) {
		return false
	}
	if cidrMatch(a.options.DenyCIDRs, ip) {
		return false
	}
	return true
}

func cidrMatch(nets []*net.IPNet, ip net.IP) bool {
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (a *App) status(w http.ResponseWriter, r *http.Request) {
	current := a.state.Snapshot()
	hostname, _ := runtimeHostname()
	writeJSON(w, 200, map[string]any{
		"version": a.version, "installation_id": current.InstallationID,
		"created_at": current.CreatedAt, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"hostname": hostname, "state": "installed", "pairing": pairingState(current), "pairing_phrase": current.PendingPairing.Phrase, "pairing_expires_at": current.PendingPairing.ExpiresAt, "post_id": current.Connection.PostID,
		"delivery": map[string]any{"queued": len(current.Delivery.Queue), "last_success_at": current.Delivery.LastSuccessAt, "last_error": current.Delivery.LastError, "next_retry_at": current.Delivery.NextRetryAt, "dropped_collections": current.Delivery.DroppedCollections},
	})
}

func pairingState(value state.State) string {
	if value.Connection.RevocationPending {
		return "unpair_pending"
	}
	if value.Connection.Credential != "" {
		return "paired"
	}
	if value.PendingPairing.RequestID != "" {
		return "pending"
	}
	return "unpaired"
}
func (a *App) requestPairing(w http.ResponseWriter, r *http.Request) {
	var input struct {
		WatchpostURL string `json:"watchpost_url"`
	}
	if !decode(w, r, &input) {
		return
	}
	result, err := a.pairing.Request(r.Context(), input.WatchpostURL)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "pairing_request", input.WatchpostURL)
	writeJSON(w, 201, result)
}
func (a *App) pollPairing(w http.ResponseWriter, r *http.Request) {
	result, err := a.pairing.Poll(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "pairing_poll", result.State)
	writeJSON(w, 200, result)
}
func (a *App) collectorConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		writeJSON(w, 200, a.state.Snapshot().Collectors)
		return
	}
	var input state.CollectorConfig
	if !decode(w, r, &input) {
		return
	}
	if err := input.Validate(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := a.state.Update(func(value *state.State) error {
		value.Collectors = input
		return nil
	}); err != nil {
		writeJSON(w, 500, map[string]string{"error": "collector configuration could not be saved"})
		return
	}
	a.recordAudit(r, "collector_config", "interval seconds="+strconv.Itoa(input.IntervalSeconds))
	writeJSON(w, 200, input)
}
func (a *App) unpair(w http.ResponseWriter, r *http.Request) {
	if err := a.pairing.Unpair(r.Context()); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "unpair", "revoked at Watchpost")
	w.WriteHeader(http.StatusNoContent)
}
func (a *App) rotate(w http.ResponseWriter, r *http.Request) {
	if err := a.pairing.Rotate(r.Context()); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "rotate", "credential rotated")
	w.WriteHeader(http.StatusNoContent)
}
func (a *App) reset(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &input) {
		return
	}
	if err := a.state.Reset(input.Confirm); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	a.auth.ClearSessions()
	http.SetCookie(w, &http.Cookie{Name: "watchpost_agent_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}
func (a *App) changePassword(w http.ResponseWriter, r *http.Request) {
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decode(w, r, &input) {
		return
	}
	cookie, err := r.Cookie("watchpost_agent_session")
	if err != nil {
		writeJSON(w, 401, map[string]string{"error": "authentication required"})
		return
	}
	session, _ := auth.FromContext(r.Context())
	if err := a.auth.ChangePassword(session.User.ID, input.CurrentPassword, input.NewPassword, cookie.Value); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "password_change", "password rotated")
	w.WriteHeader(http.StatusNoContent)
}
func (a *App) accounts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"accounts": a.auth.ListAccounts()})
}
func (a *App) createAccount(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Email, Password, Role string
	}
	if !decode(w, r, &input) {
		return
	}
	account, err := a.auth.CreateAccount(input.Email, input.Password, input.Role)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	a.recordAudit(r, "account_create", input.Email+" role="+input.Role)
	writeJSON(w, 201, account)
}
func (a *App) revokeAccountSessions(w http.ResponseWriter, r *http.Request) {
	removed := a.auth.RevokeUserSessions(r.PathValue("id"))
	a.recordAudit(r, "account_revoke_sessions", "account="+r.PathValue("id"))
	writeJSON(w, 200, map[string]int{"revoked": removed})
}
func (a *App) audit(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"audit": a.auth.ListAudit()})
}
func (a *App) recordAudit(r *http.Request, action, detail string) {
	session, ok := auth.FromContext(r.Context())
	actor := "unknown"
	if ok {
		actor = session.User.Email
	}
	a.state.Update(func(current *state.State) error {
		current.LocalAuth.AppendAudit(actor, action, detail)
		return nil
	})
}

var runtimeHostname = os.Hostname

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}