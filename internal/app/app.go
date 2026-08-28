package app

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"runtime"
	"strings"

	"github.com/watchpost-ops/watchpost-agent/internal/auth"
	"github.com/watchpost-ops/watchpost-agent/internal/pairing"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

type App struct {
	state   *state.Store
	auth    *auth.Manager
	version string
	assets  fs.FS
	pairing *pairing.Client
}

func New(store *state.Store, version string, assets fs.FS) *App {
	return &App{state: store, auth: auth.New(store), version: version, assets: assets, pairing: pairing.New(store, version)}
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ready"}) })
	mux.HandleFunc("GET /api/v1/bootstrap", a.bootstrap)
	mux.HandleFunc("POST /api/v1/setup", a.setup)
	mux.HandleFunc("POST /api/v1/login", a.login)
	mux.HandleFunc("POST /api/v1/logout", a.require(a.logout))
	mux.HandleFunc("GET /api/v1/status", a.require(a.status))
	mux.HandleFunc("POST /api/v1/pairing/request", a.require(a.requestPairing))
	mux.HandleFunc("POST /api/v1/pairing/poll", a.require(a.pollPairing))
	mux.HandleFunc("GET /api/v1/collectors", a.require(a.collectorConfig))
	mux.HandleFunc("PUT /api/v1/collectors", a.require(a.collectorConfig))
	mux.HandleFunc("POST /api/v1/unpair", a.require(a.unpair))
	mux.HandleFunc("POST /api/v1/reset", a.require(a.reset))
	mux.Handle("/", http.FileServer(http.FS(a.assets)))
	return headers(mux)
}

func (a *App) bootstrap(w http.ResponseWriter, r *http.Request) {
	response := map[string]any{"setup_required": a.auth.SetupRequired(), "authenticated": false}
	if cookie, err := r.Cookie("watchpost_agent_session"); err == nil {
		if session, ok := a.auth.Authenticate(cookie.Value); ok {
			response["authenticated"] = true
			response["csrf_token"] = session.CSRF
		}
	}
	writeJSON(w, 200, response)
}

func (a *App) setup(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeJSON(w, 403, map[string]string{"error": "origin check failed"})
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
	if !sameOrigin(r) {
		writeJSON(w, 403, map[string]string{"error": "origin check failed"})
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
	http.SetCookie(w, auth.Cookie(r, session))
	writeJSON(w, 200, map[string]string{"csrf_token": session.CSRF})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("watchpost_agent_session"); err == nil {
		a.auth.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "watchpost_agent_session", Value: "", Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) require(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if r.Method != http.MethodGet {
			if !sameOrigin(r) || r.Header.Get("X-Watchpost-Agent-CSRF") != session.CSRF {
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

func sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return strings.EqualFold(origin, scheme+"://"+r.Host)
}

func (a *App) status(w http.ResponseWriter, _ *http.Request) {
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
	writeJSON(w, 201, result)
}
func (a *App) pollPairing(w http.ResponseWriter, r *http.Request) {
	result, err := a.pairing.Poll(r.Context())
	if err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
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
	if err := a.state.Update(func(value *state.State) error { value.Collectors = input; return nil }); err != nil {
		writeJSON(w, 500, map[string]string{"error": "collector configuration could not be saved"})
		return
	}
	writeJSON(w, 200, input)
}
func (a *App) unpair(w http.ResponseWriter, r *http.Request) {
	if err := a.state.Unpair(); err != nil {
		writeJSON(w, 500, map[string]string{"error": "could not clear connection"})
		return
	}
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
