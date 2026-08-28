package app

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"runtime"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

type App struct {
	state   *state.Store
	version string
	assets  fs.FS
}

func New(store *state.Store, version string, assets fs.FS) *App {
	return &App{state: store, version: version, assets: assets}
}

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ready"}) })
	mux.HandleFunc("GET /api/v1/status", a.status)
	mux.Handle("/", http.FileServer(http.FS(a.assets)))
	return headers(mux)
}

func (a *App) status(w http.ResponseWriter, _ *http.Request) {
	current := a.state.Snapshot()
	hostname, _ := runtimeHostname()
	writeJSON(w, 200, map[string]any{
		"version": a.version, "installation_id": current.InstallationID,
		"created_at": current.CreatedAt, "platform": runtime.GOOS + "/" + runtime.GOARCH,
		"hostname": hostname, "state": "installed", "pairing": "unpaired",
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
