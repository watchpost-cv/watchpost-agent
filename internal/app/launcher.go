package app

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	corelauncher "github.com/gantry-tools/gantry-core/launcher"
	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

func (a *App) launcherRoot(static http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Has("config") {
			cookie, err := r.Cookie("watchpost_agent_session")
			session, ok := a.auth.Authenticate(cookieValue(cookie, err))
			if !ok || session.User.Role != "admin" {
				http.Redirect(w, r, "/app/?return=%2F%3Fconfig", http.StatusFound)
				return
			}
			a.serveLauncher(static, w, r)
			return
		}
		instances := a.state.Snapshot().Launcher
		switch len(instances) {
		case 0:
			http.Redirect(w, r, "/app/", http.StatusFound)
		case 1:
			target, err := corelauncher.AppURL(instances[0])
			if err != nil {
				http.Error(w, "invalid launcher configuration", 500)
				return
			}
			http.Redirect(w, r, target, http.StatusFound)
		default:
			a.serveLauncher(static, w, r)
		}
	})
}

func cookieValue(cookie *http.Cookie, err error) string {
	if err != nil || cookie == nil {
		return ""
	}
	return cookie.Value
}

func (a *App) serveLauncher(static http.Handler, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(r.Context())
	clone.URL.Path, clone.URL.RawPath = "/launcher.html", ""
	w.Header().Set("Cache-Control", "no-store")
	static.ServeHTTP(w, clone)
}

func (a *App) launcherInstances(w http.ResponseWriter, _ *http.Request) {
	view, err := corelauncher.MakeView("watchpost-agent", a.state.Snapshot().Launcher)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid launcher configuration"})
		return
	}
	writeJSON(w, 200, view)
}

func (a *App) launcherConfig(w http.ResponseWriter, r *http.Request) {
	var document corelauncher.Document
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	instances, err := corelauncher.Normalize("watchpost-agent", document)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := a.state.Update(func(value *state.State) error { value.Launcher = instances; return nil }); err != nil {
		writeJSON(w, 500, map[string]string{"error": "unable to save launcher configuration"})
		return
	}
	view, _ := corelauncher.MakeView("watchpost-agent", instances)
	writeJSON(w, 200, view)
}
