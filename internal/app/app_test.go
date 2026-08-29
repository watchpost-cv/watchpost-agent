package app

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/watchpost-ops/watchpost-agent/internal/auth"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

func TestUnpairedStatusAndSecurityHeaders(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	handler := New(store, "test", fs.FS(assets), Options{}).Handler()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewBufferString(`{"email":"admin@local","password":"1234567"}`))
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("setup=%d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(`{"email":"admin@local","password":"1234567"}`))
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatalf("login=%d %s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.AddCookie(response.Result().Cookies()[0])
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"pairing":"unpaired"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers=%v", response.Header())
	}
}

func loginForRole(t *testing.T, handler http.Handler, email, password string) (*http.Cookie, string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(`{"email":"`+email+`","password":"`+password+`"}`))
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("login=%d %s", response.Code, response.Body.String())
	}
	var body struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(response.Body.Bytes(), &body)
	return response.Result().Cookies()[0], body.CSRF
}

func TestLocalRoleCapabilityMatrix(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	handler := New(store, "test", fs.FS(assets), Options{}).Handler()
	setup := httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewBufferString(`{"email":"admin@local","password":"admin-pass-1"}`))
	setup.Header.Set("Origin", "http://example.com")
	setup.Host = "example.com"
	setupRecorder := httptest.NewRecorder()
	handler.ServeHTTP(setupRecorder, setup)
	if setupRecorder.Code != http.StatusNoContent {
		t.Fatalf("setup=%d", setupRecorder.Code)
	}
	adminCookie, adminCSRF := loginForRole(t, handler, "admin@local", "admin-pass-1")
	// Create roles through the auth manager directly, then log in through the API.
	manager := auth.New(store)
	if _, err := manager.CreateAccount("tech@local", "tech-pass-1", "technician"); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CreateAccount("view@local", "view-pass-1", "viewer"); err != nil {
		t.Fatal(err)
	}
	techCookie, techCSRF := loginForRole(t, handler, "tech@local", "tech-pass-1")
	viewCookie, viewCSRF := loginForRole(t, handler, "view@local", "view-pass-1")

	// Viewer cannot configure collectors, rotate, unpair or manage accounts.
	put := func(cookie *http.Cookie, csrf, path, body string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodPut, path, bytes.NewBufferString(body))
		request.AddCookie(cookie)
		request.Header.Set("X-Watchpost-Agent-CSRF", csrf)
		request.Header.Set("Origin", "http://example.com")
		request.Host = "example.com"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	post := func(cookie *http.Cookie, csrf, path string) int {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, nil)
		request.AddCookie(cookie)
		request.Header.Set("X-Watchpost-Agent-CSRF", csrf)
		request.Header.Set("Origin", "http://example.com")
		request.Host = "example.com"
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	if got := put(viewCookie, viewCSRF, "/api/v1/collectors", `{"interval_seconds":60,"cpu":true}`); got != http.StatusForbidden {
		t.Fatalf("viewer configure collectors=%d want 403", got)
	}
	if got := post(viewCookie, viewCSRF, "/api/v1/rotate"); got != http.StatusForbidden {
		t.Fatalf("viewer rotate=%d want 403", got)
	}
	if got := post(viewCookie, viewCSRF, "/api/v1/accounts"); got != http.StatusForbidden {
		t.Fatalf("viewer create account=%d want 403", got)
	}
	// Technician can configure collectors but not manage accounts or rotate.
	if got := put(techCookie, techCSRF, "/api/v1/collectors", `{"interval_seconds":60,"cpu":true}`); got != http.StatusOK {
		t.Fatalf("technician configure collectors=%d want 200", got)
	}
	if got := post(techCookie, techCSRF, "/api/v1/rotate"); got != http.StatusForbidden {
		t.Fatalf("technician rotate=%d want 403", got)
	}
	if got := post(techCookie, techCSRF, "/api/v1/accounts"); got != http.StatusForbidden {
		t.Fatalf("technician create account=%d want 403", got)
	}
	// Administrator reaches rotate (unpaired -> 409, not 403) and manages accounts.
	if got := post(adminCookie, adminCSRF, "/api/v1/rotate"); got != http.StatusConflict {
		t.Fatalf("admin rotate unpaired=%d want 409", got)
	}
	accountBody := `{"email":"new@local","password":"role-pass-1","role":"viewer"}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/accounts", bytes.NewBufferString(accountBody))
	request.AddCookie(adminCookie)
	request.Header.Set("X-Watchpost-Agent-CSRF", adminCSRF)
	request.Header.Set("Origin", "http://example.com")
	request.Host = "example.com"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("admin create account=%d %s", response.Code, response.Body.String())
	}
}

func TestTrustedProxyOriginHandling(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	setupApp := func(trusted bool) http.Handler {
		manager := auth.New(store)
		_ = manager.Setup("admin@local", "admin-pass-1")
		return New(store, "test", fs.FS(assets), Options{TrustedProxy: trusted}).Handler()
	}
	login := func(handler http.Handler, forwardedProto, forwardedHost string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(`{"email":"admin@local","password":"admin-pass-1"}`))
		request.Header.Set("Origin", "https://proxy.example")
		request.Host = "127.0.0.1:8090"
		request.Header.Set("X-Forwarded-Proto", forwardedProto)
		request.Header.Set("X-Forwarded-Host", forwardedHost)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	// With an explicitly trusted proxy, forwarded https origin matches.
	if got := login(setupApp(true), "https", "proxy.example"); got != http.StatusOK {
		t.Fatalf("trusted proxy login=%d want 200", got)
	}
	// Without trust, the forwarded https origin is refused (the server sees http).
	if got := login(setupApp(false), "https", "proxy.example"); got != http.StatusForbidden {
		t.Fatalf("untrusted forwarded scheme login=%d want 403", got)
	}
	// A trusted proxy claiming a different host must not match.
	if got := login(setupApp(true), "https", "other.example"); got != http.StatusForbidden {
		t.Fatalf("trusted proxy wrong forwarded host=%d want 403", got)
	}
}
