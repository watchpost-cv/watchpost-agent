package app

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"

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

func trustedProxyOptions(trusted bool, allow, deny string) Options {
	opts := Options{}
	if trusted {
		opts.TrustedProxies = []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}}
	}
	if allow != "" {
		_, network, _ := net.ParseCIDR(allow)
		opts.AllowCIDRs = []*net.IPNet{network}
	}
	if deny != "" {
		_, network, _ := net.ParseCIDR(deny)
		opts.DenyCIDRs = []*net.IPNet{network}
	}
	return opts
}

func TestProxyOriginHandlingRequiresTrustedPeer(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	setupApp := func(opts Options) http.Handler {
		manager := auth.New(store)
		_ = manager.Setup("admin@local", "admin-pass-1", "")
		return New(store, "test", fs.FS(assets), opts).Handler()
	}
	login := func(handler http.Handler, remoteAddr, forwardedProto, forwardedHost string) int {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/login", bytes.NewBufferString(`{"email":"admin@local","password":"admin-pass-1"}`))
		request.RemoteAddr = remoteAddr
		request.Header.Set("Origin", "https://proxy.example")
		request.Host = "127.0.0.1:8090"
		request.Header.Set("X-Forwarded-Proto", forwardedProto)
		request.Header.Set("X-Forwarded-Host", forwardedHost)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	trusted := trustedProxyOptions(true, "", "")
	// A trusted peer's forwarded https origin is honoured.
	if got := login(setupApp(trusted), "127.0.0.1:9999", "https", "proxy.example"); got != http.StatusOK {
		t.Fatalf("trusted proxy login=%d want 200", got)
	}
	// An untrusted peer's forwarded https origin is refused (spoofing).
	untrusted := trustedProxyOptions(false, "", "")
	if got := login(setupApp(untrusted), "192.0.2.5:9999", "https", "proxy.example"); got != http.StatusForbidden {
		t.Fatalf("untrusted peer spoofed origin login=%d want 403", got)
	}
	// A trusted proxy claiming a different host must not match.
	if got := login(setupApp(trusted), "127.0.0.1:9999", "https", "other.example"); got != http.StatusForbidden {
		t.Fatalf("trusted proxy wrong forwarded host=%d want 403", got)
	}
}

func TestClientAddressResolutionThroughTrustedProxies(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	opts := trustedProxyOptions(true, "", "")
	opts.TrustedProxies = []*net.IPNet{{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(32, 32)}, {IP: net.ParseIP("10.0.0.0"), Mask: net.CIDRMask(8, 32)}}
	_, v4, _ := net.ParseCIDR("192.0.2.0/24")
	_, v6, _ := net.ParseCIDR("2001:db8::/32")
	opts.AllowCIDRs = []*net.IPNet{v4, v6}
	handler := New(store, "test", fs.FS(assets), opts).Handler()

	status := func(remoteAddr, xff string) int {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
		request.RemoteAddr = remoteAddr
		if xff != "" {
			request.Header.Set("X-Forwarded-For", xff)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response.Code
	}
	// Allowed client through a trusted proxy.
	if got := status("127.0.0.1:9999", "192.0.2.10"); got != http.StatusUnauthorized {
		t.Fatalf("allowed proxied client=%d want 401", got)
	}
	// Denied client through a trusted proxy.
	if got := status("127.0.0.1:9999", "198.51.100.5"); got != http.StatusForbidden {
		t.Fatalf("denied proxied client=%d want 403", got)
	}
	// Direct spoofing: an untrusted peer's X-Forwarded-For must not bypass deny.
	if got := status("198.51.100.5:9999", "192.0.2.10"); got != http.StatusForbidden {
		t.Fatalf("untrusted peer spoofed XFF=%d want 403", got)
	}
	// Multiple trusted hops resolve to the first untrusted address.
	if got := status("10.1.1.1:9999", "192.0.2.10, 10.2.2.2"); got != http.StatusUnauthorized {
		t.Fatalf("multi-hop proxied client=%d want 401", got)
	}
	// IPv6 client through a trusted proxy.
	if got := status("127.0.0.1:9999", "2001:db8::1"); got != http.StatusUnauthorized {
		t.Fatalf("ipv6 proxied client=%d want 401", got)
	}
	// IPv6 client outside the allow list is denied.
	if got := status("127.0.0.1:9999", "2001:db9::1"); got != http.StatusForbidden {
		t.Fatalf("ipv6 unallowed client=%d want 403", got)
	}
	// Malformed forwarded header from a trusted proxy fails closed.
	if got := status("127.0.0.1:9999", "not-an-ip"); got != http.StatusForbidden {
		t.Fatalf("malformed XFF=%d want 403", got)
	}
	// Unresolvable RemoteAddr with a policy active fails closed.
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.RemoteAddr = "not-an-address"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("unresolvable remote with policy=%d want 403", response.Code)
	}
}

func TestClientResolutionFailsOpenWithoutPolicyOnLoopbackRecovery(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	handler := New(store, "test", fs.FS(assets), Options{}).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	request.RemoteAddr = "not-an-address"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	// No policy active: the loopback recovery path lets the request proceed
	// to authentication (401 rather than a policy denial).
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("no-policy unresolvable remote=%d want 401", response.Code)
	}
}

func TestRemoteSetupRequiresBootstrapToken(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := auth.New(store)
	if err := manager.StoreBootstrapToken("remote-setup-token", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	handler := New(store, "test", fs.FS(assets), Options{SetupTokenRequired: true}).Handler()
	bootstrap := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap", nil)
	bootRec := httptest.NewRecorder()
	handler.ServeHTTP(bootRec, bootstrap)
	if !bytes.Contains(bootRec.Body.Bytes(), []byte(`"setup_token_required":true`)) {
		t.Fatalf("bootstrap must report token required: %s", bootRec.Body.String())
	}
	noToken := httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewBufferString(`{"email":"admin@local","password":"1234567"}`))
	noToken.Header.Set("Origin", "http://example.com")
	noToken.Host = "example.com"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, noToken)
	if rec.Code != http.StatusConflict {
		t.Fatalf("setup without token=%d want 409", rec.Code)
	}
	withToken := httptest.NewRequest(http.MethodPost, "/api/v1/setup", bytes.NewBufferString(`{"email":"admin@local","password":"1234567","token":"remote-setup-token"}`))
	withToken.Header.Set("Origin", "http://example.com")
	withToken.Host = "example.com"
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, withToken)
	if rec2.Code != http.StatusNoContent {
		t.Fatalf("setup with token=%d %s", rec2.Code, rec2.Body.String())
	}
	// The token is never disclosed by status or bootstrap.
	status := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	statusRec := httptest.NewRecorder()
	handler.ServeHTTP(statusRec, status)
	if bytes.Contains(statusRec.Body.Bytes(), []byte("remote-setup-token")) {
		t.Fatal("status disclosed the bootstrap token")
	}
}
