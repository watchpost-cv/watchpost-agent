package app

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

func TestUnpairedStatusAndSecurityHeaders(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	assets := fstest.MapFS{"index.html": &fstest.MapFile{Data: []byte("agent")}}
	handler := New(store, "test", fs.FS(assets)).Handler()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"pairing":"unpaired"`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Frame-Options") != "DENY" || response.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("security headers=%v", response.Header())
	}
}
