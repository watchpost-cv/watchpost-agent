package agentassets

import (
	"strings"
	"testing"
)

func TestPublicShellHasOneHeader(t *testing.T) {
	page, err := Public.ReadFile("public/index.html")
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if got := strings.Count(html, "<header"); got != 1 {
		t.Fatalf("public shell contains %d headers, want 1", got)
	}
	if strings.Contains(html, "header-state") || strings.Contains(html, "Starting…") {
		t.Fatal("public shell still contains the obsolete pre-SPA header")
	}
}
