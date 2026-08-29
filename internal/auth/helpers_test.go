package auth

import (
	"path/filepath"
	"testing"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

func openStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
