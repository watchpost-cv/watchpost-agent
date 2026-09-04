package auth

import (
	"path/filepath"
	"testing"

	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

func openStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}
