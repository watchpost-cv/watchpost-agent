package auth

import (
	"path/filepath"
	"testing"

	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

func TestSetupLoginAndSession(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	manager := New(store)
	if !manager.SetupRequired() {
		t.Fatal("fresh agent did not require setup")
	}
	if err = manager.Setup("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if err = manager.Setup("1234567"); err != nil {
		t.Fatal(err)
	}
	if manager.SetupRequired() {
		t.Fatal("setup was not persisted")
	}
	session, err := manager.Login("1234567")
	if err != nil || session.Token == "" || session.CSRF == "" {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if _, ok := manager.Authenticate(session.Token); !ok {
		t.Fatal("session not accepted")
	}
	manager.Logout(session.Token)
	if _, ok := manager.Authenticate(session.Token); ok {
		t.Fatal("logged-out session accepted")
	}
}
