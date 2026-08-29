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

func TestRoleCapabilities(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	admin, err := m.Login("correct-horse-battery")
	if err != nil || admin.User.Role != "admin" {
		t.Fatalf("admin login: %#v %v", admin, err)
	}
	if _, err := m.CreateAccount("tech@local", "1234567", "technician"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("view@local", "1234567", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("bad@local", "1234567", "superuser"); err == nil {
		t.Fatal("invalid role accepted")
	}
	items := m.ListAccounts()
	if len(items) != 3 {
		t.Fatalf("accounts=%d want 3", len(items))
	}
	if _, err := m.Login("definitely-wrong-password"); err == nil {
		t.Fatal("throttled/unknown login accepted")
	}
}

func TestSessionRevocationAndPasswordChange(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("correct-horse-battery"); err != nil {
		t.Fatal(err)
	}
	session1, _ := m.Login("correct-horse-battery")
	session2, _ := m.Login("correct-horse-battery")
	if err := m.ChangePassword(session1.User.ID, "correct-horse-battery", "new-password-1", session1.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Authenticate(session2.Token); ok {
		t.Fatal("other session survived password change")
	}
	if _, ok := m.Authenticate(session1.Token); !ok {
		t.Fatal("current session revoked")
	}
	if removed := m.RevokeUserSessions(session1.User.ID); removed < 1 {
		t.Fatalf("revoke sessions removed=%d", removed)
	}
	if _, ok := m.Authenticate(session1.Token); ok {
		t.Fatal("session survived explicit revocation")
	}
}
