package auth

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost-agent/internal/state"
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
	if err = manager.Setup("admin", "admin@local", "short", ""); err == nil {
		t.Fatal("short password accepted")
	}
	if err = manager.Setup("admin", "admin@local", "1234567", ""); err != nil {
		t.Fatal(err)
	}
	if manager.SetupRequired() {
		t.Fatal("setup was not persisted")
	}
	session, err := manager.Login("admin@local", "1234567")
	if err != nil || session.Token == "" || session.CSRF == "" {
		t.Fatalf("session=%#v err=%v", session, err)
	}
	if _, ok := manager.Authenticate(session.Token); !ok {
		t.Fatal("session not accepted")
	}
	if err := manager.Logout(session.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok := manager.Authenticate(session.Token); ok {
		t.Fatal("logged-out session accepted")
	}
}

func TestSessionSurvivesManagerRestart(t *testing.T) {
	store := openStore(t)
	manager := New(store)
	if err := manager.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session, err := manager.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	restarted := New(store)
	if got, ok := restarted.Authenticate(session.Token); !ok || got.User.Email != "admin@local" || got.CSRF != session.CSRF {
		t.Fatalf("durable session not restored: %#v ok=%v", got, ok)
	}
}

func TestRoleCapabilities(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	admin, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil || admin.User.Role != "admin" {
		t.Fatalf("admin login: %#v %v", admin, err)
	}
	if _, err := m.CreateAccount("admin@local", "tech", "tech@local", "1234567", "technician"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "view", "view@local", "1234567", "viewer"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "bad", "bad@local", "1234567", "superuser"); err == nil {
		t.Fatal("invalid role accepted")
	}
	items := m.ListAccounts()
	if len(items) != 3 {
		t.Fatalf("accounts=%d want 3", len(items))
	}
	if _, err := m.Login("unknown@local", "definitely-wrong-password"); err == nil {
		t.Fatal("throttled/unknown login accepted")
	}
}

func TestSessionRevocationAndPasswordChange(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session1, _ := m.Login("admin@local", "correct-horse-battery")
	session2, _ := m.Login("admin@local", "correct-horse-battery")
	if err := m.ChangePassword(session1.User.ID, "correct-horse-battery", "new-password-1", session1.Token); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Authenticate(session2.Token); ok {
		t.Fatal("other session survived password change")
	}
	if _, ok := m.Authenticate(session1.Token); !ok {
		t.Fatal("current session revoked")
	}
	removed, err := m.RevokeUserSessions("admin@local", session1.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removed < 1 {
		t.Fatalf("revoke sessions removed=%d", removed)
	}
	if _, ok := m.Authenticate(session1.Token); ok {
		t.Fatal("session survived explicit revocation")
	}
}

func TestSharedPasswordResolvesEachEmailToOwnIdentity(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "shared-password-1", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "tech", "tech@local", "shared-password-1", "technician"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "view", "view@local", "shared-password-1", "viewer"); err != nil {
		t.Fatal(err)
	}
	cases := []struct{ email, role string }{
		{"admin@local", "admin"},
		{"tech@local", "technician"},
		{"view@local", "viewer"},
	}
	for _, tc := range cases {
		session, err := m.Login(tc.email, "shared-password-1")
		if err != nil {
			t.Fatalf("login %s: %v", tc.email, err)
		}
		if session.User.Email != tc.email || session.User.Role != tc.role {
			t.Fatalf("login %s resolved to %#v", tc.email, session.User)
		}
	}
}

func TestLoginRejectsUnknownEmailAndWrongPassword(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login("nobody@local", "correct-horse-battery"); err == nil {
		t.Fatal("unknown email authenticated")
	}
	if _, err := m.Login("admin@local", "wrong-password"); err == nil {
		t.Fatal("wrong password authenticated")
	}
}

func TestLoginRejectsWrongUsernameAndCrossedCredentials(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	// Wrong username with the correct password must not authenticate.
	if _, err := m.Login("nobody", "correct-horse-battery"); err == nil {
		t.Fatal("wrong username authenticated")
	}
	// Correct username with the wrong password must not authenticate.
	if _, err := m.Login("admin", "wrong-password"); err == nil {
		t.Fatal("wrong password authenticated against username")
	}
	// A username that is not a valid email must still be rejected cleanly.
	if _, err := m.Login("", "correct-horse-battery"); err == nil {
		t.Fatal("empty identifier authenticated")
	}
}

func TestDuplicateEmailRejectedCaseInsensitively(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("Admin", "Admin@Local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	// Distinct username but the same (case-insensitive) email must be rejected
	// by email uniqueness, not merely by username collision.
	if _, err := m.CreateAccount("admin@local", "another", "admin@LOCAL", "another-password-1", "viewer"); err == nil {
		t.Fatal("duplicate normalized email accepted")
	}
	if _, err := m.CreateAccount("admin@local", "TECH", "TECH@local", "another-password-1", "technician"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "other", "tech@LOCAL", "another-password-1", "viewer"); err == nil {
		t.Fatal("duplicate normalized technician email accepted")
	}
}

func TestUsernameLoginWorksAfterSetup(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Login("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("login by username failed: %v", err)
	}
	if _, err := m.Login("admin@local", "correct-horse-battery"); err != nil {
		t.Fatalf("login by email failed: %v", err)
	}
}

func TestLoginNormalizesEmailCase(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("Admin", "Admin@Example.COM", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login("  admin@example.com  ", "correct-horse-battery")
	if err != nil {
		t.Fatalf("case/whitespace login failed: %v", err)
	}
	if session.User.Email != "admin@example.com" {
		t.Fatalf("normalized email=%q", session.User.Email)
	}
}

func TestBootstrapTokenRequiredForRemoteSetup(t *testing.T) {
	store := openStore(t)
	m := New(store)
	m.SetBootstrapTokenRequired(true)
	token, err := m.GenerateBootstrapToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err == nil {
		t.Fatal("setup without token succeeded")
	}
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", "wrong-token"); err == nil {
		t.Fatal("setup with wrong token succeeded")
	}
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", token); err != nil {
		t.Fatalf("setup with token failed: %v", err)
	}
	// Only a hash is persisted.
	state := store.Snapshot()
	if state.LocalAuth.Bootstrap.Hash == token || state.LocalAuth.Bootstrap.Hash == "" {
		t.Fatal("raw token persisted instead of a hash")
	}
	// The consumed token cannot be replayed (setup is also complete).
	if err := m.Setup("other", "other@local", "correct-horse-battery", token); err == nil {
		t.Fatal("second setup with the same token succeeded")
	}
}

func TestBootstrapTokenExpiryFailsClosed(t *testing.T) {
	store := openStore(t)
	m := New(store)
	m.SetBootstrapTokenRequired(true)
	if err := m.StoreBootstrapToken("expired-token", time.Now().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", "expired-token"); err == nil {
		t.Fatal("setup with an expired token succeeded")
	}
}

func TestLoopbackSetupRemainsDirectWithoutToken(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if m.BootstrapTokenRequired() {
		t.Fatal("loopback setup unexpectedly requires a token")
	}
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatalf("direct loopback setup failed: %v", err)
	}
}

func TestConcurrentSetupWithBootstrapTokenCreatesOneAdministrator(t *testing.T) {
	store := openStore(t)
	m := New(store)
	m.SetBootstrapTokenRequired(true)
	token, err := m.GenerateBootstrapToken(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, email := range []string{"one@local", "two@local"} {
		wg.Add(1)
		go func(e string) {
			defer wg.Done()
			err := m.Setup("admin", e, "correct-horse-battery", token)
			results <- err == nil
		}(email)
	}
	wg.Wait()
	close(results)
	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("successes=%d want 1", successes)
	}
}

func TestPasswordHashesUseCanonicalGantryFormat(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if len(snapshot.LocalAuth.Accounts.Accounts) != 1 {
		t.Fatalf("accounts=%d", len(snapshot.LocalAuth.Accounts.Accounts))
	}
	account := snapshot.LocalAuth.Accounts.Accounts[0]
	passwordHash := account.Identities[0].PasswordHash
	if !strings.HasPrefix(passwordHash, "pbkdf2-sha256$310000$") {
		t.Fatalf("password hash is not canonical Gantry PBKDF2: %q", passwordHash)
	}
	if session, err := m.Login("admin@local", "correct-horse-battery"); err != nil || session.User.Role != "admin" {
		t.Fatalf("PBKDF2 login failed: %v", err)
	}
	// A legacy custom iterated-SHA-256 hash must fail closed, forcing re-setup.
	if verifyPassword("correct-horse-battery", "", "deadbeef") {
		t.Fatal("legacy unversioned hash verified")
	}
}

func auditEntries(store *state.Store, action string) []state.AuditEntry {
	entries := []state.AuditEntry{}
	for _, entry := range store.Snapshot().LocalAuth.Audit {
		if entry.Action == action {
			entries = append(entries, entry)
		}
	}
	return entries
}

func TestAccountCreationEmitsSingleAuditWithRealActor(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "tech", "tech@local", "1234567", "technician"); err != nil {
		t.Fatal(err)
	}
	entries := auditEntries(store, "account_create")
	if len(entries) != 1 {
		t.Fatalf("account_create rows=%d want exactly 1", len(entries))
	}
	if entries[0].Actor != "admin@local" {
		t.Fatalf("account_create actor=%q want admin@local", entries[0].Actor)
	}
	if entries[0].Detail != "tech@local role=technician" {
		t.Fatalf("account_create detail=%q", entries[0].Detail)
	}
}

func TestChangePasswordEmitsSingleAuditWithSelfActor(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	account, err := m.CreateAccount("admin@local", "tech", "tech@local", "1234567", "technician")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePassword(account.ID, "1234567", "new-password-1", "keep-token"); err != nil {
		t.Fatal(err)
	}
	entries := auditEntries(store, "password_change")
	if len(entries) != 1 {
		t.Fatalf("password_change rows=%d want exactly 1", len(entries))
	}
	if entries[0].Actor != "tech@local" {
		t.Fatalf("password_change actor=%q want tech@local", entries[0].Actor)
	}
}

func TestFailedAuditSaveRollsBackAccountCreation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	beforeAccounts := len(store.Snapshot().LocalAuth.Accounts.Accounts)
	beforeAudit := len(store.Snapshot().LocalAuth.Audit)
	// Replace the state file with a directory so the next save fails.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "op", "op@local", "1234567", "viewer"); err == nil {
		t.Fatal("account creation with broken save succeeded")
	}
	snapshot := store.Snapshot()
	if len(snapshot.LocalAuth.Accounts.Accounts) != beforeAccounts {
		t.Fatalf("account list changed on failed save: %d", len(snapshot.LocalAuth.Accounts.Accounts))
	}
	if len(snapshot.LocalAuth.Audit) != beforeAudit {
		t.Fatalf("audit changed on failed save: %d", len(snapshot.LocalAuth.Audit))
	}
}

func TestVerifyPasswordRejectsMalformedAndBoundedEncodings(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	account := store.Snapshot().LocalAuth.Accounts.Accounts[0]
	passwordHash := account.Identities[0].PasswordHash
	if !verifyPassword("correct-horse-battery", "", passwordHash) {
		t.Fatal("valid hash rejected")
	}
	// Empty and truncated payloads.
	if verifyPassword("correct-horse-battery", "", "pbkdf2-sha256$310000$$") {
		t.Fatal("empty derived key accepted")
	}
	if verifyPassword("correct-horse-battery", "", "pbkdf2-sha256$310000$aa$aa") {
		t.Fatal("truncated derived key accepted")
	}
	// Oversized derived key (33+ decoded bytes).
	if verifyPassword("correct-horse-battery", "", "pbkdf2-sha256$310000$"+strings.Repeat("aa", 16)+"$"+strings.Repeat("aa", 33)) {
		t.Fatal("oversized derived key accepted")
	}
	// Out-of-bound work factors.
	for _, iterations := range []int{0, 1, 9999, 10000001, 1000000000} {
		parts := strings.Split(passwordHash, "$")
		bad := "pbkdf2-sha256$" + strconv.Itoa(iterations) + "$" + parts[2] + "$" + parts[3]
		if verifyPassword("correct-horse-battery", "", bad) {
			t.Fatalf("out-of-bound work factor %d accepted", iterations)
		}
	}
	// Wrong algorithm prefix and non-hex payload.
	if verifyPassword("correct-horse-battery", "", strings.Replace(passwordHash, "pbkdf2-sha256", "sha256", 1)) {
		t.Fatal("wrong algorithm accepted")
	}
	if verifyPassword("correct-horse-battery", "", "pbkdf2-sha256$310000$not-hex!$aaaa") {
		t.Fatal("non-hex derived key accepted")
	}
	// A wrong password with an otherwise valid hash must still fail.
	if verifyPassword("wrong-password", "", passwordHash) {
		t.Fatal("wrong password verified")
	}
}

func breakNextSave(path string) {
	if err := os.Remove(path); err != nil {
		panic(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		panic(err)
	}
}

func TestLoginAuditFailureCreatesNoSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sessions) != 1 {
		t.Fatalf("sessions=%d want 1", len(m.sessions))
	}
	breakNextSave(path)
	if _, err := m.Login("admin@local", "correct-horse-battery"); !errors.Is(err, ErrAuditPersistence) {
		t.Fatalf("login with broken save err=%v want ErrAuditPersistence", err)
	}
	if len(m.sessions) != 1 {
		t.Fatalf("failed login created a session: %d", len(m.sessions))
	}
	if got := len(auditEntries(store, "login")); got != 1 {
		t.Fatalf("login audit rows=%d want 1", got)
	}
	if _, ok := m.Authenticate(session.Token); !ok {
		t.Fatal("existing session invalidated by failed login")
	}
}

func TestLogoutAuditFailureLeavesSessionValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	session, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	breakNextSave(path)
	if err := m.Logout(session.Token); !errors.Is(err, ErrAuditPersistence) {
		t.Fatalf("logout with broken save err=%v want ErrAuditPersistence", err)
	}
	if _, ok := m.Authenticate(session.Token); !ok {
		t.Fatal("session revoked on failed logout")
	}
	if got := len(auditEntries(store, "logout")); got != 0 {
		t.Fatalf("logout audit rows=%d want 0", got)
	}
}

func TestRevokeAuditFailureLeavesSessionsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	first, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	if len(m.sessions) != 2 {
		t.Fatalf("sessions=%d want 2", len(m.sessions))
	}
	breakNextSave(path)
	if _, err := m.RevokeUserSessions("admin@local", first.User.ID); !errors.Is(err, ErrAuditPersistence) {
		t.Fatalf("revoke with broken save err=%v want ErrAuditPersistence", err)
	}
	if len(m.sessions) != 2 {
		t.Fatalf("sessions revoked on failed audit: %d", len(m.sessions))
	}
	if _, ok := m.Authenticate(first.Token); !ok {
		t.Fatal("targeted session revoked on failed audit")
	}
	if _, ok := m.Authenticate(second.Token); !ok {
		t.Fatal("second session revoked on failed audit")
	}
	if got := len(auditEntries(store, "account_revoke_sessions")); got != 0 {
		t.Fatalf("revoke audit rows=%d want 0", got)
	}
}

func TestSuccessfulSessionEventsEmitSingleAttributedAudit(t *testing.T) {
	store := openStore(t)
	m := New(store)
	if err := m.Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateAccount("admin@local", "tech", "tech@local", "1234567", "technician"); err != nil {
		t.Fatal(err)
	}
	adminSession, err := m.Login("admin@local", "correct-horse-battery")
	if err != nil {
		t.Fatal(err)
	}
	techSession, err := m.Login("tech@local", "1234567")
	if err != nil {
		t.Fatal(err)
	}
	loginRows := auditEntries(store, "login")
	if len(loginRows) != 2 {
		t.Fatalf("login rows=%d want 2", len(loginRows))
	}
	if loginRows[0].Actor != "admin@local" || loginRows[1].Actor != "tech@local" {
		t.Fatalf("login actors=%q,%q", loginRows[0].Actor, loginRows[1].Actor)
	}
	if err := m.Logout(techSession.Token); err != nil {
		t.Fatal(err)
	}
	logoutRows := auditEntries(store, "logout")
	if len(logoutRows) != 1 {
		t.Fatalf("logout rows=%d want 1", len(logoutRows))
	}
	if logoutRows[0].Actor != "tech@local" {
		t.Fatalf("logout actor=%q want tech@local", logoutRows[0].Actor)
	}
	removed, err := m.RevokeUserSessions("admin@local", adminSession.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("revoked=%d want 1", removed)
	}
	revokeRows := auditEntries(store, "account_revoke_sessions")
	if len(revokeRows) != 1 {
		t.Fatalf("revoke rows=%d want 1", len(revokeRows))
	}
	if revokeRows[0].Actor != "admin@local" || revokeRows[0].Detail != "account="+adminSession.User.ID {
		t.Fatalf("revoke actor=%q detail=%q", revokeRows[0].Actor, revokeRows[0].Detail)
	}
}

func TestOutOfBandSetupRecognisedWithoutRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := New(store)
	if !m.SetupRequired() {
		t.Fatal("expected setup required initially")
	}
	// Simulate `watchpost-agent setup` in a separate process/store writing the
	// administrator to the same agent.json.
	cliStore, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := New(cliStore).Setup("admin", "admin@local", "correct-horse-battery", ""); err != nil {
		t.Fatal(err)
	}
	// The running manager must observe the change without a restart.
	if m.SetupRequired() {
		t.Fatal("out-of-band setup not recognised without restart")
	}
	if _, err := m.Login("admin", "correct-horse-battery"); err != nil {
		t.Fatalf("login by out-of-band administrator failed: %v", err)
	}
}
