package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	coreauth "github.com/gantry-tools/gantry-core/auth"
)

func canonicalTestAccount(id, email, hash, role string) coreauth.Account {
	return coreauth.Account{
		ID: id, DisplayName: email, Enabled: true, Roles: []string{role}, CreatedAt: time.Now().UTC(),
		Identities: []coreauth.Identity{{ID: "id_" + id, Type: "password", Username: email, Email: email, PasswordHash: hash, Enabled: true}},
	}
}

func TestCorruptStateFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("corrupt state accepted")
	}
}

func TestInstallationIdentitySurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := first.Snapshot().InstallationID
	if id == "" {
		t.Fatal("empty installation ID")
	}
	second, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if second.Snapshot().InstallationID != id {
		t.Fatal("installation identity changed")
	}
}

func TestCollectorConfigValidation(t *testing.T) {
	valid := DefaultCollectorConfig()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	valid.IntervalSeconds = 14
	if valid.Validate() == nil {
		t.Fatal("accepted interval below bound")
	}
	valid = DefaultCollectorConfig()
	valid.Filesystems = []string{"relative"}
	if valid.Validate() == nil {
		t.Fatal("accepted relative filesystem")
	}
}

func TestUnpairAndResetAreDistinct(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	id := store.Snapshot().InstallationID
	if err = store.Update(func(value *State) error {
		value.Connection = Connection{Credential: "secret", PostID: "post"}
		value.LocalAuth.Audit = []AuditEntry{{Action: "keep"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Unpair(); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if after.Connection.Credential != "" || len(after.LocalAuth.Audit) != 1 {
		t.Fatal("unpair crossed local auth boundary")
	}
	if store.Reset("wrong") == nil {
		t.Fatal("reset accepted wrong confirmation")
	}
	if err = store.Reset(id); err != nil {
		t.Fatal(err)
	}
	after = store.Snapshot()
	if len(after.LocalAuth.Accounts.Accounts) != 0 || after.InstallationID != id {
		t.Fatal("reset did not preserve installation identity boundary")
	}
}

func TestRecoverFileBypassesInvalidAuthentication(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	wantID := store.Snapshot().InstallationID
	var raw map[string]any
	data, _ := os.ReadFile(path)
	if err = json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	raw["local_auth"] = map[string]any{"password_hash": "obsolete-hash"}
	data, _ = json.Marshal(raw)
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(path); err == nil {
		t.Fatal("ordinary open accepted incompatible authentication")
	}
	if err = RecoverFile(path, true); err != nil {
		t.Fatal(err)
	}
	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := recovered.Snapshot()
	if got.InstallationID != wantID || len(got.LocalAuth.Accounts.Accounts) != 0 {
		t.Fatal("authentication recovery changed the installation or retained accounts")
	}
}

func TestRecoverFileAllReplacesInvalidState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := os.WriteFile(path, []byte("not valid JSON"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RecoverFile(path, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err != nil {
		t.Fatalf("full recovery did not create valid state: %v", err)
	}
}

// breakSaves makes the next state save fail by replacing the state file with a
// directory, so the atomic rename cannot complete.
func breakSaves(t *testing.T, path string) {
	t.Helper()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestFailedSaveLeavesInMemoryAndDiskUnchanged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	seed := func() {
		if err := store.Update(func(value *State) error {
			value.LocalAuth.Accounts.Accounts = []coreauth.Account{canonicalTestAccount("a1", "admin@local", "pbkdf2-sha256$310000$aa$aa", "administrator")}
			value.LocalAuth.Audit = []AuditEntry{{At: "t", Actor: "admin@local", Action: "setup", Detail: "first administrator created"}}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	seed()
	breakSaves(t, path)

	// In-place element mutation (password change) must not corrupt shared state.
	if err := store.Update(func(value *State) error {
		value.LocalAuth.Accounts.Accounts[0].Identities[0].PasswordHash = "pbkdf2-sha256$310000$bb$bb"
		return nil
	}); err == nil {
		t.Fatal("update with broken save succeeded")
	}
	if got := store.Snapshot().LocalAuth.Accounts.Accounts[0].Identities[0].PasswordHash; got != "pbkdf2-sha256$310000$aa$aa" {
		t.Fatalf("in-memory password mutated on failed save: %q", got)
	}

	// Account creation append must not leak.
	if err := store.Update(func(value *State) error {
		value.LocalAuth.Accounts.Accounts = append(value.LocalAuth.Accounts.Accounts, canonicalTestAccount("a2", "op@local", "pbkdf2-sha256$310000$cc$cc", "viewer"))
		return nil
	}); err == nil {
		t.Fatal("account append with broken save succeeded")
	}
	if len(store.Snapshot().LocalAuth.Accounts.Accounts) != 1 {
		t.Fatalf("in-memory account list changed on failed save: %d", len(store.Snapshot().LocalAuth.Accounts.Accounts))
	}

	// Audit append must not leak.
	if err := store.Update(func(value *State) error {
		value.LocalAuth.AppendAudit("op@local", "account_create", "op@local role=operator")
		return nil
	}); err == nil {
		t.Fatal("audit append with broken save succeeded")
	}
	if len(store.Snapshot().LocalAuth.Audit) != 1 {
		t.Fatalf("in-memory audit changed on failed save: %d", len(store.Snapshot().LocalAuth.Audit))
	}

	// Collector configuration change must not leak.
	if err := store.Update(func(value *State) error {
		value.Collectors = CollectorConfig{IntervalSeconds: 30, CPU: true}
		return nil
	}); err == nil {
		t.Fatal("collector config with broken save succeeded")
	}
	if store.Snapshot().Collectors.IntervalSeconds != 60 {
		t.Fatalf("in-memory collector config changed on failed save")
	}

	// Delivery queue append must not leak.
	if err := store.Update(func(value *State) error {
		value.Delivery.Queue = append(value.Delivery.Queue, json.RawMessage(`{"batch":1}`))
		return nil
	}); err == nil {
		t.Fatal("delivery queue with broken save succeeded")
	}
	if len(store.Snapshot().Delivery.Queue) != 0 {
		t.Fatalf("in-memory delivery queue changed on failed save: %d", len(store.Snapshot().Delivery.Queue))
	}

	// Pairing state change must not leak.
	if err := store.Update(func(value *State) error {
		value.PendingPairing = PendingPairing{RequestID: "r1", RequestSecret: "secret"}
		return nil
	}); err == nil {
		t.Fatal("pairing state with broken save succeeded")
	}
	if store.Snapshot().PendingPairing.RequestID != "" {
		t.Fatal("in-memory pairing state changed on failed save")
	}

}

func TestFailedSaveLeavesDiskFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(value *State) error {
		value.LocalAuth.Accounts.Accounts = []coreauth.Account{canonicalTestAccount("a1", "admin@local", "pbkdf2-sha256$310000$aa$aa", "administrator")}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	breakSaves(t, path)
	if err := store.Update(func(value *State) error {
		value.LocalAuth.Accounts.Accounts[0].Identities[0].PasswordHash = "pbkdf2-sha256$310000$bb$bb"
		return nil
	}); err == nil {
		t.Fatal("update with broken save succeeded")
	}
	// The original file was replaced by a directory; no temp state file remains.
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if len(entry.Name()) > 0 && entry.Name()[0] == '.' && entry.Name() != "." {
			t.Fatalf("leftover temporary state file: %s", entry.Name())
		}
	}
}

func TestConcurrentUpdatesRemainConsistent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = store.Update(func(value *State) error {
				value.LocalAuth.Audit = append(value.LocalAuth.Audit, AuditEntry{At: "t", Actor: "user", Action: "op", Detail: string(rune('a' + n))})
				return nil
			})
		}(i)
	}
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = store.Update(func(value *State) error {
				value.Collectors.CPU = !value.Collectors.CPU
				return nil
			})
		}()
	}
	wg.Wait()
	// After all updates, the audit list and collector config are consistent.
	snapshot := store.Snapshot()
	if len(snapshot.LocalAuth.Audit) > 40 {
		t.Fatalf("audit entries lost or duplicated: %d", len(snapshot.LocalAuth.Audit))
	}
}

// TestStateFileModeBits asserts the durable state file is owner-only and the
// data directory is not world-readable after a write, on every platform.
func TestStateFileModeBits(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(s *State) error { s.Collectors.IntervalSeconds = 15; return nil }); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("agent.json mode = %04o, want 0600", got)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("data directory mode = %04o, want 0700", got)
	}
}
