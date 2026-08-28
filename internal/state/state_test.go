package state

import (
	"os"
	"path/filepath"
	"testing"
)

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
		value.LocalAuth = LocalAuth{PasswordHash: "hash"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = store.Unpair(); err != nil {
		t.Fatal(err)
	}
	after := store.Snapshot()
	if after.Connection.Credential != "" || after.LocalAuth.PasswordHash == "" {
		t.Fatal("unpair crossed local auth boundary")
	}
	if store.Reset("wrong") == nil {
		t.Fatal("reset accepted wrong confirmation")
	}
	if err = store.Reset(id); err != nil {
		t.Fatal(err)
	}
	after = store.Snapshot()
	if after.LocalAuth.PasswordHash != "" || after.InstallationID != id {
		t.Fatal("reset did not preserve installation identity boundary")
	}
}
