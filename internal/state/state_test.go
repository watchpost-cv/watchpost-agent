package state

import (
	"path/filepath"
	"testing"
)

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
