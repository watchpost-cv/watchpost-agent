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
