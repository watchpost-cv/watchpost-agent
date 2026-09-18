package service

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledDataDirFromManagedUnit(t *testing.T) {
	_, _, paths := fakeManager(t)
	dataDir := filepath.Join(t.TempDir(), "agent-data")
	paths.DataDir = dataDir
	unit := buildUnit(paths, Options{Host: "127.0.0.1", Port: "7335"})
	if err := os.WriteFile(paths.Unit, []byte(unit), 0600); err != nil {
		t.Fatal(err)
	}

	got, ok, err := (Manager{}).InstalledDataDir(paths)
	if err != nil {
		t.Fatalf("InstalledDataDir: %v", err)
	}
	if !ok || got != dataDir {
		t.Fatalf("InstalledDataDir = (%q, %v), want (%q, true)", got, ok, dataDir)
	}
}

func TestInstalledDataDirNotInstalled(t *testing.T) {
	_, _, paths := fakeManager(t)
	got, ok, err := (Manager{}).InstalledDataDir(paths)
	if err != nil {
		t.Fatalf("InstalledDataDir: %v", err)
	}
	if ok || got != "" {
		t.Fatalf("InstalledDataDir = (%q, %v), want (\"\", false)", got, ok)
	}
}

// TestInstalledDataDirFailsClosedOnLegacyUnit verifies a managed unit that
// predates the data-dir marker stays valid for lifecycle operations but cannot
// be used by destructive commands, which must fail closed rather than falling
// back to a different directory.
func TestInstalledDataDirFailsClosedOnLegacyUnit(t *testing.T) {
	_, _, paths := fakeManager(t)
	body := "# watchpost-agent-listen: 127.0.0.1:7335\n# watchpost-agent-listen-mode: bootstrap\n# watchpost-agent-health: " + healthPath + "\n" + renderUnitBody(paths, Options{Host: "127.0.0.1", Port: "7335"})
	sum := sha256.Sum256([]byte(body))
	legacy := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + body
	if err := os.WriteFile(paths.Unit, []byte(legacy), 0600); err != nil {
		t.Fatal(err)
	}

	// The legacy unit is still a valid managed unit for lifecycle operations.
	if _, err := readManagedUnitFile(paths.Unit); err != nil {
		t.Fatalf("legacy unit must remain valid: %v", err)
	}
	got, ok, err := (Manager{}).InstalledDataDir(paths)
	if err == nil {
		t.Fatalf("InstalledDataDir = (%q, %v), want a fail-closed error", got, ok)
	}
	if !strings.Contains(err.Error(), "predates data-directory metadata") {
		t.Fatalf("error %q missing actionable legacy-unit guidance", err)
	}
}