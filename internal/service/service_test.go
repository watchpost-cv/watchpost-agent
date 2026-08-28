package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallBeforePairAndAtomicUpgrade(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	paths := Paths{Binary: filepath.Join(directory, "bin", "watchpost-agent"), DataDir: filepath.Join(directory, "state"), Unit: filepath.Join(directory, "unit", "agent.service")}
	if err := os.WriteFile(source, []byte("version one"), 0755); err != nil {
		t.Fatal(err)
	}
	var calls []string
	manager := Manager{Run: func(name string, arguments ...string) error {
		calls = append(calls, name+" "+strings.Join(arguments, " "))
		return nil
	}}
	if err := manager.Install(source, paths); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(paths.DataDir)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("version two"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(source, paths); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(paths.Binary)
	if err != nil || string(installed) != "version two" {
		t.Fatalf("installed=%q err=%v", installed, err)
	}
	unit, err := os.ReadFile(paths.Unit)
	if err != nil || !strings.Contains(string(unit), "NoNewPrivileges=true") || !strings.Contains(string(unit), paths.DataDir) {
		t.Fatalf("unit=%s err=%v", unit, err)
	}
	if len(calls) != 6 || !strings.Contains(calls[2], "restart") || !strings.Contains(calls[5], "restart") {
		t.Fatalf("calls=%v", calls)
	}
}
