package service

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type agentStateMatrixEntry struct {
	name          string
	enabled       string
	active        string
	accepted      bool
	wantEnableSeq []string
	wantActive    string
}

func TestAgentInstallStateMatrix(t *testing.T) {
	matrix := []agentStateMatrixEntry{
		{name: "enabled+active", enabled: "enabled", active: "active", accepted: true, wantEnableSeq: []string{"systemctl enable watchpost-agent.service"}, wantActive: "restart"},
		{name: "enabled+inactive", enabled: "enabled", active: "inactive", accepted: true, wantEnableSeq: []string{"systemctl enable watchpost-agent.service"}, wantActive: "stop"},
		{name: "enabled-runtime+active", enabled: "enabled-runtime", active: "active", accepted: true, wantEnableSeq: []string{"systemctl enable --runtime watchpost-agent.service"}, wantActive: "restart"},
		{name: "enabled-runtime+inactive", enabled: "enabled-runtime", active: "inactive", accepted: true, wantEnableSeq: []string{"systemctl enable --runtime watchpost-agent.service"}, wantActive: "stop"},
		{name: "disabled+active", enabled: "disabled", active: "active", accepted: true, wantEnableSeq: []string{}, wantActive: "restart"},
		{name: "disabled+inactive", enabled: "disabled", active: "inactive", accepted: true, wantEnableSeq: []string{}, wantActive: "stop"},
		{name: "masked+active", enabled: "masked", active: "active", accepted: false},
		{name: "masked-runtime+inactive", enabled: "masked-runtime", active: "inactive", accepted: false},
		{name: "static+inactive", enabled: "static", active: "inactive", accepted: false},
		{name: "linked+inactive", enabled: "linked", active: "inactive", accepted: false},
		{name: "generated+inactive", enabled: "generated", active: "inactive", accepted: false},
		{name: "transient+inactive", enabled: "transient", active: "inactive", accepted: false},
		{name: "failed+inactive", enabled: "failed", active: "inactive", accepted: false},
		{name: "enabled+reloading", enabled: "enabled", active: "reloading", accepted: false},
		{name: "enabled+activating", enabled: "enabled", active: "activating", accepted: false},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			m, r, paths := fakeStrictManager(t)
			installManagedUnit(t, paths)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "agent2")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if tc.accepted {
				// Reinstall with a changed listen reaches the activation path.
				r.script["systemctl daemon-reload"] = fakeResult{}
				r.script["systemctl enable watchpost-agent.service"] = fakeResult{out: "failed to enable", code: 1}
				r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
				r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
				r.script["systemctl disable watchpost-agent.service"] = fakeResult{}
				if e := m.Install(exe, paths, "127.0.0.1:9999", ""); e == nil {
					t.Fatalf("install with activation failure should return an error")
				}
				for _, want := range tc.wantEnableSeq {
					if !contains(r.log, want) {
						t.Fatalf("rollback did not restore enablement %q: log=%v", tc.enabled, r.log)
					}
				}
				if tc.wantEnableSeq == nil {
					if contains(r.log, "systemctl enable --runtime watchpost-agent.service") || contains(r.log, "systemctl enable watchpost-agent.service") {
						t.Fatalf("disabled prior should not be re-enabled: log=%v", r.log)
					}
				}
				if tc.wantActive == "restart" && !contains(r.log, "systemctl restart watchpost-agent.service") {
					t.Fatalf("active prior not restarted on rollback: log=%v", r.log)
				}
				if tc.wantActive == "stop" && !contains(r.log, "systemctl stop watchpost-agent.service") {
					t.Fatalf("inactive prior not stopped on rollback: log=%v", r.log)
				}
			} else {
				beforeBin, _ := os.ReadFile(paths.Binary)
				if e := m.Install(exe, paths, "127.0.0.1:9999", ""); e == nil {
					t.Fatalf("install of non-restorable state %s succeeded", tc.name)
				}
				afterBin, _ := os.ReadFile(paths.Binary)
				if !bytes.Equal(beforeBin, afterBin) {
					t.Fatalf("rejected state %s still mutated the binary", tc.name)
				}
				for _, call := range r.log {
					if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
						strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
						strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
						t.Fatalf("rejected state %s mutated lifecycle before refusal: %s", tc.name, call)
					}
				}
			}
		})
	}
}

func TestAgentInstallRollbackSurfacesRecoveryFailure(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	r.seq["systemctl daemon-reload"] = []fakeResult{{}, {out: "reload failed", code: 1}}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{out: "failed to enable", code: 1}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	r.script["systemctl disable watchpost-agent.service"] = fakeResult{}
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	e := m.Install(exe, paths, "127.0.0.1:9999", "")
	if e == nil {
		t.Fatal("install succeeded despite activation failure")
	}
	if !strings.Contains(e.Error(), "rollback incomplete") {
		t.Fatalf("install did not surface the rollback failure: %v", e)
	}
	if !strings.Contains(e.Error(), "reload systemd") {
		t.Fatalf("install did not surface the rollback root cause: %v", e)
	}
}

func TestAgentEnvFileRequiresRootOwnership(t *testing.T) {
	_, _, paths := fakeManager(t)
	_ = paths
	dir := t.TempDir()
	env := filepath.Join(dir, "agent.env")
	os.WriteFile(env, []byte("WATCHPOST_AGENT_SETUP_TOKEN=x\n"), 0o600)
	oldUID := fileUID
	fileUID = func(os.FileInfo) int { return 0 }
	defer func() { fileUID = oldUID }()
	if e := validateEnvFile(env); e != nil {
		t.Fatalf("root-owned 0600 env file rejected: %v", e)
	}
	fileUID = func(os.FileInfo) int { return 4242 }
	if e := validateEnvFile(env); e == nil {
		t.Fatal("service-user-owned 0600 env file accepted")
	} else if !strings.Contains(e.Error(), "root") {
		t.Fatalf("owner rejection lacks root diagnostic: %v", e)
	}
	os.Chmod(env, 0o640)
	fileUID = func(os.FileInfo) int { return 0 }
	if e := validateEnvFile(env); e == nil {
		t.Fatal("root-owned 0640 env file accepted")
	}
	os.Chmod(env, 0o600)
	link := filepath.Join(dir, "link.env")
	if e := os.Symlink(env, link); e != nil {
		t.Fatal(e)
	}
	fileUID = func(os.FileInfo) int { return 0 }
	if e := validateEnvFile(link); e == nil {
		t.Fatal("symlink env file accepted")
	}
}

func TestAgentDataDirRejectsSystemRoots(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	for _, root := range []string{"/", "/etc", "/usr", "/var", "/home"} {
		p := paths
		p.DataDir = root
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := m.Install(exe, p, DefaultListen, ""); e == nil {
			t.Fatalf("install accepted system data directory %q", root)
		}
		if len(r.log) != 0 {
			t.Fatalf("install of %q touched systemctl", root)
		}
	}
}

func TestAgentDataDirRefusesUnrelatedExistingDirectory(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing-data")
	os.MkdirAll(existing, 0o755)
	marker := filepath.Join(existing, "sentinel")
	os.WriteFile(marker, []byte("keep"), 0o644)
	oldOwned := requireServiceOwned
	requireServiceOwned = func(path string) error { return fmt.Errorf("owned by UID 1000") }
	defer func() { requireServiceOwned = oldOwned }()
	p := paths
	p.DataDir = existing
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install adopted an unrelated existing directory")
	}
	if b, e := os.ReadFile(marker); e != nil || string(b) != "keep" {
		t.Fatalf("existing directory content mutated: %q %v", b, e)
	}
	info, _ := os.Lstat(existing)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("existing directory mode mutated to %v", info.Mode().Perm())
	}
	if len(r.log) != 0 {
		t.Fatalf("rejected existing directory still ran systemctl: %v", r.log)
	}
}

func TestAgentRecoveryTimeMarkerProvesTiming(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return fmt.Errorf("health failed") }
	defer func() { healthCheck = oldHealth }()
	oldWin := healthWindow
	healthWindow = func() time.Duration { return 1 }
	defer func() { healthWindow = oldWin }()
	exe := filepath.Join(t.TempDir(), "agent2")
	newBin := []byte("#!/bin/sh\n# v2\nexit 0\n")
	os.WriteFile(exe, newBin, 0o755)
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	var seamSaw struct {
		markerWritten bool
		binaryIsNew   bool
		logLenAtSeam  int
	}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			if _, e := os.Stat(paths.Binary + ".prior-active"); e == nil {
				seamSaw.markerWritten = true
			}
			cur, _ := os.ReadFile(paths.Binary)
			seamSaw.binaryIsNew = bytes.Equal(cur, newBin)
			seamSaw.logLenAtSeam = len(r.log)
			stopCount, restartCount := 0, 0
			for _, c := range r.log {
				if c == "systemctl stop watchpost-agent.service" {
					stopCount++
				}
				if c == "systemctl restart watchpost-agent.service" {
					restartCount++
				}
			}
			if stopCount != 0 {
				t.Fatalf("recovery issued stop before reading the marker (log=%v)", r.log)
			}
			if restartCount != 1 {
				t.Fatalf("expected exactly the update's restart before recovery marker read, got %d (log=%v)", restartCount, r.log)
			}
			return nil, fmt.Errorf("marker vanished at recovery time")
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := m.Update(exe, fakeSHA(exe), paths)
	if uerr == nil {
		t.Fatal("update succeeded despite recovery marker failure")
	}
	if !seamSaw.markerWritten {
		t.Fatal("recovery seam fired but Update never wrote the marker; test is not exercising recovery-time")
	}
	if !seamSaw.binaryIsNew {
		t.Fatal("recovery seam fired but the installed binary is not the new one; timing wrong")
	}
	if seamSaw.logLenAtSeam == 0 {
		t.Fatal("recovery seam did not record a log position")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed not surfaced: %v", uerr)
	}
	for _, c := range r.log[seamSaw.logLenAtSeam:] {
		if strings.HasPrefix(c, "systemctl ") {
			t.Fatalf("recovery issued a lifecycle verb after the failed marker read: %s", c)
		}
	}
}
