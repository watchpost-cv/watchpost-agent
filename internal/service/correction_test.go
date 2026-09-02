package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeStrictManager and the descriptor-relative data-dir helpers are defined in
// service_test.go. This file holds the adversarial lifecycle and data-directory
// regressions.

func TestAgentInstallStateMatrix(t *testing.T) {
	matrix := []struct {
		name          string
		enabled       string
		active        string
		accepted      bool
		wantEnableSeq []string
		wantActive    string
	}{
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
				// Reinstall with a changed listen reaches the forward path.
				// Force a rollback state-independently: the forward daemon-reload
				// fails (1st call), the rollback daemon-reload succeeds (2nd).
				r.seq["systemctl daemon-reload"] = []fakeResult{{out: "reload failed", code: 1}, {}}
				r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
				r.script["systemctl enable --runtime watchpost-agent.service"] = fakeResult{}
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

func TestAgentSuccessfulReinstallPreservesPriorState(t *testing.T) {
	matrix := []struct {
		name          string
		enabled       string
		active        string
		wantEnableSeq []string
		wantActive    string
	}{
		{name: "enabled+active", enabled: "enabled", active: "active", wantEnableSeq: []string{"systemctl enable watchpost-agent.service"}, wantActive: "restart"},
		{name: "enabled+inactive", enabled: "enabled", active: "inactive", wantEnableSeq: []string{"systemctl enable watchpost-agent.service"}, wantActive: "stop"},
		{name: "enabled-runtime+active", enabled: "enabled-runtime", active: "active", wantEnableSeq: []string{"systemctl enable --runtime watchpost-agent.service"}, wantActive: "restart"},
		{name: "enabled-runtime+inactive", enabled: "enabled-runtime", active: "inactive", wantEnableSeq: []string{"systemctl enable --runtime watchpost-agent.service"}, wantActive: "stop"},
		{name: "disabled+active", enabled: "disabled", active: "active", wantEnableSeq: []string{}, wantActive: "restart"},
		{name: "disabled+inactive", enabled: "disabled", active: "inactive", wantEnableSeq: []string{}, wantActive: "stop"},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			m, r, paths := fakeStrictManager(t)
			installManagedUnit(t, paths)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "agent2")
			os.WriteFile(exe, []byte("#!/bin/sh\n# changed binary\nexit 0\n"), 0o755)
			r.script["systemctl daemon-reload"] = fakeResult{}
			r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
			r.script["systemctl enable --runtime watchpost-agent.service"] = fakeResult{}
			r.script["systemctl disable watchpost-agent.service"] = fakeResult{}
			r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
			r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
			if e := m.Install(exe, paths, "127.0.0.1:9999", ""); e != nil {
				t.Fatalf("successful reinstall failed: %v", e)
			}
			for _, want := range tc.wantEnableSeq {
				if !contains(r.log, want) {
					t.Fatalf("reinstall did not apply enablement %q: log=%v", tc.enabled, r.log)
				}
			}
			if tc.enabled == "enabled-runtime" {
				if contains(r.log, "systemctl enable watchpost-agent.service") {
					t.Fatalf("enabled-runtime prior was converted to persistent enable: log=%v", r.log)
				}
			}
			if tc.enabled == "disabled" {
				if contains(r.log, "systemctl enable watchpost-agent.service") || contains(r.log, "systemctl enable --runtime watchpost-agent.service") {
					t.Fatalf("disabled prior was enabled by reinstall: log=%v", r.log)
				}
			}
			if tc.wantActive == "restart" && !contains(r.log, "systemctl restart watchpost-agent.service") {
				t.Fatalf("active prior not restarted on successful reinstall: log=%v", r.log)
			}
			if tc.wantActive == "stop" && !contains(r.log, "systemctl stop watchpost-agent.service") {
				t.Fatalf("inactive prior not stopped on successful reinstall: log=%v", r.log)
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
	fakeManager(t)
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
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing-data")
	os.MkdirAll(existing, 0o755)
	marker := filepath.Join(existing, "sentinel")
	os.WriteFile(marker, []byte("keep"), 0o644)
	serviceUID = func() (int, error) { return os.Getuid() + 10000, nil }
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

func TestAgentDataDirLeafOnlyCreation(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	parent := t.TempDir()
	newData := filepath.Join(parent, "agent-data")
	p := paths
	p.DataDir = newData
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.Install(exe, p, DefaultListen, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(newData); e != nil {
		t.Fatalf("leaf was not actually created: %v", e)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("parent gained unexpected entries: %v", entries)
	}
}

func TestAgentDataDirRefusesMissingParent(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	dir := t.TempDir()
	missingParent := filepath.Join(dir, "does-not-exist")
	dataDir := filepath.Join(missingParent, "agent-data")
	p := paths
	p.DataDir = dataDir
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install created a data directory under a missing parent")
	}
	if _, e := os.Lstat(missingParent); !os.IsNotExist(e) {
		t.Fatalf("missing parent %q was created by the installer", missingParent)
	}
	if len(r.log) != 0 {
		t.Fatalf("missing-parent install still ran systemctl: %v", r.log)
	}
}

func TestAgentDataDirRejectsUnderSystemTree(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	for _, root := range []string{"/etc/watchpost-agent-data", "/usr/local/agent", "/bin/agent"} {
		p := paths
		p.DataDir = root
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := m.Install(exe, p, DefaultListen, ""); e == nil {
			t.Fatalf("install accepted data directory %q beneath a system tree", root)
		}
		if len(r.log) != 0 {
			t.Fatalf("install of %q touched systemctl", root)
		}
	}
	if e := validateDataDirPath("/var/lib/watchpost-agent"); e != nil {
		t.Fatalf("canonical /var/lib/watchpost-agent rejected: %v", e)
	}
	if e := validateDataDirPath("/srv/watchpost-agent"); e != nil {
		t.Fatalf("canonical /srv/watchpost-agent rejected: %v", e)
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

type agentMutations struct {
	account bool
	mkdir   bool
	chmod   bool
	chown   bool
}

func watchAgentMutations(t *testing.T) *agentMutations {
	t.Helper()
	c := &agentMutations{}
	oldAccount, oldMkdir, oldChmod, oldChown := ensureAccount, mkdirAtLeafSeam, fchmodLeafSeam, fchownLeafSeam
	ensureAccount = func() error { c.account = true; return nil }
	mkdirAtLeafSeam = func(int, string) error { c.mkdir = true; return nil }
	fchmodLeafSeam = func(int) error { c.chmod = true; return nil }
	fchownLeafSeam = func(int) error { c.chown = true; return nil }
	t.Cleanup(func() {
		ensureAccount, mkdirAtLeafSeam, fchmodLeafSeam, fchownLeafSeam = oldAccount, oldMkdir, oldChmod, oldChown
	})
	return c
}

func (c *agentMutations) any() bool { return c.account || c.mkdir || c.chmod || c.chown }

func lifecycleMutation(log []string) bool {
	for _, call := range log {
		if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
			strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
			strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
			return true
		}
	}
	return false
}

func TestAgentInstallRefusalCausesZeroMutation(t *testing.T) {
	cases := []struct{ name string }{
		{"foreign-unit"}, {"tampered-unit"}, {"unsupported-enabled-state"},
		{"unsupported-active-state"}, {"state-query-failure"}, {"invalid-incoming-executable"},
		{"invalid-env-file"}, {"unacceptable-data-dir"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, r, paths := fakeStrictManager(t)
			c := watchAgentMutations(t)
			installManagedUnit(t, paths)
			exe := filepath.Join(t.TempDir(), "agent2")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			envfile := ""
			switch tc.name {
			case "foreign-unit":
				writeFileAtomic(paths.Unit, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/x\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
			case "tampered-unit":
				u := string(mustRead(t, paths.Unit))
				writeFileAtomic(paths.Unit, []byte(strings.Replace(u, DefaultListen, "127.0.0.1:9999", 1)), 0o644)
			case "unsupported-enabled-state":
				setState(r, "masked", "inactive")
			case "unsupported-active-state":
				setState(r, "enabled", "reloading")
			case "state-query-failure":
				r.script["systemctl is-enabled watchpost-agent.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("query failed")}
			case "invalid-incoming-executable":
				os.Remove(exe)
			case "invalid-env-file":
				bad := filepath.Join(t.TempDir(), "bad.env")
				os.WriteFile(bad, []byte("X=1\n"), 0o644)
				envfile = bad
			case "unacceptable-data-dir":
				// An existing leaf not owned by the service account is refused
				// during preflight inspection: the leaf descriptor is opened and
				// fstat'd, and the descriptor's UID is validated (not the name).
				statDataLeafSeam = func(int, string) (dataLeafInfo, error) {
					return dataLeafInfo{isDir: true, mode: 0o755, uid: 1000}, nil
				}
				openAtLeafSeam = func(int, string) (int, error) { return 2, nil }
				fstatLeafSeam = func(int) (dataLeafInfo, error) {
					return dataLeafInfo{isDir: true, mode: 0o755, uid: 1000}, nil
				}
			}
			beforeBin, _ := os.ReadFile(paths.Binary)
			if e := m.Install(exe, paths, DefaultListen, envfile); e == nil {
				t.Fatalf("refusal case %s unexpectedly succeeded", tc.name)
			}
			if c.any() {
				t.Fatalf("refusal case %s mutated account/mkdir/chmod/chown: %+v", tc.name, c)
			}
			afterBin, _ := os.ReadFile(paths.Binary)
			if !bytes.Equal(beforeBin, afterBin) {
				t.Fatalf("refusal case %s mutated the binary", tc.name)
			}
			if lifecycleMutation(r.log) {
				t.Fatalf("refusal case %s performed a lifecycle mutation: %v", tc.name, r.log)
			}
		})
	}
}

func TestAgentDataDirRefusesAncestorSymlinkEscape(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	base := t.TempDir()
	protected := filepath.Join(base, "protected")
	os.MkdirAll(protected, 0o755)
	link := filepath.Join(base, "link")
	if e := os.Symlink(protected, link); e != nil {
		t.Fatal(e)
	}
	p := paths
	p.DataDir = filepath.Join(link, "project")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install followed an ancestor symlink escape")
	}
	if _, e := os.Lstat(filepath.Join(protected, "project")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at resolved protected target: %v", e)
	}
	if lifecycleMutation(r.log) {
		t.Fatalf("ancestor-symlink install mutated lifecycle: %v", r.log)
	}
}

func TestAgentDataDirChmodFailure(t *testing.T) {
	// New leaf.
	{
		m, _, paths := fakeStrictManager(t)
		useRealDataDirSeams(t)
		simulateSafeParent(t)
		parent := t.TempDir()
		p := paths
		p.DataDir = filepath.Join(parent, "agent-data")
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		fchmodLeafSeam = func(int) error { return fmt.Errorf("chmod failed") }
		if e := m.Install(exe, p, DefaultListen, ""); e == nil {
			t.Fatal("install succeeded despite new-leaf chmod failure")
		}
		if _, e := os.Lstat(p.DataDir); !os.IsNotExist(e) {
			t.Fatalf("partial leaf left behind: %v", e)
		}
	}
	// Existing leaf.
	{
		m, _, paths := fakeStrictManager(t)
		useRealDataDirSeams(t)
		simulateSafeParent(t)
		dir := t.TempDir()
		p := paths
		p.DataDir = filepath.Join(dir, "existing")
		os.MkdirAll(p.DataDir, 0o755)
		fchmodLeafSeam = func(int) error { return fmt.Errorf("chmod failed") }
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := m.Install(exe, p, DefaultListen, ""); e == nil {
			t.Fatal("install succeeded despite existing-leaf chmod failure")
		}
	}
}

func TestAgentInstallRollbackSurfacesNeutralizationFailures(t *testing.T) {
	// Forward failure + rollback stop failure.
	{
		m, r, paths := fakeStrictManager(t)
		installManagedUnit(t, paths)
		setState(r, "enabled", "active")
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl disable watchpost-agent.service"] = fakeResult{}
		r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
		r.script["systemctl restart watchpost-agent.service"] = fakeResult{out: "activation failed", code: 1}
		r.script["systemctl stop watchpost-agent.service"] = fakeResult{out: "cannot stop", code: 1}
		e := m.Install(exe, paths, "127.0.0.1:9999", "")
		if e == nil {
			t.Fatal("install succeeded despite forward failure")
		}
		if !strings.Contains(e.Error(), "neutralize stop") {
			t.Fatalf("rollback stop failure not surfaced: %v", e)
		}
		if !strings.Contains(e.Error(), "rollback incomplete") {
			t.Fatalf("rollback incomplete not reported: %v", e)
		}
	}
	// Forward failure + rollback disable failure.
	{
		m, r, paths := fakeStrictManager(t)
		installManagedUnit(t, paths)
		setState(r, "enabled", "inactive")
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl disable watchpost-agent.service"] = fakeResult{out: "cannot disable", code: 1}
		r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
		r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
		e := m.Install(exe, paths, "127.0.0.1:9999", "")
		if e == nil {
			t.Fatal("install succeeded despite forward failure")
		}
		if !strings.Contains(e.Error(), "neutralize disable") {
			t.Fatalf("rollback disable failure not surfaced: %v", e)
		}
	}
}

func TestAgentUnchangedReinstallPreservesPriorState(t *testing.T) {
	matrix := []struct{ name, enabled, active string }{
		{"enabled+active", "enabled", "active"},
		{"enabled+inactive", "enabled", "inactive"},
		{"enabled-runtime+active", "enabled-runtime", "active"},
		{"enabled-runtime+inactive", "enabled-runtime", "inactive"},
		{"disabled+active", "disabled", "active"},
		{"disabled+inactive", "disabled", "inactive"},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			m, r, paths := fakeStrictManager(t)
			useRealDataDirSeams(t)
			simulateSafeParent(t)
			dataDir := filepath.Join(t.TempDir(), "agent-data")
			if e := os.Mkdir(dataDir, 0o700); e != nil {
				t.Fatal(e)
			}
			serviceUID = func() (int, error) { return os.Getuid(), nil }
			p := paths
			p.DataDir = dataDir
			writeFileAtomic(p.Unit, []byte(Unit(p, DefaultListen, "")), 0o644)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "agent2")
			os.WriteFile(exe, mustRead(t, p.Binary), 0o755)
			if e := m.Install(exe, p, DefaultListen, ""); e != nil {
				t.Fatalf("unchanged reinstall failed: %v", e)
			}
			if lifecycleMutation(r.log) {
				t.Fatalf("unchanged %s reinstall performed a lifecycle mutation: %v", tc.name, r.log)
			}
		})
	}
}

func TestAgentNoOpRepairsMissingDataLeaf(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	dataDir := filepath.Join(t.TempDir(), "agent-data")
	p := paths
	p.DataDir = dataDir
	writeFileAtomic(p.Unit, []byte(Unit(p, DefaultListen, "")), 0o644)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, mustRead(t, p.Binary), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e != nil {
		t.Fatalf("repair install failed: %v", e)
	}
	if _, e := os.Lstat(dataDir); e != nil {
		t.Fatalf("repaired leaf not created: %v", e)
	}
	if lifecycleMutation(r.log) {
		t.Fatalf("repair install performed a lifecycle mutation: %v", r.log)
	}
}

func TestAgentDataDirEstablishmentFailuresCleanUp(t *testing.T) {
	run := func(name string, breakIt func()) {
		t.Run(name, func(t *testing.T) {
			m, r, paths := fakeStrictManager(t)
			useRealDataDirSeams(t)
			simulateSafeParent(t)
			p := paths
			p.DataDir = filepath.Join(t.TempDir(), "agent-data")
			binBefore := mustRead(t, paths.Binary)
			breakIt()
			exe := filepath.Join(t.TempDir(), "agent2")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if e := m.Install(exe, p, DefaultListen, ""); e == nil {
				t.Fatal("install succeeded despite a data-leaf establishment failure")
			}
			if _, e := os.Stat(paths.Unit); !os.IsNotExist(e) {
				t.Fatal("unit written despite the data-leaf failure")
			}
			if got := mustRead(t, paths.Binary); !bytes.Equal(got, binBefore) {
				t.Fatal("binary mutated despite the data-leaf failure")
			}
			if hasMutatingSystemctl(r.log) {
				t.Fatalf("systemctl mutated despite the data-leaf failure: %v", r.log)
			}
			if _, e := os.Stat(p.DataDir); !os.IsNotExist(e) {
				t.Fatal("partial leaf was not cleaned up after the establishment failure")
			}
		})
	}
	run("chown-failure", func() { fchownLeafSeam = func(int) error { return errors.New("chown denied") } })
	run("bind-failure", func() {
		openAtLeafSeam = func(int, string) (int, error) { return -1, errors.New("bind denied") }
	})
	run("inspection-failure", func() {
		fstatLeafSeam = func(int) (dataLeafInfo, error) { return dataLeafInfo{}, errors.New("inspect denied") }
	})

	t.Run("cleanup-failure-reported", func(t *testing.T) {
		m, r, paths := fakeStrictManager(t)
		useRealDataDirSeams(t)
		simulateSafeParent(t)
		p := paths
		p.DataDir = filepath.Join(t.TempDir(), "agent-data")
		fchmodLeafSeam = func(int) error { return errors.New("chmod denied") }
		unlinkAtSeam = func(int, string) error { return errors.New("unlink denied") }
		exe := filepath.Join(t.TempDir(), "agent2")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := m.Install(exe, p, DefaultListen, ""); e == nil {
			t.Fatal("install succeeded despite a cleanup failure")
		} else if !strings.Contains(e.Error(), "partial leaf cleanup incomplete") {
			t.Fatalf("cleanup failure not surfaced: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("cleanup-failure install touched systemctl")
		}
	})
}

func TestAgentDataDirAncestorSwapAfterInspectionRefused(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	original := t.TempDir()
	substitute := t.TempDir()
	p := paths
	p.DataDir = filepath.Join(original, "agent-data")
	ensureAccount = func() error {
		if e := os.Rename(original, original+"-moved"); e != nil {
			return e
		}
		return os.Symlink(substitute, original)
	}
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install proceeded after the parent was swapped for a symlink")
	}
	if _, e := os.Stat(filepath.Join(substitute, "agent-data")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at the substituted target: %v", e)
	}
	if _, e := os.Stat(filepath.Join(original+"-moved", "agent-data")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at the renamed original: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatal("ancestor-swap install touched systemctl")
	}
}

func TestAgentDataDirExistingLeafReplacedAfterInspection(t *testing.T) {
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	dir := t.TempDir()
	original := filepath.Join(dir, "leaf")
	replacement := filepath.Join(dir, "replacement")
	os.Mkdir(original, 0o700)
	os.Mkdir(replacement, 0o750)
	serviceUID = func() (int, error) { return os.Getuid(), nil }
	plan, err := inspectDataDir(original)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	defer plan.close()
	if plan.status != dataDirAcceptExisting {
		t.Fatalf("expected existing leaf, got status %d", plan.status)
	}
	if err := os.Rename(original, original+"-moved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, original); err != nil {
		t.Fatal(err)
	}
	if err := establishDataDir(&plan); err != nil {
		t.Fatalf("establish: %v", err)
	}
	info, _ := os.Stat(original + "-moved")
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("retained original leaf not chmod'd 0700: %v", info.Mode().Perm())
	}
	info2, _ := os.Stat(original)
	if info2.Mode().Perm() != 0o750 {
		t.Fatalf("replacement leaf was chmod'd by the installer: %v", info2.Mode().Perm())
	}
}

// nonRootTempParent returns a temporary directory whose ownership
// deterministically fails the root-owned parent safety check regardless of the
// test runner's uid. Running as root the directory is chowned to a non-root uid
// (nobody); running unprivileged it is already owned by the test user.
func nonRootTempParent(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if os.Geteuid() == 0 {
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Skipf("cannot chown temp parent to a non-root uid: %v", err)
		}
	}
	return dir
}

func TestAgentDataDirParentSafety(t *testing.T) {
	fakeStrictManager(t)
	useRealDataDirSeams(t)
	dir := nonRootTempParent(t)
	fd, err := openDataParentSeam(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFdSeam(fd)
	if e := parentSafeSeam(fd); e == nil {
		t.Fatal("non-root parent accepted")
	}
	gw := filepath.Join(t.TempDir(), "gw")
	os.Mkdir(gw, 0o770)
	gfd, err := openDataParentSeam(gw)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFdSeam(gfd)
	if e := parentSafeSeam(gfd); e == nil {
		t.Fatal("group-writable parent accepted")
	}
	ww := filepath.Join(t.TempDir(), "ww")
	os.Mkdir(ww, 0o707)
	wfd, err := openDataParentSeam(ww)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFdSeam(wfd)
	if e := parentSafeSeam(wfd); e == nil {
		t.Fatal("world-writable parent accepted")
	}
	// Refusal before account/data mutation.
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	c := watchAgentMutations(t)
	p := paths
	p.DataDir = filepath.Join(nonRootTempParent(t), "sub")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install accepted a non-root parent")
	}
	if c.any() {
		t.Fatalf("non-root parent install mutated account/mkdir/chmod/chown: %+v", c)
	}
	if len(r.log) != 0 {
		t.Fatalf("non-root parent install touched systemctl: %v", r.log)
	}
}

// TestAgentDataDirParentPathnameSymlinkSwapRefused proves the parent-consistency
// check re-walks the current pathname with O_NOFOLLOW instead of following newly
// introduced symlinks: renaming the parent between inspection and establishment
// and replacing its pathname with a symlink pointing back to the renamed
// original is refused before any leaf/binary/unit/systemd mutation.
func TestAgentDataDirParentPathnameSymlinkSwapRefused(t *testing.T) {
	m, r, paths := fakeStrictManager(t)
	useRealDataDirSeams(t)
	simulateSafeParent(t)
	parent := t.TempDir()
	p := paths
	p.DataDir = filepath.Join(parent, "agent-data")
	// Between inspection (parent descriptor retained) and establishment the
	// parent is renamed away and its pathname replaced with a symlink pointing
	// back to the renamed original.
	ensureAccount = func() error {
		if e := os.Rename(parent, parent+"-original"); e != nil {
			return e
		}
		return os.Symlink(parent+"-original", parent)
	}
	t.Cleanup(func() { os.RemoveAll(parent + "-original"); os.Remove(parent) })
	binBefore := mustRead(t, paths.Binary)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := m.Install(exe, p, DefaultListen, ""); e == nil {
		t.Fatal("install proceeded after the parent pathname became a symlink")
	} else if !strings.Contains(e.Error(), "parent") {
		t.Fatalf("refusal did not identify the parent pathname: %v", e)
	}
	if _, e := os.Stat(filepath.Join(parent+"-original", "agent-data")); !os.IsNotExist(e) {
		t.Fatal("leaf created through the symlinked parent pathname")
	}
	if got := mustRead(t, paths.Binary); !bytes.Equal(got, binBefore) {
		t.Fatal("binary mutated despite the parent-pathname refusal")
	}
	if _, e := os.Stat(paths.Unit); !os.IsNotExist(e) {
		t.Fatal("unit written despite the parent-pathname refusal")
	}
	if hasMutatingSystemctl(r.log) {
		t.Fatalf("systemctl mutated despite the parent-pathname refusal: %v", r.log)
	}
}
