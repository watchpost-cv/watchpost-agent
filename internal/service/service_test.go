package service

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeResult struct {
	out  string
	code int
	err  error
}

type fakeRunner struct {
	script map[string]fakeResult
	log    []string
	calls  map[string]int
	seq    map[string][]fakeResult
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	n := f.calls[key]
	f.calls[key] = n + 1
	if seq, ok := f.seq[key]; ok && n < len(seq) {
		r := seq[n]
		return r.out, r.code, r.err
	}
	if r, ok := f.script[key]; ok {
		return r.out, r.code, r.err
	}
	return "", 0, nil
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if r, ok := f.script[key]; ok {
		return r.code, r.err
	}
	return 0, nil
}

// fakeManager returns a Manager wired to the fake runner with canonical
// machine-service paths redirected to a temp directory.
func fakeManager(t *testing.T) (Manager, *fakeRunner, Paths) {
	t.Helper()
	oldAccount, oldMkdir, oldChown := ensureAccount, mkdirData, chownData
	ensureAccount = func() error { return nil }
	mkdirData = func(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }
	chownData = func(path string) error { return nil }
	t.Cleanup(func() { ensureAccount, mkdirData, chownData = oldAccount, oldMkdir, oldChown })
	dir := t.TempDir()
	paths := Paths{
		Binary:  filepath.Join(dir, "watchpost-agent"),
		DataDir: filepath.Join(dir, "data"),
		Unit:    filepath.Join(dir, "watchpost-agent.service"),
		System:  true,
	}
	os.WriteFile(paths.Binary, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r := &fakeRunner{script: map[string]fakeResult{}, seq: map[string][]fakeResult{}}
	m := Manager{Run: r.Run, Stream: r.Stream}
	return m, r, paths
}

func installManagedUnit(t *testing.T, paths Paths) {
	t.Helper()
	if e := writeFileAtomic(paths.Unit, []byte(Unit(paths, DefaultListen, "")), 0o644); e != nil {
		t.Fatal(e)
	}
}

func setState(r *fakeRunner, enabled, active string) {
	r.script["systemctl is-enabled watchpost-agent.service"] = fakeResult{out: enabled, code: 0}
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: active, code: 0}
}

func fakeSHA(path string) string {
	h, _ := fileSHA256(path)
	return h
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestUnitHardeningAndManagedMarker(t *testing.T) {
	_, _, paths := fakeManager(t)
	u := Unit(paths, DefaultListen, "")
	for _, x := range []string{"# Managed by watchpost-agent. Do not edit manually.", "NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=\"" + paths.DataDir + "\"", "User=" + ServiceUser, "Group=" + ServiceGroup, "WantedBy=multi-user.target"} {
		if !strings.Contains(u, x) {
			t.Fatal("missing " + x)
		}
	}
	if !strings.Contains(u, "watchpost-agent-managed: v1 sha256=") {
		t.Fatal("managed integrity header missing")
	}
	if !strings.Contains(Unit(paths, DefaultListen, "/etc/watchpost-agent/watchpost-agent.env"), "EnvironmentFile=\"/etc/watchpost-agent/watchpost-agent.env\"") {
		t.Fatal("env file not referenced")
	}
}

func TestValidateNoControlAndQuote(t *testing.T) {
	if e := validateNoControl("127.0.0.1:8090", "listen"); e != nil {
		t.Fatal(e)
	}
	if e := validateNoControl("127.0.0.1:8090\nfoo", "listen"); e == nil {
		t.Fatal("newline accepted")
	}
	if got := systemdQuote(`/a b/"x"$y`); got != `"/a b/\"x\"\$y"` {
		t.Fatalf("quote = %q", got)
	}
}

func TestResolveReturnsMachinePaths(t *testing.T) {
	paths, err := Resolve(true)
	if err != nil {
		t.Fatal(err)
	}
	if paths.Binary != "/usr/local/bin/watchpost-agent" {
		t.Fatalf("binary = %q", paths.Binary)
	}
	if paths.DataDir != "/var/lib/watchpost-agent" {
		t.Fatalf("data dir = %q", paths.DataDir)
	}
	if paths.Unit != "/etc/systemd/system/watchpost-agent.service" {
		t.Fatalf("unit = %q", paths.Unit)
	}
	if !paths.System {
		t.Fatal("system mode not default")
	}
}

func TestLifecycleVerbsRequireManagedUnit(t *testing.T) {
	m, r, paths := fakeManager(t)
	for _, v := range []string{"start", "stop", "restart", "enable", "disable"} {
		if err := m.lifecycle(paths, v); err == nil {
			t.Fatalf("%s succeeded without an installed unit", v)
		}
		if len(r.log) != 0 {
			t.Fatalf("%s touched systemctl without a managed unit", v)
		}
	}
	installManagedUnit(t, paths)
	r.script["systemctl start watchpost-agent.service"] = fakeResult{}
	if err := m.lifecycle(paths, "start"); err != nil {
		t.Fatal(err)
	}
	if !contains(r.log, "systemctl start watchpost-agent.service") {
		t.Fatal("start did not call systemctl")
	}
}

func TestLifecycleRefusesForeignUnit(t *testing.T) {
	m, _, paths := fakeManager(t)
	if e := writeFileAtomic(paths.Unit, []byte("[Unit]\nDescription=admin unit\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"start", "stop", "restart", "enable", "disable"} {
		if err := m.lifecycle(paths, v); err == nil {
			t.Fatalf("%s modified a foreign unit", v)
		}
	}
}

func TestInstallChangedBinaryRestarts(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.Install(exe, paths, DefaultListen, ""); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart watchpost-agent.service") {
		t.Fatal("changed binary did not trigger a restart")
	}
}

func TestInstallSameBinaryIsNoOp(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, mustRead(t, paths.Binary), 0o755)
	if e := m.Install(exe, paths, DefaultListen, ""); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl daemon-reload") {
			t.Fatal("identical reinstall performed a daemon-reload")
		}
	}
}

func TestStatusReportsStates(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	r.script["systemctl is-enabled watchpost-agent.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value watchpost-agent.service"] = fakeResult{out: "1234", code: 0}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer h.Close()
	listen := strings.TrimPrefix(h.URL, "http://")
	writeFileAtomic(paths.Unit, []byte(Unit(paths, listen, "")), 0o644)
	var buf bytes.Buffer
	if e := m.Status(&buf, paths, "v1"); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"unit:    watchpost-agent.service", "enabled: enabled", "active:  active", "pid:     1234", "user:    watchpost-agent", "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q", want)
		}
	}
}

func TestLogsConstruction(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	if e := m.Logs(false, io.Discard, paths); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit watchpost-agent.service") {
		t.Fatal("logs did not run journalctl --unit")
	}
}

func TestUninstallPreservesData(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	r.script["systemctl disable --now watchpost-agent.service"] = fakeResult{}
	r.script["systemctl daemon-reload"] = fakeResult{}
	if e := m.Uninstall(io.Discard, paths); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(paths.Unit); !os.IsNotExist(e) {
		t.Fatal("unit file not removed")
	}
	if _, e := os.Stat(paths.Binary); os.IsNotExist(e) {
		t.Fatal("binary should be preserved on uninstall")
	}
}

func TestUpdatePreservesActiveState(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return nil }
	defer func() { healthCheck = oldHealth }()
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.Update(exe, fakeSHA(exe), paths); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart watchpost-agent.service") {
		t.Fatal("active update did not restart")
	}
	r.log = nil
	setState(r, "enabled", "inactive")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "inactive", code: 0}
	if e := m.Update(exe, fakeSHA(exe), paths); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart watchpost-agent.service") || strings.Contains(call, "start watchpost-agent.service") {
			t.Fatalf("stopped update started the service: %s", call)
		}
	}
}

func TestUpdateFailedActivationRestoresOldBinary(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	oldBin := mustRead(t, paths.Binary)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return nil }
	defer func() { healthCheck = oldHealth }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	if e := m.Update(exe, fakeSHA(exe), paths); e == nil {
		t.Fatal("failed activation update returned nil")
	}
	now, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("failed activation did not restore the old binary")
	}
}

func TestUpdateAndRollbackRefuseForeignUnit(t *testing.T) {
	m, _, paths := fakeManager(t)
	if e := writeFileAtomic(paths.Unit, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	before, _ := os.ReadFile(paths.Binary)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := m.Update(exe, fakeSHA(exe), paths); e == nil {
		t.Fatal("update mutated a foreign unit")
	}
	if e := m.Rollback(paths); e == nil {
		t.Fatal("rollback mutated a foreign unit")
	}
	after, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated the binary of a foreign unit")
	}
}

func TestRollbackFailClosedWithoutMarker(t *testing.T) {
	m, _, paths := fakeManager(t)
	installManagedUnit(t, paths)
	os.WriteFile(paths.Binary+".rollback", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.Remove(paths.Binary + ".prior-active")
	if e := m.Rollback(paths); e == nil {
		t.Fatal("rollback defaulted to active without a prior-state marker")
	}
}

// TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime is the corrected
// real-sequence regression: the marker is written by Update, the new binary is
// activated, the health check fails, and only THEN is the marker corrupted (via
// a narrow injectable read seam) so recovery must fail closed rather than guess
// to active.
func TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return fmt.Errorf("health failed") }
	defer func() { healthCheck = oldHealth }()
	oldWin := healthWindow
	healthWindow = func() time.Duration { return 1 * time.Second }
	defer func() { healthWindow = oldWin }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			return []byte("garbage"), nil
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := m.Update(exe, fakeSHA(exe), paths)
	if uerr == nil {
		t.Fatal("update succeeded despite corrupted recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

// TestRecoveryFailsClosedWhenMarkerMissingAtRecoveryTime proves recovery does
// not guess to active when the marker disappears at recovery time (after Update
// wrote it), without test-side fabrication before Update.
func TestRecoveryFailsClosedWhenMarkerMissingAtRecoveryTime(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return fmt.Errorf("health failed") }
	defer func() { healthCheck = oldHealth }()
	oldWin := healthWindow
	healthWindow = func() time.Duration { return 1 * time.Second }
	defer func() { healthWindow = oldWin }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			return nil, fmt.Errorf("marker vanished")
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := m.Update(exe, fakeSHA(exe), paths)
	if uerr == nil {
		t.Fatal("update succeeded despite missing recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

func TestEndToEndActiveUpdateThenRollback(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	oldBin := mustRead(t, paths.Binary)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return nil }
	defer func() { healthCheck = oldHealth }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.Update(exe, fakeSHA(exe), paths); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(paths.Binary + ".rollback"); e != nil {
		t.Fatal("rollback binary missing after successful update")
	}
	if _, e := os.Stat(paths.Binary + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after successful update")
	}
	now, _ := os.ReadFile(paths.Binary)
	if bytes.Equal(now, oldBin) {
		t.Fatal("update did not replace the binary")
	}
	r.log = nil
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.Rollback(paths); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
}

func TestEndToEndStoppedUpdateThenRollback(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	oldBin := mustRead(t, paths.Binary)
	setState(r, "enabled", "inactive")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "inactive", code: 0}
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := m.Update(exe, fakeSHA(exe), paths); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(paths.Binary + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after stopped update")
	}
	r.log = nil
	if e := m.Rollback(paths); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart watchpost-agent.service") || strings.Contains(call, "start watchpost-agent.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestUpdateVerifiesHealthNotJustRestartExit(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	oldBin := mustRead(t, paths.Binary)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return fmt.Errorf("health failed") }
	defer func() { healthCheck = oldHealth }()
	oldWin := healthWindow
	healthWindow = func() time.Duration { return 1 * time.Second }
	defer func() { healthWindow = oldWin }()
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	if e := m.Update(exe, fakeSHA(exe), paths); e == nil {
		t.Fatal("update succeeded although the new binary never became healthy")
	}
	now, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("unhealthy update did not restore the old binary")
	}
}

func TestInitialRestartFailureSurfacesRecoveryFailure(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return nil }
	defer func() { healthCheck = oldHealth }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart watchpost-agent.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{out: "recovery restart failed", code: 1},
	}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	uerr := m.Update(exe, fakeSHA(exe), paths)
	if uerr == nil {
		t.Fatal("update succeeded despite initial restart failure")
	}
	if !strings.Contains(uerr.Error(), "restart after update") {
		t.Fatalf("original restart failure missing: %v", uerr)
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery failure not surfaced: %v", uerr)
	}
}

func TestInitialRestartFailureRecoverySucceedsCleansMetadata(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	oldBin := mustRead(t, paths.Binary)
	setState(r, "enabled", "active")
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	oldHealth := healthCheck
	healthCheck = func(url string) error { return nil }
	defer func() { healthCheck = oldHealth }()
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart watchpost-agent.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{},
	}
	r.script["systemctl stop watchpost-agent.service"] = fakeResult{}
	uerr := m.Update(exe, fakeSHA(exe), paths)
	if uerr == nil {
		t.Fatal("update should report the initial restart failure")
	}
	back, _ := os.ReadFile(paths.Binary)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("recovery did not restore the old binary")
	}
	if _, e := os.Stat(paths.Binary + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("stale rollback binary left after verified recovery")
	}
	if _, e := os.Stat(paths.Binary + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("stale prior-active marker left after verified recovery")
	}
}

func TestTamperedManagedUnitRejected(t *testing.T) {
	m, _, paths := fakeManager(t)
	u := Unit(paths, DefaultListen, "")
	tampered := strings.Replace(u, DefaultListen, "127.0.0.1:9999", 1)
	writeFileAtomic(paths.Unit, []byte(tampered), 0o644)
	if e := m.lifecycle(paths, "start"); e == nil {
		t.Fatal("tampered managed unit accepted for start")
	}
}
