package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestUnitOptionsExplicitHostPort(t *testing.T) {
	_, _, paths := fakeManager(t)
	u := UnitOptions(paths, Options{Host: "0.0.0.0", Port: "7404"})
	for _, want := range []string{`"--host" "0.0.0.0"`, `"--port" "7404"`, `# watchpost-agent-listen: 0.0.0.0:7404`, `# watchpost-agent-listen-mode: explicit`} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q\n%s", want, u)
		}
	}
	if strings.Contains(u, "--listen") {
		t.Fatalf("explicit unit must not use legacy --listen\n%s", u)
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("explicit unit should validate: %v", err)
	}
}

func TestUnitDefaultListenIsCanonical(t *testing.T) {
	_, _, paths := fakeManager(t)
	// A fresh install resolves to 127.0.0.1:7335; the unit records it through
	// --host/--port so the listener survives restart and reboot.
	u := UnitOptions(paths, Options{Host: "127.0.0.1", Port: "7335"})
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7335"`, `# watchpost-agent-listen: 127.0.0.1:7335`, `# watchpost-agent-listen-mode: explicit`} {
		if !strings.Contains(u, want) {
			t.Fatalf("default unit missing %q\n%s", want, u)
		}
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("default unit should validate: %v", err)
	}
}

func TestUnitOptionsCanonicalWhitespace(t *testing.T) {
	_, _, paths := fakeManager(t)
	// Whitespace-surrounded host/port must never leak into the unit metadata or
	// ExecStart; only the canonical trimmed values are recorded.
	u := UnitOptions(paths, Options{Host: "  127.0.0.1  ", Port: "  7402  "})
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7402"`, `# watchpost-agent-listen: 127.0.0.1:7402`} {
		if !strings.Contains(u, want) {
			t.Fatalf("canonical unit missing %q\n%s", want, u)
		}
	}
	for _, bad := range []string{`"  127.0.0.1  "`, `"  7402  "`, `# watchpost-agent-listen:   127.0.0.1:7402`} {
		if strings.Contains(u, bad) {
			t.Fatalf("unit leaked untrimmed value %q\n%s", bad, u)
		}
	}
}

func TestUnitOptionsIPv6HostBracketed(t *testing.T) {
	_, _, paths := fakeManager(t)
	u := UnitOptions(paths, Options{Host: "::1", Port: "7335"})
	for _, want := range []string{`"--host" "::1"`, `# watchpost-agent-listen: [::1]:7335`} {
		if !strings.Contains(u, want) {
			t.Fatalf("IPv6 unit missing %q\n%s", want, u)
		}
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("IPv6 unit should validate: %v", err)
	}
}

func TestUnitLegacyBootstrapMode(t *testing.T) {
	_, _, paths := fakeManager(t)
	u := Unit(paths, "127.0.0.1:8080", "")
	if !strings.Contains(u, `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy unit missing --listen\n%s", u)
	}
	if !strings.Contains(u, "# watchpost-agent-listen-mode: bootstrap") {
		t.Fatalf("legacy unit missing bootstrap mode marker\n%s", u)
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("legacy unit should validate: %v", err)
	}
}

func TestListenModeMarkers(t *testing.T) {
	_, _, paths := fakeManager(t)
	explicit := UnitOptions(paths, Options{Host: "127.0.0.1", Port: "7402"})
	if !strings.Contains(explicit, "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("explicit unit missing explicit mode marker\n%s", explicit)
	}
	m, err := readManagedUnit(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if m.listenMode != listenModeExplicit {
		t.Fatalf("explicit unit listenMode = %q", m.listenMode)
	}
	legacy := Unit(paths, "127.0.0.1:8080", "")
	m, err = readManagedUnit(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if m.listenMode != listenModeBootstrap {
		t.Fatalf("legacy unit listenMode = %q", m.listenMode)
	}
	// A hostile mode value is rejected.
	bad := strings.Replace(legacy, "# watchpost-agent-listen-mode: bootstrap", "# watchpost-agent-listen-mode: attacker", 1)
	if _, err := readManagedUnit(bad); err == nil {
		t.Fatal("invalid listen-mode accepted")
	}
	// A duplicate mode marker is rejected.
	dup := strings.Replace(legacy, "# watchpost-agent-listen-mode: bootstrap", "# watchpost-agent-listen-mode: bootstrap\n# watchpost-agent-listen-mode: bootstrap", 1)
	if _, err := readManagedUnit(dup); err == nil {
		t.Fatal("duplicate listen-mode accepted")
	}
}

func TestLegacyUnitWithoutModeMarkerDefaultsToBootstrap(t *testing.T) {
	_, _, paths := fakeManager(t)
	// A unit written before the mode marker existed must still validate and be
	// classified bootstrap, keeping legacy durable-listen behaviour.
	body := renderUnitBody(paths, Options{Listen: "127.0.0.1:8080"})
	content := "# watchpost-agent-listen: 127.0.0.1:8080\n# watchpost-agent-health: /healthz\n" + body
	sum := sha256.Sum256([]byte(content))
	unit := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
	m, err := readManagedUnit(unit)
	if err != nil {
		t.Fatalf("legacy unit without mode marker should validate: %v", err)
	}
	if m.listenMode != listenModeBootstrap {
		t.Fatalf("missing marker must default to bootstrap, got %q", m.listenMode)
	}
}

func TestOptionsFromMeta(t *testing.T) {
	explicit := OptionsFromMeta(Meta{Listen: "0.0.0.0:7405", ListenMode: listenModeExplicit}, "/etc/watchpost-agent/watchpost-agent.env")
	if explicit.Host != "0.0.0.0" || explicit.Port != "7405" || explicit.Listen != "" || explicit.EnvFile != "/etc/watchpost-agent/watchpost-agent.env" {
		t.Fatalf("explicit OptionsFromMeta = %#v", explicit)
	}
	// IPv6 explicit listeners are split back into an unbracketed host.
	ipv6 := OptionsFromMeta(Meta{Listen: "[::1]:7405", ListenMode: listenModeExplicit}, "")
	if ipv6.Host != "::1" || ipv6.Port != "7405" || ipv6.Listen != "" {
		t.Fatalf("IPv6 OptionsFromMeta = %#v", ipv6)
	}
	legacy := OptionsFromMeta(Meta{Listen: "127.0.0.1:8080", ListenMode: listenModeBootstrap}, "")
	if legacy.Listen != "127.0.0.1:8080" || legacy.Host != "" || legacy.Port != "" {
		t.Fatalf("legacy OptionsFromMeta = %#v", legacy)
	}
	// An old unit without the marker defaults to bootstrap.
	old := OptionsFromMeta(Meta{Listen: "127.0.0.1:8080", ListenMode: ""}, "")
	if old.Listen != "127.0.0.1:8080" {
		t.Fatalf("missing-mode OptionsFromMeta = %#v", old)
	}
}

func TestExistingMetaReportsListenMode(t *testing.T) {
	m, _, paths := fakeManager(t)
	if _, ok, err := m.ExistingMeta(paths); err != nil || ok {
		t.Fatalf("unexpected existing meta: ok=%v err=%v", ok, err)
	}
	if e := writeFileAtomic(paths.Unit, []byte(UnitOptions(paths, Options{Host: "127.0.0.1", Port: "7404"})), 0o644); e != nil {
		t.Fatal(e)
	}
	meta, ok, err := m.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("existing meta: ok=%v err=%v", ok, err)
	}
	if meta.Listen != "127.0.0.1:7404" || meta.ListenMode != listenModeExplicit {
		t.Fatalf("existing meta = %#v", meta)
	}
	// A legacy unit reports bootstrap mode.
	if e := writeFileAtomic(paths.Unit, []byte(Unit(paths, "127.0.0.1:8080", "")), 0o644); e != nil {
		t.Fatal(e)
	}
	meta, ok, err = m.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("legacy existing meta: ok=%v err=%v", ok, err)
	}
	if meta.Listen != "127.0.0.1:8080" || meta.ListenMode != listenModeBootstrap {
		t.Fatalf("legacy existing meta = %#v", meta)
	}
}

func TestStatusReportsEffectiveRuntimeListener(t *testing.T) {
	m, r, paths := fakeManager(t)
	// Explicit host/port unit: the recorded --host/--port listener is the
	// runtime listener and status/health must use it.
	if e := writeFileAtomic(paths.Unit, []byte(UnitOptions(paths, Options{Host: "127.0.0.1", Port: "7404"})), 0o644); e != nil {
		t.Fatal(e)
	}
	r.script["systemctl is-enabled watchpost-agent.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active watchpost-agent.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value watchpost-agent.service"] = fakeResult{out: "1234", code: 0}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer h.Close()
	// Point the recorded listener at the test server: status must target it.
	listen := strings.TrimPrefix(h.URL, "http://")
	if e := writeFileAtomic(paths.Unit, []byte(UnitOptions(paths, Options{Host: "127.0.0.1", Port: strings.TrimPrefix(listen, "127.0.0.1:")})), 0o644); e != nil {
		t.Fatal(e)
	}
	var buf bytes.Buffer
	if e := m.Status(&buf, paths, "v1"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(buf.String(), "listen:  "+listen) {
		t.Fatalf("status must report the recorded runtime listener %q\n%s", listen, buf.String())
	}
	if !strings.Contains(buf.String(), "health:  ok") {
		t.Fatalf("status health must target the recorded listener\n%s", buf.String())
	}
	// Legacy bootstrap unit: the recorded --listen address is the runtime
	// listener and status/health use it.
	r.log = nil
	if e := writeFileAtomic(paths.Unit, []byte(Unit(paths, listen, "")), 0o644); e != nil {
		t.Fatal(e)
	}
	buf.Reset()
	if e := m.Status(&buf, paths, "v1"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(buf.String(), "listen:  "+listen) {
		t.Fatalf("legacy status must report the recorded runtime listener %q\n%s", listen, buf.String())
	}
	if !strings.Contains(buf.String(), "health:  ok") {
		t.Fatalf("legacy status health must target the recorded listener\n%s", buf.String())
	}
}

func TestInstallOptionsExplicitHostPort(t *testing.T) {
	m, r, paths := fakeManager(t)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	o := Options{Host: "127.0.0.1", Port: "7402"}
	if e := m.InstallOptions(exe, paths, o); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--host" "127.0.0.1"`) || !strings.Contains(string(b), `"--port" "7402"`) {
		t.Fatalf("explicit install must record --host/--port\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen: 127.0.0.1:7402") {
		t.Fatalf("explicit install must record the canonical listener\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("explicit install must be explicit mode\n%s", b)
	}
}

func TestInstallOptionsLegacyBootstrapMode(t *testing.T) {
	m, r, paths := fakeManager(t)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.InstallOptions(exe, paths, Options{Listen: "127.0.0.1:8080"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy install must record --listen\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: bootstrap") {
		t.Fatalf("legacy install must be bootstrap mode\n%s", b)
	}
}

func TestInstallOptionsDefaultListener(t *testing.T) {
	m, r, paths := fakeManager(t)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	// A bare CLI install resolves the fresh default 127.0.0.1:7335 and records
	// it through canonical --host/--port.
	if e := m.InstallOptions(exe, paths, Options{Host: "127.0.0.1", Port: "7335"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--host" "127.0.0.1"`) || !strings.Contains(string(b), `"--port" "7335"`) {
		t.Fatalf("default install must record --host 127.0.0.1 --port 7335\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen: 127.0.0.1:7335") {
		t.Fatalf("default install must record the canonical listener\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("default install must be explicit mode\n%s", b)
	}
}

func TestInstallLegacyEmptyListenDefaultsToBootstrapDefault(t *testing.T) {
	m, r, paths := fakeManager(t)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	// The legacy Install wrapper with an empty listen defaults to the fresh
	// DefaultListen in bootstrap mode, preserving the durable-config contract.
	if e := m.Install(exe, paths, "", ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--listen" "127.0.0.1:7335"`) {
		t.Fatalf("legacy empty-listen install must record --listen 127.0.0.1:7335\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: bootstrap") {
		t.Fatalf("legacy empty-listen install must be bootstrap mode\n%s", b)
	}
}

func TestReinstallExplicitHostPortChangesListener(t *testing.T) {
	m, r, paths := fakeManager(t)
	installManagedUnit(t, paths)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	o1 := Options{Host: "127.0.0.1", Port: "7402"}
	if e := m.InstallOptions(exe, paths, o1); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--port" "7402"`) {
		t.Fatalf("first install must record 7402\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("first install must be explicit mode\n%s", b)
	}
	// A changed --port rewrites the unit's --host/--port and restarts.
	exe2 := filepath.Join(t.TempDir(), "agent3")
	os.WriteFile(exe2, []byte("#!/bin/sh\n# v3\nexit 0\n"), 0o755)
	r.log = nil
	o2 := Options{Host: "127.0.0.1", Port: "7403"}
	if e := m.InstallOptions(exe2, paths, o2); e != nil {
		t.Fatalf("reinstall: %v", e)
	}
	b, _ = os.ReadFile(paths.Unit)
	if !strings.Contains(string(b), `"--port" "7403"`) {
		t.Fatalf("reinstall must record 7403\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("reinstall unit must remain explicit mode\n%s", b)
	}
	if !contains(r.log, "systemctl restart watchpost-agent.service") {
		t.Fatalf("changed listener must restart the service\ncalls: %v", r.log)
	}
}

// TestReinstallBarePreservesRecordedListener proves that a bare reinstall with
// the preserved options (OptionsFromMeta) produces a byte-identical unit, so an
// explicit host/port listener survives restart and reboot and a legacy listener
// is never silently rewritten.
func TestReinstallBarePreservesRecordedListener(t *testing.T) {
	m, r, paths := fakeManager(t)
	exe := filepath.Join(t.TempDir(), "agent2")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost-agent.service"] = fakeResult{}
	r.script["systemctl restart watchpost-agent.service"] = fakeResult{}
	if e := m.InstallOptions(exe, paths, Options{Host: "127.0.0.1", Port: "7402"}); e != nil {
		t.Fatal(e)
	}
	first, _ := os.ReadFile(paths.Unit)
	meta, ok, err := m.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("existing meta: ok=%v err=%v", ok, err)
	}
	// Preserved explicit options reproduce the identical unit (no-op reinstall).
	preserved := OptionsFromMeta(meta, "")
	second := buildUnit(paths, preserved)
	if !bytes.Equal(first, []byte(second)) {
		t.Fatalf("preserved explicit reinstall changed the unit:\n%s", second)
	}
	if !strings.Contains(string(first), "# watchpost-agent-listen-mode: explicit") {
		t.Fatalf("explicit unit lost its mode marker\n%s", first)
	}
	// A legacy unit is preserved as --listen.
	if e := writeFileAtomic(paths.Unit, []byte(Unit(paths, "127.0.0.1:8080", "")), 0o644); e != nil {
		t.Fatal(e)
	}
	legacyMeta, ok, err := m.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("legacy meta: ok=%v err=%v", ok, err)
	}
	legacyPreserved := OptionsFromMeta(legacyMeta, "")
	if legacyPreserved.Listen != "127.0.0.1:8080" || legacyPreserved.Host != "" || legacyPreserved.Port != "" {
		t.Fatalf("legacy preserved options = %#v", legacyPreserved)
	}
	if u := buildUnit(paths, legacyPreserved); !strings.Contains(u, `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy preserved reinstall must keep --listen\n%s", u)
	}
}
