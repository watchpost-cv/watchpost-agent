package service

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
)

type fakeRunner struct {
	mu      sync.Mutex
	calls   []string
	handler func(name string, args ...string) (string, int, error)
	out     string
	code    int
	err     error
	stream  func(name string, args ...string) (int, error)
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	h := f.handler
	f.mu.Unlock()
	if h != nil {
		return h(name, args...)
	}
	return f.out, f.code, f.err
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	f.mu.Lock()
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	s := f.stream
	f.mu.Unlock()
	if s != nil {
		return s(name, args...)
	}
	return 0, nil
}

func (f *fakeRunner) contains(args []string, s string) bool {
	for _, a := range args {
		if a == s {
			return true
		}
	}
	return false
}

func (f *fakeRunner) saw(needle string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, c := range f.calls[:len(f.calls)-1] {
		if strings.Contains(c, needle) {
			return true
		}
	}
	return false
}

func testManager(t *testing.T) (Manager, *fakeRunner, Paths, string) {
	t.Helper()
	base := t.TempDir()
	paths := Paths{
		Binary:  filepath.Join(base, "bin", "watchpost-agent"),
		DataDir: filepath.Join(base, "state"),
		Unit:    filepath.Join(base, "unit", "watchpost-agent.service"),
	}
	source := filepath.Join(base, "source")
	if err := os.WriteFile(source, []byte("agent binary"), 0755); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRunner{}
	return Manager{Run: fr.Run, Stream: fr.Stream}, fr, paths, source
}

func jsonServer(t *testing.T, code int, body string, ct string) *httptest.Server {
	t.Helper()
	if ct == "" {
		ct = "application/json"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", ct)
		w.WriteHeader(code)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func activeHandler(fr *fakeRunner) func(name string, args ...string) (string, int, error) {
	return func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "is-active"):
			return "active", 0, nil
		case fr.contains(args, "is-enabled"):
			return "enabled", 0, nil
		}
		return "", 0, nil
	}
}

func readManagedUnitBytes(t *testing.T, data []byte) (unitMeta, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "watchpost-agent.service")
	if err := os.WriteFile(path, data, 0644); err != nil {
		return unitMeta{}, err
	}
	return readManagedUnit(path)
}

func TestResolve(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	paths, err := Resolve(false)
	if err != nil {
		t.Fatal(err)
	}
	if paths.System || !strings.HasSuffix(paths.Unit, "watchpost-agent.service") {
		t.Fatalf("user paths wrong: %+v", paths)
	}
	if _, err := Resolve(true); err == nil {
		t.Fatal("system mode must refuse to run the web service as root")
	}
}

func TestUnitAndIntegrity(t *testing.T) {
	paths := Paths{Binary: "/usr/local/lib/watchpost-agent/watchpost-agent", DataDir: "/var/lib/watchpost-agent", System: true}
	unit := Unit(paths, "127.0.0.1:8090", "")
	if !strings.Contains(unit, unitMarker) {
		t.Fatal("missing managed marker")
	}
	if !regexp.MustCompile(`(?m)^# watchpost-agent-managed: v1 sha256=[0-9a-f]{64}$`).MatchString(unit) {
		t.Fatalf("missing valid integrity header\n%s", unit)
	}
	for _, want := range []string{`ExecStart="/usr/local/lib/watchpost-agent/watchpost-agent" "--listen" "127.0.0.1:8090" "--data-dir" "/var/lib/watchpost-agent"`, `NoNewPrivileges=true`, `ProtectSystem=strict`, `ReadWritePaths="/var/lib/watchpost-agent"`, `# watchpost-agent-listen: 127.0.0.1:8090`, `# watchpost-agent-health: /healthz`, `WantedBy=multi-user.target`} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit missing %q\n%s", want, unit)
		}
	}
	if _, err := readManagedUnitBytes(t, []byte(unit)); err != nil {
		t.Fatalf("built unit should validate: %v", err)
	}

	t.Run("modified unit rejected", func(t *testing.T) {
		bad := strings.Replace(unit, "NoNewPrivileges=true", "NoNewPrivileges=false", 1)
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("foreign unit rejected", func(t *testing.T) {
		if _, err := readManagedUnitBytes(t, []byte("# hand written\n[Service]\n")); !errors.Is(err, errNotManaged) {
			t.Fatalf("want errNotManaged, got %v", err)
		}
	})
	t.Run("corrupted checksum rejected", func(t *testing.T) {
		re := regexp.MustCompile(`(v1 sha256=)([0-9a-f]{64})`)
		loc := re.FindStringSubmatchIndex(unit)
		hashStart := loc[4]
		repl := "0"
		if unit[hashStart] == '0' {
			repl = "1"
		}
		bad := unit[:hashStart] + repl + unit[hashStart+1:]
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errModified) {
			t.Fatalf("want errModified, got %v", err)
		}
	})
	t.Run("wrong health path rejected", func(t *testing.T) {
		body := renderUnitBody(paths, "127.0.0.1:8090", "")
		content := "# watchpost-agent-listen: 127.0.0.1:8090\n# watchpost-agent-health: /other\n" + body
		sum := sha256.Sum256([]byte(content))
		bad := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
		if _, err := readManagedUnitBytes(t, []byte(bad)); !errors.Is(err, errMalformed) {
			t.Fatalf("want errMalformed, got %v", err)
		}
	})
}

func TestInstallAndUpgrade(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatalf("install: %v", err)
	}
	if _, err := os.Stat(paths.Binary); err != nil {
		t.Fatalf("binary not installed: %v", err)
	}
	unit, err := os.ReadFile(paths.Unit)
	if err != nil {
		t.Fatalf("unit not written: %v", err)
	}
	if _, err := readManagedUnitBytes(t, unit); err != nil {
		t.Fatalf("installed unit invalid: %v", err)
	}
	joined := strings.Join(fr.calls, "\n")
	for _, want := range []string{"systemctl --user daemon-reload", "systemctl --user enable watchpost-agent.service", "systemctl --user restart watchpost-agent.service"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("install did not call %q\n%s", want, joined)
		}
	}
	// Upgrade replaces the binary and rewrites the managed unit.
	if err := os.WriteFile(source, []byte("agent binary v2"), 0755); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := manager.Upgrade(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	installed, _ := os.ReadFile(paths.Binary)
	if string(installed) != "agent binary v2" {
		t.Fatalf("installed=%q", installed)
	}
	if !strings.Contains(strings.Join(fr.calls, "\n"), "systemctl --user restart watchpost-agent.service") {
		t.Fatal("upgrade did not restart the service")
	}
}

func TestInstallRefusesForeignOrModifiedUnit(t *testing.T) {
	manager, _, paths, source := testManager(t)
	if err := os.MkdirAll(filepath.Dir(paths.Unit), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(paths.Unit, []byte("# hand written\n[Service]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err == nil {
		t.Fatal("install overwrote a foreign unit")
	}
}

func TestActionsRequireManagedUnit(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	if err := manager.Start(paths); err == nil {
		t.Fatal("start on a missing unit succeeded")
	}
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(paths.Unit)
	if err := os.WriteFile(paths.Unit, []byte(strings.Replace(string(unit), "NoNewPrivileges=true", "NoNewPrivileges=false", 1)), 0644); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := manager.Restart(paths); err == nil {
		t.Fatal("restart on a modified managed unit succeeded")
	}
	if len(fr.calls) != 0 {
		t.Fatalf("lifecycle command ran against a modified unit: %v", fr.calls)
	}
}

func TestStrictExitFailures(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	t.Run("install daemon-reload nonzero prevents enable and restart", func(t *testing.T) {
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "daemon-reload") {
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err == nil {
			t.Fatal("install succeeded despite a failed daemon-reload")
		}
		joined := strings.Join(fr.calls, "\n")
		if strings.Contains(joined, "enable watchpost-agent.service") || strings.Contains(joined, "restart watchpost-agent.service") {
			t.Fatalf("enable/restart ran after a failed daemon-reload: %s", joined)
		}
		fr.handler = nil
	})
	t.Run("lifecycle start/stop/restart nonzero reports failure", func(t *testing.T) {
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
			t.Fatal(err)
		}
		for _, verb := range []string{"start", "stop", "restart"} {
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				if fr.contains(args, verb) {
					return "Failed", 1, nil
				}
				return "", 0, nil
			}
			var err error
			switch verb {
			case "start":
				err = manager.Start(paths)
			case "stop":
				err = manager.Stop(paths)
			case "restart":
				err = manager.Restart(paths)
			}
			if err == nil {
				t.Fatalf("%s succeeded despite a nonzero exit", verb)
			}
		}
		fr.handler = nil
	})
}

func stateTestManager(t *testing.T, activeOut string, activeCode int, enabledOut string, enabledCode int) (Manager, *fakeRunner, Paths) {
	t.Helper()
	manager, fr, paths, source := testManager(t)
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatal(err)
	}
	fr.handler = func(name string, args ...string) (string, int, error) {
		switch {
		case fr.contains(args, "is-active"):
			return activeOut, activeCode, nil
		case fr.contains(args, "is-enabled"):
			return enabledOut, enabledCode, nil
		}
		return "", 0, nil
	}
	return manager, fr, paths
}

func TestStateExitValidation(t *testing.T) {
	valid := []struct {
		verb, out string
		code      int
		want      svcState
	}{
		{"is-active", "active", 0, stateActive},
		{"is-active", "reloading", 0, stateReloading},
		{"is-active", "refreshing", 0, stateRefreshing},
		{"is-active", "refreshing", 3, stateRefreshing},
		{"is-active", "inactive", 3, stateInactive},
		{"is-active", "dead", 3, stateInactive},
		{"is-active", "failed", 3, stateInactive},
		{"is-active", "activating", 3, stateTransition},
		{"is-active", "deactivating", 3, stateTransition},
		{"is-active", "maintenance", 3, stateTransition},
		{"is-active", "unknown", 3, stateUnknown},
		{"is-active", "not-found", 3, stateUnknown},
		{"is-active", "not-found", 4, stateUnknown},
		{"is-enabled", "enabled", 0, stateEnabled},
		{"is-enabled", "enabled-runtime", 0, stateEnabled},
		{"is-enabled", "static", 0, stateNotEnabled},
		{"is-enabled", "alias", 0, stateNotEnabled},
		{"is-enabled", "indirect", 0, stateNotEnabled},
		{"is-enabled", "generated", 0, stateNotEnabled},
		{"is-enabled", "disabled", 1, stateNotEnabled},
		{"is-enabled", "linked", 1, stateNotEnabled},
		{"is-enabled", "linked-runtime", 1, stateNotEnabled},
		{"is-enabled", "transient", 1, stateNotEnabled},
		{"is-enabled", "not-found", 4, stateNotEnabled},
		{"is-enabled", "masked", 1, stateMasked},
		{"is-enabled", "masked-runtime", 1, stateMasked},
	}
	for _, tc := range valid {
		manager, _, paths := stateTestManager(t, tc.out, tc.code, tc.out, tc.code)
		got, err := manager.queryState(paths, tc.verb)
		if err != nil {
			t.Fatalf("%s %q exit %d: unexpected error %v", tc.verb, tc.out, tc.code, err)
		}
		if got != tc.want {
			t.Fatalf("%s %q exit %d = %q want %q", tc.verb, tc.out, tc.code, got, tc.want)
		}
	}
	invalid := []struct {
		verb, out string
		code      int
	}{
		{"is-active", "active", 3},
		{"is-active", "reloading", 3},
		{"is-active", "inactive", 0},
		{"is-active", "failed", 0},
		{"is-active", "activating", 0},
		{"is-active", "unknown", 0},
		{"is-active", "not-found", 0},
		{"is-enabled", "enabled", 1},
		{"is-enabled", "static", 1},
		{"is-enabled", "alias", 1},
		{"is-enabled", "disabled", 0},
		{"is-enabled", "linked", 0},
		{"is-enabled", "masked", 0},
	}
	for _, tc := range invalid {
		manager, _, paths := stateTestManager(t, tc.out, tc.code, tc.out, tc.code)
		if _, err := manager.queryState(paths, tc.verb); err == nil {
			t.Fatalf("%s %q exit %d should be rejected as inconsistent", tc.verb, tc.out, tc.code)
		}
	}
}

func TestIsEnabledUninstallPolicy(t *testing.T) {
	cases := []struct {
		state string
		code  int
		want  svcState
	}{
		{"enabled", 0, stateEnabled},
		{"enabled-runtime", 0, stateEnabled},
		{"static", 0, stateNotEnabled},
		{"alias", 0, stateNotEnabled},
		{"indirect", 0, stateNotEnabled},
		{"generated", 0, stateNotEnabled},
		{"disabled", 1, stateNotEnabled},
		{"linked", 1, stateNotEnabled},
		{"linked-runtime", 1, stateNotEnabled},
		{"transient", 1, stateNotEnabled},
		{"not-found", 4, stateNotEnabled},
		{"masked", 1, stateMasked},
		{"masked-runtime", 1, stateMasked},
		{"unknown", 1, stateUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.state, func(t *testing.T) {
			manager, fr, paths, source := testManager(t)
			if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				switch {
				case fr.contains(args, "is-active"):
					return "inactive", 3, nil
				case fr.contains(args, "is-enabled"):
					if fr.saw("disable watchpost-agent.service") {
						return "disabled", 1, nil
					}
					return tc.state, tc.code, nil
				}
				return "", 0, nil
			}
			err := manager.Uninstall(os.Stderr, paths)
			joined := strings.Join(fr.calls, "\n")
			disabled := strings.Contains(joined, "disable watchpost-agent.service")
			if tc.want == stateEnabled {
				if !disabled {
					t.Fatalf("%s should invoke disable", tc.state)
				}
			} else if disabled {
				t.Fatalf("%s must not invoke disable", tc.state)
			}
			if tc.want == stateUnknown {
				if err == nil {
					t.Fatalf("%s should fail closed", tc.state)
				}
				if _, serr := os.Stat(paths.Unit); serr != nil {
					t.Fatalf("unit removed for unknown enablement %s: %v", tc.state, serr)
				}
			} else {
				if err != nil {
					t.Fatalf("uninstall for %s failed: %v", tc.state, err)
				}
				if _, serr := os.Stat(paths.Unit); !os.IsNotExist(serr) {
					t.Fatalf("unit not removed for %s", tc.state)
				}
				if _, serr := os.Stat(paths.Binary); !os.IsNotExist(serr) {
					t.Fatalf("binary not removed for %s", tc.state)
				}
			}
		})
	}
}

func TestUninstallStateQueryFailures(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	fr.handler = func(name string, args ...string) (string, int, error) {
		if fr.contains(args, "is-active") {
			return "Failed to connect to bus: No such file or directory", 1, nil
		}
		return "", 0, nil
	}
	if err := manager.Uninstall(os.Stderr, paths); err == nil {
		t.Fatal("uninstall treated a bus failure as inactive")
	} else if !strings.Contains(err.Error(), "unrecognized") {
		t.Fatalf("bus failure should surface as unrecognized state, got: %v", err)
	}
	if _, serr := os.Stat(paths.Unit); serr != nil {
		t.Fatalf("unit removed despite bus failure: %v", serr)
	}
	joined := strings.Join(fr.calls, "\n")
	if strings.Contains(joined, "stop watchpost-agent.service") || strings.Contains(joined, "disable watchpost-agent.service") || strings.Contains(joined, "daemon-reload") {
		t.Fatalf("destructive steps ran after an active-state query failure: %s", joined)
	}
}

func TestDisableVerificationFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name             string
		afterDisableOut  string
		afterDisableCode int
		afterDisableErr  error
	}{
		{"unknown", "unknown", 3, nil},
		{"unrecognized", "bogus-state", 1, nil},
		{"launch failure", "", -1, errors.New("bus gone")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager, fr, paths, source := testManager(t)
			if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
				t.Fatal(err)
			}
			fr.calls = nil
			fr.handler = func(name string, args ...string) (string, int, error) {
				switch {
				case fr.contains(args, "is-active"):
					return "inactive", 3, nil
				case fr.contains(args, "is-enabled"):
					if fr.saw("disable watchpost-agent.service") {
						return tc.afterDisableOut, tc.afterDisableCode, tc.afterDisableErr
					}
					return "enabled", 0, nil
				}
				return "", 0, nil
			}
			if err := manager.Uninstall(os.Stderr, paths); err == nil {
				t.Fatalf("uninstall proceeded after a %q disable verification", tc.name)
			}
			if _, err := os.Stat(paths.Unit); err != nil {
				t.Fatalf("unit removed despite failed disable verification: %v", err)
			}
			if strings.Contains(strings.Join(fr.calls, "\n"), "daemon-reload") {
				t.Fatal("daemon-reload ran after a failed disable verification")
			}
		})
	}
}

func TestUninstallRollback(t *testing.T) {
	backupFiles := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var out []string
		for _, e := range ents {
			if strings.HasPrefix(e.Name(), ".watchpost-agent.service.unit-backup-") {
				out = append(out, e.Name())
			}
		}
		return out
	}

	t.Run("success removes unit, binary and no backup artifacts", func(t *testing.T) {
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			}
			return "", 0, nil
		}
		if err := manager.Uninstall(os.Stderr, paths); err != nil {
			t.Fatalf("uninstall: %v", err)
		}
		if _, err := os.Stat(paths.Unit); !os.IsNotExist(err) {
			t.Fatal("unit still present after uninstall")
		}
		if _, err := os.Stat(paths.Binary); !os.IsNotExist(err) {
			t.Fatal("binary still present after uninstall")
		}
		if _, err := os.Stat(paths.DataDir); err != nil {
			t.Fatalf("data directory was removed by uninstall: %v", err)
		}
		if len(backupFiles(filepath.Dir(paths.Unit))) != 0 {
			t.Fatal("backup artifacts remain after a successful uninstall")
		}
	})

	t.Run("reload failure restores the original unit and removes the backup", func(t *testing.T) {
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
			t.Fatal(err)
		}
		orig, _ := os.ReadFile(paths.Unit)
		origInfo, _ := os.Stat(paths.Unit)
		fr.calls = nil
		reloadCalls := 0
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				reloadCalls++
				if reloadCalls == 1 {
					return "Failed to reload", 1, nil
				}
				return "", 0, nil
			}
			return "", 0, nil
		}
		err := manager.Uninstall(os.Stderr, paths)
		if err == nil {
			t.Fatal("uninstall did not report the reload failure")
		}
		if !strings.Contains(err.Error(), "restored") {
			t.Fatalf("reload failure did not restore the unit: %v", err)
		}
		got, _ := os.ReadFile(paths.Unit)
		if string(got) != string(orig) {
			t.Fatal("restored unit does not match the original byte-for-byte")
		}
		gotInfo, _ := os.Stat(paths.Unit)
		if !os.SameFile(origInfo, gotInfo) {
			t.Fatal("restored unit is not the original inode")
		}
		if len(backupFiles(filepath.Dir(paths.Unit))) != 0 {
			t.Fatal("backup artifacts remain after restoration")
		}
	})

	t.Run("concurrent replacement is preserved and the backup is recoverable", func(t *testing.T) {
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
			t.Fatal(err)
		}
		orig, _ := os.ReadFile(paths.Unit)
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "disabled", 1, nil
			case fr.contains(args, "daemon-reload"):
				_ = os.WriteFile(paths.Unit, []byte("# replacement\n"), 0644)
				return "Failed to reload", 1, nil
			}
			return "", 0, nil
		}
		err := manager.Uninstall(os.Stderr, paths)
		if err == nil {
			t.Fatal("uninstall did not report the reload failure")
		}
		if !strings.Contains(err.Error(), "concurrently created") || !strings.Contains(err.Error(), "preserved at") {
			t.Fatalf("restoration conflict not reported clearly: %v", err)
		}
		got, _ := os.ReadFile(paths.Unit)
		if string(got) != "# replacement\n" {
			t.Fatalf("concurrently created file was overwritten: %q", got)
		}
		backs := backupFiles(filepath.Dir(paths.Unit))
		if len(backs) != 1 {
			t.Fatalf("expected exactly one retained backup, got %v", backs)
		}
		recovered, _ := os.ReadFile(filepath.Join(filepath.Dir(paths.Unit), backs[0]))
		if string(recovered) != string(orig) {
			t.Fatal("retained backup does not contain the original unit")
		}
	})
}

func TestStatus(t *testing.T) {
	t.Run("missing unit", func(t *testing.T) {
		manager, _, paths, _ := testManager(t)
		if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
			t.Fatal("status of a missing unit should fail")
		}
	})
	t.Run("inactive service", func(t *testing.T) {
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = func(name string, args ...string) (string, int, error) {
			switch {
			case fr.contains(args, "is-active"):
				return "inactive", 3, nil
			case fr.contains(args, "is-enabled"):
				return "enabled", 0, nil
			}
			return "", 0, nil
		}
		if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
			t.Fatal("status of an inactive service should fail")
		}
	})
	t.Run("uses installed listen and healthz", func(t *testing.T) {
		srv := jsonServer(t, 200, `{"status":"ok"}`, "application/json")
		listen := strings.TrimPrefix(srv.URL, "http://")
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, listen, ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := manager.Status(os.Stderr, paths, "1.0"); err != nil {
			t.Fatalf("status with installed listen failed: %v", err)
		}
	})
	t.Run("404 health response", func(t *testing.T) {
		srv := jsonServer(t, 404, `{"error":"not found"}`, "application/json")
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, strings.TrimPrefix(srv.URL, "http://"), ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
			t.Fatal("status with a 404 health response should fail")
		}
	})
	t.Run("401 health response", func(t *testing.T) {
		srv := jsonServer(t, 401, `{"error":"unauthorized"}`, "application/json")
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, strings.TrimPrefix(srv.URL, "http://"), ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
			t.Fatal("status with a 401 health response should fail")
		}
	})
	t.Run("non-JSON 200 health response", func(t *testing.T) {
		srv := jsonServer(t, 200, `ok`, "text/plain")
		manager, fr, paths, source := testManager(t)
		if err := manager.Install(source, paths, strings.TrimPrefix(srv.URL, "http://"), ""); err != nil {
			t.Fatal(err)
		}
		fr.handler = activeHandler(fr)
		if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
			t.Fatal("status with a non-JSON 200 health response should fail")
		}
	})
}

func TestBackupManagedUnitNoReplace(t *testing.T) {
	dirEntries := func(dir string) []string {
		ents, err := os.ReadDir(dir)
		if err != nil {
			return nil
		}
		var out []string
		for _, e := range ents {
			out = append(out, e.Name())
		}
		return out
	}

	t.Run("random source failure leaves the original intact", func(t *testing.T) {
		orig := randomSuffix
		randomSuffix = func() (string, error) { return "", errors.New("rand failed") }
		t.Cleanup(func() { randomSuffix = orig })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("random-source failure should error")
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
		if entries := dirEntries(dir); len(entries) != 1 {
			t.Fatalf("unexpected entries after failure: %v", entries)
		}
	})

	t.Run("collision never overwrites a retained backup", func(t *testing.T) {
		orig := randomSuffix
		randomSuffix = func() (string, error) { return "aa", nil }
		t.Cleanup(func() { randomSuffix = orig })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		retained := filepath.Join(dir, ".app.service.unit-backup-aa")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(retained, []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("all candidates collided; should error")
		}
		if got, _ := os.ReadFile(retained); string(got) != "retained" {
			t.Fatalf("retained backup was overwritten: %q", got)
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
	})

	t.Run("unlink failure aborts and leaves no artifact", func(t *testing.T) {
		origSuffix, origRemove := randomSuffix, removeFile
		randomSuffix = func() (string, error) { return "bb", nil }
		removeFile = func(p string) error { return errors.New("remove failed") }
		t.Cleanup(func() { randomSuffix, removeFile = origSuffix, origRemove })
		dir := t.TempDir()
		unit := filepath.Join(dir, "app.service")
		if err := os.WriteFile(unit, []byte("unit"), 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := backupManagedUnit(unit); err == nil {
			t.Fatal("unlink failure should error")
		}
		if got, _ := os.ReadFile(unit); string(got) != "unit" {
			t.Fatalf("original changed: %q", got)
		}
		if entries := dirEntries(dir); len(entries) != 1 {
			t.Fatalf("backup artifact left after aborted transaction: %v", entries)
		}
	})
}

func TestEnvFile(t *testing.T) {
	dir := t.TempDir()
	env := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(env, []byte("WATCHPOST_AGENT_SECURE_COOKIES=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manager, _, paths, source := testManager(t)

	t.Run("unit includes EnvironmentFile and authenticated metadata", func(t *testing.T) {
		unit := Unit(paths, "127.0.0.1:8090", env)
		if !strings.Contains(unit, "EnvironmentFile="+systemdQuote(env)) {
			t.Fatalf("unit missing EnvironmentFile\n%s", unit)
		}
		if !strings.Contains(unit, "# watchpost-agent-envfile: "+env) {
			t.Fatalf("unit missing envfile metadata\n%s", unit)
		}
		meta, err := readManagedUnitBytes(t, []byte(unit))
		if err != nil {
			t.Fatalf("unit should validate: %v", err)
		}
		if meta.envfile != env {
			t.Fatalf("meta.envfile=%q", meta.envfile)
		}
	})

	t.Run("validateEnvFile rejects unsafe files", func(t *testing.T) {
		if err := validateEnvFile(env); err != nil {
			t.Fatalf("valid env file rejected: %v", err)
		}
		if err := validateEnvFile("relative.env"); err == nil {
			t.Fatal("relative path accepted")
		}
		sym := filepath.Join(dir, "link.env")
		if err := os.Symlink(env, sym); err != nil {
			t.Fatal(err)
		}
		if err := validateEnvFile(sym); err == nil {
			t.Fatal("symlink accepted")
		}
		world := filepath.Join(dir, "world.env")
		if err := os.WriteFile(world, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := validateEnvFile(world); err == nil {
			t.Fatal("group/world-writable accepted")
		}
		percent := filepath.Join(dir, "bad%env")
		if err := os.WriteFile(percent, []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := validateEnvFile(percent); err == nil {
			t.Fatal("systemd specifier character accepted")
		}
	})

	t.Run("install validates the environment file", func(t *testing.T) {
		world := filepath.Join(dir, "world2.env")
		if err := os.WriteFile(world, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
		if err := manager.Install(source, paths, "127.0.0.1:8090", world); err == nil {
			t.Fatal("install accepted an unsafe environment file")
		}
	})
}

func TestUpgradePreservesInstalledConfig(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	dir := t.TempDir()
	env := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(env, []byte("WATCHPOST_AGENT_SECURE_COOKIES=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(source, paths, "127.0.0.1:9005", env); err != nil {
		t.Fatal(err)
	}
	// Upgrade with unset listen/env-file preserves the installed values.
	upgradeListen, upgradeEnv := PreserveInstallValues(metaFrom(t, manager, paths), false, "", false, "")
	if upgradeListen != "127.0.0.1:9005" || upgradeEnv != env {
		t.Fatalf("preserved values wrong: listen=%q env=%q", upgradeListen, upgradeEnv)
	}
	if err := manager.Upgrade(source, paths, upgradeListen, upgradeEnv); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	meta, ok, err := manager.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("existing meta: ok=%v err=%v", ok, err)
	}
	if meta.Listen != "127.0.0.1:9005" || meta.EnvFile != env {
		t.Fatalf("upgrade did not preserve config: listen=%q env=%q", meta.Listen, meta.EnvFile)
	}
	// Explicit override changes it.
	env2 := filepath.Join(dir, "agent2.env")
	if err := os.WriteFile(env2, []byte("x=1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Upgrade(source, paths, "127.0.0.1:9006", env2); err != nil {
		t.Fatal(err)
	}
	meta, _, _ = manager.ExistingMeta(paths)
	if meta.Listen != "127.0.0.1:9006" || meta.EnvFile != env2 {
		t.Fatalf("explicit override failed: listen=%q env=%q", meta.Listen, meta.EnvFile)
	}
	// Upgrade refuses a foreign unit.
	if err := os.WriteFile(paths.Unit, []byte("# hand written\n"), 0644); err != nil {
		t.Fatal(err)
	}
	fr.calls = nil
	if err := manager.Upgrade(source, paths, "127.0.0.1:8090", ""); err == nil {
		t.Fatal("upgrade overwrote a foreign unit")
	}
	if len(fr.calls) != 0 {
		t.Fatalf("upgrade ran systemctl against a foreign unit: %v", fr.calls)
	}
}

func metaFrom(t *testing.T, m Manager, paths Paths) Meta {
	t.Helper()
	meta, ok, err := m.ExistingMeta(paths)
	if err != nil || !ok {
		t.Fatalf("existing meta: ok=%v err=%v", ok, err)
	}
	return meta
}

func TestEnvFilePermissions(t *testing.T) {
	dir := t.TempDir()
	modes := []struct {
		mode os.FileMode
		ok   bool
	}{
		{0o000, false}, {0o200, false}, {0o400, false}, {0o600, true},
		{0o640, false}, {0o660, false}, {0o666, false},
	}
	for _, tc := range modes {
		env := filepath.Join(dir, fmt.Sprintf("env-%o", tc.mode))
		if err := os.WriteFile(env, []byte("x\n"), tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := validateEnvFile(env); (err == nil) != tc.ok {
			t.Fatalf("mode %04o: ok=%v err=%v", tc.mode, tc.ok, err)
		}
	}
}

func TestReadWritePath(t *testing.T) {
	if err := validateReadWritePath("/home/nick/my data"); err != nil {
		t.Fatalf("space path rejected: %v", err)
	}
	paths := Paths{Binary: "/usr/local/lib/watchpost-agent/watchpost-agent", DataDir: "/home/nick/my data"}
	unit := Unit(paths, "127.0.0.1:8090", "")
	if !strings.Contains(unit, `ReadWritePaths="/home/nick/my data"`) {
		t.Fatalf("ReadWritePaths not quoted:\n%s", unit)
	}
	for _, bad := range []string{"/x/%h", "/x/\"/y", "/x/\\y", "-/weird", "+/weird", "!/weird", "~/weird", "relative"} {
		if err := validateReadWritePath(bad); err == nil {
			t.Fatalf("unsafe ReadWritePaths path accepted: %q", bad)
		}
	}
}

func TestFreshInstallPreparesDataDir(t *testing.T) {
	manager, _, paths, source := testManager(t)
	paths.DataDir = filepath.Join(t.TempDir(), "state", "data")
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatalf("fresh install failed: %v", err)
	}
	info, err := os.Stat(paths.DataDir)
	if err != nil || !info.IsDir() {
		t.Fatalf("data dir not created: %v", err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatalf("data dir mode=%v", info.Mode().Perm())
	}
	symTarget := filepath.Join(t.TempDir(), "target")
	if err := os.MkdirAll(symTarget, 0700); err != nil {
		t.Fatal(err)
	}
	sym := filepath.Join(t.TempDir(), "symlink")
	if err := os.Symlink(symTarget, sym); err != nil {
		t.Fatal(err)
	}
	paths.DataDir = sym
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err == nil {
		t.Fatal("symlink data dir accepted")
	}
}

func TestEnvFileRevalidatedOnStartRestart(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	dir := t.TempDir()
	env := filepath.Join(dir, "agent.env")
	if err := os.WriteFile(env, []byte("WATCHPOST_AGENT_SECURE_COOKIES=true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(source, paths, "127.0.0.1:8090", env); err != nil {
		t.Fatal(err)
	}
	fr.handler = func(name string, args ...string) (string, int, error) {
		if fr.contains(args, "is-active") || fr.contains(args, "is-enabled") {
			return "active", 0, nil
		}
		return "", 0, nil
	}
	if err := manager.Restart(paths); err != nil {
		t.Fatalf("restart with valid env file failed: %v", err)
	}
	if err := os.Remove(env); err != nil {
		t.Fatal(err)
	}
	if err := manager.Restart(paths); err == nil {
		t.Fatal("restart succeeded with a missing env file")
	}
	if err := manager.Start(paths); err == nil {
		t.Fatal("start succeeded with a missing env file")
	}
	if err := manager.Status(os.Stderr, paths, "1.0"); err == nil {
		t.Fatal("status succeeded with a missing env file")
	}
	if err := manager.Stop(paths); err != nil {
		t.Fatalf("stop should remain possible: %v", err)
	}
}

func TestUpgradeTransaction(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	if err := os.WriteFile(source, []byte("v1 binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := manager.Install(source, paths, "127.0.0.1:9001", ""); err != nil {
		t.Fatal(err)
	}
	oldUnit, _ := os.ReadFile(paths.Unit)
	oldBinary, _ := os.ReadFile(paths.Binary)

	t.Run("restart failure rolls back unit and binary", func(t *testing.T) {
		if err := os.WriteFile(source, []byte("v2 binary"), 0755); err != nil {
			t.Fatal(err)
		}
		fr.calls = nil
		fr.handler = func(name string, args ...string) (string, int, error) {
			if fr.contains(args, "restart") {
				return "Failed", 1, nil
			}
			return "", 0, nil
		}
		if err := manager.Upgrade(source, paths, "127.0.0.1:9001", ""); err == nil {
			t.Fatal("upgrade should fail")
		}
		gotUnit, _ := os.ReadFile(paths.Unit)
		gotBinary, _ := os.ReadFile(paths.Binary)
		if string(gotUnit) != string(oldUnit) || string(gotBinary) != string(oldBinary) {
			t.Fatalf("failed upgrade left mixed state: unit=%q binary=%q", gotUnit, gotBinary)
		}
		meta, _, _ := manager.ExistingMeta(paths)
		if meta.Listen != "127.0.0.1:9001" {
			t.Fatalf("metadata not rolled back: %q", meta.Listen)
		}
		fr.handler = nil
	})

	t.Run("fresh install failure removes new artifacts", func(t *testing.T) {
		manager2, fr2, paths2, source2 := testManager(t)
		fr2.handler = func(name string, args ...string) (string, int, error) {
			if fr2.contains(args, "enable") {
				return "Failed", 1, nil
			}
			return "", 0, nil
		}
		if err := manager2.Install(source2, paths2, "127.0.0.1:9002", ""); err == nil {
			t.Fatal("install should fail")
		}
		if _, err := os.Stat(paths2.Unit); !os.IsNotExist(err) {
			t.Fatalf("unit not removed after failed fresh install: %v", err)
		}
		if _, err := os.Stat(paths2.Binary); !os.IsNotExist(err) {
			t.Fatalf("binary not removed after failed fresh install: %v", err)
		}
	})

	t.Run("staging failure leaves state intact", func(t *testing.T) {
		if err := os.Chmod(filepath.Dir(paths.Binary), 0500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(filepath.Dir(paths.Binary), 0700) })
		if err := manager.Upgrade(source, paths, "127.0.0.1:9001", ""); err == nil {
			t.Fatal("upgrade should fail when staging cannot write")
		}
		gotUnit, _ := os.ReadFile(paths.Unit)
		gotBinary, _ := os.ReadFile(paths.Binary)
		if string(gotUnit) != string(oldUnit) || string(gotBinary) != string(oldBinary) {
			t.Fatalf("staging failure changed installed state")
		}
	})
}

func TestReleaseMatrixBuilds(t *testing.T) {
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"linux", "arm64"},
		{"darwin", "amd64"}, {"darwin", "arm64"},
		{"windows", "amd64"}, {"windows", "arm64"},
	}
	for _, tc := range targets {
		t.Run(tc.goos+"/"+tc.goarch, func(t *testing.T) {
			dir := t.TempDir()
			cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "svc"), ".")
			cmd.Env = append(os.Environ(), "GOOS="+tc.goos, "GOARCH="+tc.goarch, "CGO_ENABLED=0")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s/%s build failed: %v\n%s", tc.goos, tc.goarch, err, out)
			}
		})
	}
}

func TestLogsReportsNonzeroJournalctl(t *testing.T) {
	manager, fr, paths, source := testManager(t)
	if err := manager.Install(source, paths, "127.0.0.1:8090", ""); err != nil {
		t.Fatal(err)
	}
	fr.handler = func(name string, args ...string) (string, int, error) {
		if name == "journalctl" {
			return "no journal found", 1, nil
		}
		return "", 0, nil
	}
	if err := manager.Logs(false, os.Stderr, paths); err == nil {
		t.Fatal("logs ignored a nonzero journalctl exit")
	}
}