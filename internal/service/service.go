package service

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// unitMarker marks unit files written by `watchpost-agent service`.
const unitMarker = "# Managed by watchpost-agent. Do not edit manually."

// managedPrefix introduces the versioned integrity header. The header is
// followed by a SHA-256 of everything below it (managed metadata plus the unit
// body), so any hand edit is detected on the next write, action or uninstall.
const managedPrefix = "# watchpost-agent-managed: "

// healthPath is the public, read-only liveness endpoint the service health
// check targets.
const healthPath = "/healthz"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// Paths holds the resolved installation paths for a user or system unit.
type Paths struct {
	Binary  string
	DataDir string
	Unit    string
	System  bool
}

// Resolve returns the stable paths for the agent in user or system mode.
func Resolve(system bool) (Paths, error) {
	if runtime.GOOS != "linux" {
		return Paths{}, errors.New("service installation currently requires Linux systemd")
	}
	if system {
		return Paths{Binary: "/usr/local/lib/watchpost-agent/watchpost-agent", DataDir: "/var/lib/watchpost-agent", Unit: "/etc/systemd/system/watchpost-agent.service", System: true}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	return Paths{
		Binary:  filepath.Join(home, ".local", "lib", "watchpost-agent", "watchpost-agent"),
		DataDir: filepath.Join(home, ".local", "share", "watchpost-agent"),
		Unit:    filepath.Join(home, ".config", "systemd", "user", "watchpost-agent.service"),
	}, nil
}

// Runner runs a command and returns its combined output, exit code (0 on
// success, -1 when the command could not be launched) and a launch error only.
type Runner func(name string, args ...string) (string, int, error)

// Streamer runs a command with inherited stdout/stderr and returns its exit
// code (used for journalctl --follow).
type Streamer func(name string, args ...string) (int, error)

type Manager struct {
	Run    Runner
	Stream Streamer
}

func New() Manager {
	return Manager{
		Run: func(name string, args ...string) (string, int, error) {
			cmd := exec.Command(name, args...)
			out, err := cmd.CombinedOutput()
			if err == nil {
				return string(out), 0, nil
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return string(out), ee.ExitCode(), nil
			}
			return string(out), -1, err
		},
		Stream: func(name string, args ...string) (int, error) {
			cmd := exec.Command(name, args...)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			err := cmd.Run()
			if err == nil {
				return 0, nil
			}
			var ee *exec.ExitError
			if errors.As(err, &ee) {
				return ee.ExitCode(), nil
			}
			return -1, err
		},
	}
}

// svcState is a deliberately resolved systemd state category that separates
// command-result validation from the lifecycle meaning uninstall needs.
type svcState string

const (
	stateActive     svcState = "active"
	stateReloading  svcState = "reloading"
	stateRefreshing svcState = "refreshing"
	stateTransition svcState = "transitioning"
	stateInactive   svcState = "inactive"
	stateUnknown    svcState = "unknown"
	stateEnabled    svcState = "enabled"
	stateNotEnabled svcState = "not-enabled"
	stateMasked     svcState = "masked"
)

func stateName(s svcState) string { return string(s) }

type exitExpect int

const (
	exitZero     exitExpect = iota
	exitNonzero
	exitEither
)

func classifyActive(word string) (svcState, exitExpect, bool) {
	switch word {
	case "active":
		return stateActive, exitZero, true
	case "reloading":
		return stateReloading, exitZero, true
	case "refreshing":
		return stateRefreshing, exitEither, true
	case "inactive", "dead", "failed":
		return stateInactive, exitNonzero, true
	case "activating", "deactivating", "maintenance":
		return stateTransition, exitNonzero, true
	case "not-found", "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

func classifyEnabled(word string) (svcState, exitExpect, bool) {
	switch word {
	case "enabled", "enabled-runtime":
		return stateEnabled, exitZero, true
	case "static", "alias", "indirect", "generated":
		return stateNotEnabled, exitZero, true
	case "disabled", "linked", "linked-runtime", "transient":
		return stateNotEnabled, exitNonzero, true
	case "masked", "masked-runtime":
		return stateMasked, exitNonzero, true
	case "not-found":
		return stateNotEnabled, exitNonzero, true
	case "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

func systemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%%")
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func (m Manager) systemctl(paths Paths, args ...string) (string, int, error) {
	if !paths.System {
		args = append([]string{"--user"}, args...)
	}
	return m.Run("systemctl", args...)
}

func (m Manager) systemctlSuccess(paths Paths, args ...string) error {
	out, code, err := m.systemctl(paths, args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

func (m Manager) queryState(paths Paths, verb string) (svcState, error) {
	out, code, err := m.systemctl(paths, verb, "watchpost-agent.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	word := strings.TrimSpace(out)
	var st svcState
	var expect exitExpect
	var ok bool
	switch verb {
	case "is-active":
		st, expect, ok = classifyActive(word)
	case "is-enabled":
		st, expect, ok = classifyEnabled(word)
	}
	if !ok {
		return "", fmt.Errorf("systemctl %s returned unrecognized state %q (exit %d)", verb, word, code)
	}
	switch expect {
	case exitZero:
		if code != 0 {
			return "", fmt.Errorf("systemctl %s reported %q but exited %d; inconsistent state result", verb, word, code)
		}
	case exitNonzero:
		if code == 0 {
			return "", fmt.Errorf("systemctl %s reported %q but exited 0; inconsistent state result", verb, word)
		}
	}
	return st, nil
}

func (m Manager) requireManaged(paths Paths, verb string) error {
	if _, err := readManagedUnit(paths.Unit); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("refusing to %s the service: unit is not installed", verb)
		}
		return fmt.Errorf("refusing to %s the service: %w", verb, err)
	}
	return nil
}

func renderUnitBody(paths Paths, listen string) string {
	wanted := "default.target"
	if paths.System {
		wanted = "multi-user.target"
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Watchpost Agent\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + systemdQuote(paths.Binary))
	b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(listen))
	b.WriteString(" " + systemdQuote("--data-dir") + " " + systemdQuote(paths.DataDir))
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5s\n")
	b.WriteString("UMask=0077\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=read-only\n")
	b.WriteString("ReadWritePaths=" + paths.DataDir + "\n")
	b.WriteString("Environment=HOME=%h\n")
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=" + wanted + "\n")
	return b.String()
}

// Unit renders the full managed unit: a marker line, a versioned integrity
// header carrying the SHA-256 of the managed content below it, the runtime
// metadata (listen/health) used by status, and the body.
func Unit(paths Paths, listen string) string {
	content := "# watchpost-agent-listen: " + listen + "\n# watchpost-agent-health: " + healthPath + "\n" + renderUnitBody(paths, listen)
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

type unitMeta struct {
	listen string
	health string
}

func readManagedUnit(path string) (unitMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unitMeta{}, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 || lines[0] != unitMarker {
		return unitMeta{}, errNotManaged
	}
	count := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, managedPrefix) {
			count++
		}
	}
	if count != 1 || !strings.HasPrefix(lines[1], managedPrefix) {
		return unitMeta{}, errMalformed
	}
	sm := regexp.MustCompile(`^# watchpost-agent-managed: v1 sha256=([0-9a-f]{64})$`).FindStringSubmatch(lines[1])
	if sm == nil {
		return unitMeta{}, errMalformed
	}
	content := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(content))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	meta := unitMeta{}
	listenSeen, healthSeen := 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# watchpost-agent-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-listen: "))
		case strings.HasPrefix(ln, "# watchpost-agent-health: "):
			healthSeen++
			if healthSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.health = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-health: "))
		}
	}
	if listenSeen != 1 || healthSeen != 1 || meta.listen == "" || meta.health == "" {
		return unitMeta{}, errMalformed
	}
	if meta.health != healthPath {
		return unitMeta{}, errMalformed
	}
	if err := validateNoControl(meta.listen, "listen"); err != nil {
		return unitMeta{}, errMalformed
	}
	return meta, nil
}

func writeManagedUnit(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		if _, err := readManagedUnit(path); err != nil {
			return fmt.Errorf("refusing to overwrite %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-agent-unit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func atomicCopy(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".watchpost-agent-install-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if _, err = io.Copy(temporary, input); err == nil {
		err = temporary.Chmod(mode)
	}
	if closeErr := temporary.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(name, destination)
}

func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

func unitBackupSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func backupManagedUnit(path string) (string, error) {
	dir := filepath.Dir(path)
	backup := filepath.Join(dir, "."+filepath.Base(path)+".unit-backup-"+unitBackupSuffix())
	if err := os.Rename(path, backup); err != nil {
		return "", err
	}
	syncDir(dir)
	return backup, nil
}

func restoreFromBackup(orig, backup string) error {
	if err := os.Link(backup, orig); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite a concurrently created unit at %s; the original unit is preserved at %s", orig, backup)
		}
		return err
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(orig))
	return nil
}

func healthCheck(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("expected 2xx, got HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		return fmt.Errorf("expected a JSON response, got %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("expected a JSON object response: %v", err)
	}
	return nil
}

// Install copies the agent binary to a stable path, writes the managed unit,
// and reloads, enables and restarts the service. Upgrade is the same call.
func (m Manager) Install(source string, paths Paths, listen string) error {
	for _, v := range []struct{ val, name string }{
		{listen, "listen"}, {paths.DataDir, "data-dir"},
	} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(paths.DataDir, 0700); err != nil {
		return err
	}
	if err := atomicCopy(source, paths.Binary, 0755); err != nil {
		return err
	}
	if err := writeManagedUnit(paths.Unit, Unit(paths, listen)); err != nil {
		return err
	}
	if err := m.systemctlSuccess(paths, "daemon-reload"); err != nil {
		return err
	}
	if err := m.systemctlSuccess(paths, "enable", "watchpost-agent.service"); err != nil {
		return err
	}
	return m.systemctlSuccess(paths, "restart", "watchpost-agent.service")
}

// Upgrade reinstalls the current binary, replacing an existing installation.
func (m Manager) Upgrade(source string, paths Paths, listen string) error {
	return m.Install(source, paths, listen)
}

func (m Manager) Start(paths Paths) error {
	return m.action(paths, "start")
}
func (m Manager) Stop(paths Paths) error {
	return m.action(paths, "stop")
}
func (m Manager) Restart(paths Paths) error {
	return m.action(paths, "restart")
}

func (m Manager) action(paths Paths, verb string) error {
	if err := m.requireManaged(paths, verb); err != nil {
		return err
	}
	out, code, err := m.systemctl(paths, verb, "watchpost-agent.service")
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", verb, code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

func (m Manager) Status(out io.Writer, paths Paths, version string) error {
	meta, err := readManagedUnit(paths.Unit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the service is not installed (no unit at %s)", paths.Unit)
		}
		return fmt.Errorf("the service unit is not valid: %w", err)
	}
	enabled, err := m.queryState(paths, "is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine enablement state: %w", err)
	}
	active, err := m.queryState(paths, "is-active")
	if err != nil {
		return fmt.Errorf("cannot determine service state: %w", err)
	}
	pid, _, _ := m.systemctl(paths, "show", "-p", "MainPID", "--value", "watchpost-agent.service")
	fmt.Fprintf(out, "unit:    watchpost-agent.service\n")
	fmt.Fprintf(out, "file:    %s\n", paths.Unit)
	fmt.Fprintf(out, "enabled: %s\n", enabled)
	fmt.Fprintf(out, "active:  %s\n", active)
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "listen:  %s\n", meta.listen)
	if active != stateActive {
		return fmt.Errorf("service is %q; expected active", active)
	}
	if err := healthCheck("http://" + meta.listen + meta.health); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

func (m Manager) Logs(follow bool, out io.Writer, paths Paths) error {
	if err := m.requireManaged(paths, "view logs for"); err != nil {
		return err
	}
	var args []string
	if paths.System {
		args = []string{"--unit", "watchpost-agent.service"}
	} else {
		args = []string{"--user-unit", "watchpost-agent.service"}
	}
	if follow {
		args = append(args, "-f")
		code, err := m.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	outText, code, err := m.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(outText)))
	}
	fmt.Fprint(out, outText)
	return nil
}

func (m Manager) Uninstall(out io.Writer, paths Paths) error {
	if _, err := readManagedUnit(paths.Unit); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the service is not installed")
		}
		return fmt.Errorf("refusing to uninstall the service: %w", err)
	}
	active, err := m.queryState(paths, "is-active")
	if err != nil {
		return fmt.Errorf("cannot determine service state before uninstall: %w", err)
	}
	if active == stateActive || active == stateReloading || active == stateRefreshing || active == stateTransition {
		if err := m.systemctlSuccess(paths, "stop", "watchpost-agent.service"); err != nil {
			return fmt.Errorf("stop failed: %w", err)
		}
		after, err := m.queryState(paths, "is-active")
		if err != nil {
			return fmt.Errorf("cannot verify the service stopped after stop: %w", err)
		}
		if after != stateInactive {
			return fmt.Errorf("the service still reports %q after stop; not removing the unit", stateName(after))
		}
	} else if active == stateInactive {
		fmt.Fprintf(out, "note: the service is inactive; nothing to stop\n")
	} else {
		return fmt.Errorf("the service is in %q; cannot confirm it is safely stopped before uninstall", stateName(active))
	}
	enabled, err := m.queryState(paths, "is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine enablement before uninstall: %w", err)
	}
	if enabled == stateEnabled {
		if err := m.systemctlSuccess(paths, "disable", "watchpost-agent.service"); err != nil {
			return fmt.Errorf("disable failed: %w", err)
		}
		after, err := m.queryState(paths, "is-enabled")
		if err != nil {
			return fmt.Errorf("cannot verify the service disabled after disable: %w", err)
		}
		if after != stateNotEnabled && after != stateMasked {
			return fmt.Errorf("the service still reports %q after disable; not removing the unit", stateName(after))
		}
	} else if enabled == stateNotEnabled || enabled == stateMasked {
		fmt.Fprintf(out, "note: the service is %s; nothing to disable\n", stateName(enabled))
	} else {
		return fmt.Errorf("enablement is %q; cannot confirm it is disabled before uninstall", stateName(enabled))
	}
	backup, err := backupManagedUnit(paths.Unit)
	if err != nil {
		return fmt.Errorf("cannot move the unit aside for uninstall: %w", err)
	}
	if err := m.systemctlSuccess(paths, "daemon-reload"); err != nil {
		if restoreErr := restoreFromBackup(paths.Unit, backup); restoreErr != nil {
			return fmt.Errorf("reloading systemd after removing the unit: %w; additionally failed to restore the unit: %v", err, restoreErr)
		}
		if reloadErr := m.systemctlSuccess(paths, "daemon-reload"); reloadErr != nil {
			return fmt.Errorf("reloading systemd after removing the unit: %w; the unit was restored but the follow-up reload also failed: %v", err, reloadErr)
		}
		return fmt.Errorf("reloading systemd after removing the unit: %w; the unit was restored", err)
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(paths.Unit))
	if err := os.Remove(paths.Binary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	fmt.Fprintf(out, "Removed the Watchpost Agent service. Agent data in %s was preserved.\n", paths.DataDir)
	return nil
}