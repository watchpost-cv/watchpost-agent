package service

import (
	"bytes"
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

// Resolve returns the stable paths for the agent in user mode. System-wide
// mode is intentionally not supported yet: the previous implementation ran the
// agent web service as root, which is not an acceptable default. A dedicated
// unprivileged account design is a documented follow-up.
func Resolve(system bool) (Paths, error) {
	if runtime.GOOS != "linux" {
		return Paths{}, errors.New("service installation currently requires Linux systemd")
	}
	if system {
		return Paths{}, errors.New("--system is not supported yet: it previously ran the agent web service as root; a dedicated unprivileged service account is a documented follow-up")
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
	exitZero exitExpect = iota
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

func renderUnitBody(paths Paths, listen, envfile string) string {
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
	b.WriteString("ReadWritePaths=" + systemdQuote(paths.DataDir) + "\n")
	b.WriteString("Environment=HOME=%h\n")
	if envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(envfile) + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=" + wanted + "\n")
	return b.String()
}

// Unit renders the full managed unit: a marker line, a versioned integrity
// header carrying the SHA-256 of the managed content below it, the runtime
// metadata (listen/health/envfile) used by status, and the body.
func Unit(paths Paths, listen, envfile string) string {
	meta := "# watchpost-agent-listen: " + listen + "\n"
	if envfile != "" {
		meta += "# watchpost-agent-envfile: " + envfile + "\n"
	}
	meta += "# watchpost-agent-health: " + healthPath + "\n"
	content := meta + renderUnitBody(paths, listen, envfile)
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

type unitMeta struct {
	listen  string
	envfile string
	health  string
}

// Meta is the exported view of a managed unit's integrity-checked metadata.
type Meta struct {
	Listen  string
	EnvFile string
}

// ExistingMeta returns the installed managed unit's integrity-checked metadata, or
// ok=false when no unit is installed. A foreign or modified unit is an error so
// install/upgrade never silently diverge from it.
func (m Manager) ExistingMeta(paths Paths) (Meta, bool, error) {
	meta, err := readManagedUnit(paths.Unit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Meta{}, false, nil
		}
		return Meta{}, false, fmt.Errorf("existing unit at %s is not valid: %w", paths.Unit, err)
	}
	return Meta{Listen: meta.listen, EnvFile: meta.envfile}, true, nil
}

// PreserveInstallValues fills values the operator did not explicitly set from
// the existing managed metadata, so install/upgrade never silently replace
// installed configuration with CLI defaults.
func PreserveInstallValues(existing Meta, listenSet bool, listen string, envfileSet bool, envfile string) (string, string) {
	if !listenSet && existing.Listen != "" {
		listen = existing.Listen
	}
	if !envfileSet && existing.EnvFile != "" {
		envfile = existing.EnvFile
	}
	return listen, envfile
}

// validateEnvFile validates an EnvironmentFile path for the service unit:
// absolute, a regular non-symlink file with exactly owner-only 0600
// permissions, owned by the invoking user, and free of systemd specifier and
// control characters. Secret values are never read or embedded.
func validateEnvFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("environment file %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "environment file"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("environment file %q must not contain systemd specifiers (%% )", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("environment file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("environment file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("environment file %q must be a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("environment file %q must have exactly 0600 permissions (owner read/write only)", path)
	}
	if err := fileOwnerOK(info); err != nil {
		return fmt.Errorf("environment file %q: %w", path, err)
	}
	return nil
}

// prepareDataDir creates the service data directory with owner-only permissions
// and refuses symlinks, non-directories, unsafe permissions or wrong ownership.
func prepareDataDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("cannot create data directory %q: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("data directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data directory %q must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("data directory %q is not a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("data directory %q must not be group- or world-writable", path)
	}
	if err := fileOwnerOK(info); err != nil {
		return fmt.Errorf("data directory %q: %w", path, err)
	}
	return nil
}

// validateReadWritePath validates a data directory for the ReadWritePaths=
// directive: absolute, free of control characters, systemd specifiers, quotes
// and backslashes, and not starting with a special path-list prefix.
func validateReadWritePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("data directory %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "data directory"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("data directory %q must not contain systemd specifiers (%% )", path)
	}
	if strings.ContainsAny(path, `"\`) {
		return fmt.Errorf("data directory %q cannot be safely quoted in ReadWritePaths", path)
	}
	if len(path) > 0 && strings.ContainsRune("-+!~", rune(path[0])) {
		return fmt.Errorf("data directory %q starts with a ReadWritePaths special prefix; use a plain absolute path", path)
	}
	return nil
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
	listenSeen, envfileSeen, healthSeen := 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# watchpost-agent-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-listen: "))
		case strings.HasPrefix(ln, "# watchpost-agent-envfile: "):
			envfileSeen++
			if envfileSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.envfile = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-envfile: "))
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
	if envfileSeen > 1 {
		return unitMeta{}, errMalformed
	}
	if meta.health != healthPath {
		return unitMeta{}, errMalformed
	}
	if err := validateNoControl(meta.listen, "listen"); err != nil {
		return unitMeta{}, errMalformed
	}
	if meta.envfile != "" {
		if err := validateNoControl(meta.envfile, "environment file"); err != nil {
			return unitMeta{}, errMalformed
		}
		if strings.ContainsAny(meta.envfile, "%") {
			return unitMeta{}, errMalformed
		}
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

func readFileIfPresent(path string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// stageCopy copies source to a staging file beside destination (no publish),
// so a copy failure can never corrupt the installed binary.
func stageCopy(source, dest string, mode os.FileMode) (string, error) {
	input, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer input.Close()
	dir := filepath.Dir(dest)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-agent-stage-*")
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if _, err := io.Copy(tmp, input); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-agent-restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// systemctlTolerantMissing runs a systemctl verb treating "unit not loaded /
// not found" results as success, which is expected when rolling back a failed
// fresh install whose unit has already been removed.
func (m Manager) systemctlTolerantMissing(paths Paths, args ...string) error {
	out, code, err := m.systemctl(paths, args...)
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "not loaded") || strings.Contains(low, "not found") || strings.Contains(low, "no such file") {
			return nil
		}
		return err
	}
	if code != 0 {
		low := strings.ToLower(out)
		if strings.Contains(low, "not loaded") || strings.Contains(low, "not found") || strings.Contains(low, "no such file") {
			return nil
		}
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// rawState returns the exact systemctl is-enabled/is-active output word. The
// install transaction snapshots these raw words rather than the resolved
// lifecycle categories so rollback can reproduce the precise prior state.
func (m Manager) rawState(paths Paths, verb string) (string, error) {
	out, _, err := m.systemctl(paths, verb, "watchpost-agent.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	word := strings.TrimSpace(out)
	if word == "" {
		return "", fmt.Errorf("systemctl %s returned no state", verb)
	}
	return word, nil
}

// restorableEnabledWord reports whether a prior is-enabled raw word can be
// restored exactly. Enablement links (enabled, enabled-runtime, masked,
// masked-runtime) and their absence (disabled, not-found) are restorable;
// unit-file states that enable/disable cannot reproduce (static, alias,
// indirect, generated, linked, linked-runtime, transient, unknown) are not.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "masked", "masked-runtime", "disabled", "not-found":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active raw word can be
// restored exactly. Running and stopped states are restorable; transient and
// failed states cannot be reproduced deterministically.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive", "dead", "unknown", "not-found":
		return true
	}
	return false
}

// enableRestoreArgs returns the systemctl call that reproduces a prior
// is-enabled word exactly.
func enableRestoreArgs(word, unit string) []string {
	switch word {
	case "enabled":
		return []string{"enable", unit}
	case "enabled-runtime":
		return []string{"enable", "--runtime", unit}
	case "masked":
		return []string{"mask", unit}
	case "masked-runtime":
		return []string{"mask", "--runtime", unit}
	}
	return []string{"disable", unit}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior
// is-active word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

// rollbackInstall restores the pre-install state after a failed publish or
// lifecycle step. For a reinstall it restores the prior unit and binary bytes,
// reloads systemd, then reproduces the exact prior enablement and active
// states. For a failed fresh install it stops and disables the newly installed
// unit while it is still loaded, then removes the unit and binary and reloads
// systemd, so no enablement link, active service or published binary is left
// behind. It returns an explanatory string when rollback itself fails so
// callers never claim a full rollback when only part of it succeeded.
func (m Manager) rollbackInstall(paths Paths, oldUnit, oldBinary []byte, hadUnit, hadBinary bool, priorEnabledWord, priorActiveWord string) string {
	var errs []string
	if hadUnit {
		if err := writeFileAtomic(paths.Unit, oldUnit, 0644); err != nil {
			errs = append(errs, fmt.Sprintf("restore unit: %v", err))
		}
	} else {
		if err := m.systemctlTolerantMissing(paths, "stop", "watchpost-agent.service"); err != nil {
			errs = append(errs, fmt.Sprintf("stop new unit: %v", err))
		}
		if err := m.systemctlTolerantMissing(paths, "disable", "watchpost-agent.service"); err != nil {
			errs = append(errs, fmt.Sprintf("disable new unit: %v", err))
		}
	}
	if hadUnit {
		if hadBinary {
			if err := writeFileAtomic(paths.Binary, oldBinary, 0755); err != nil {
				errs = append(errs, fmt.Sprintf("restore binary: %v", err))
			}
		}
	} else {
		if err := os.Remove(paths.Unit); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("remove new unit: %v", err))
		}
		if err := os.Remove(paths.Binary); err != nil && !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, fmt.Sprintf("remove new binary: %v", err))
		}
	}
	if err := m.systemctlSuccess(paths, "daemon-reload"); err != nil {
		errs = append(errs, fmt.Sprintf("reload systemd: %v", err))
	}
	if hadUnit {
		if err := m.systemctlSuccess(paths, enableRestoreArgs(priorEnabledWord, "watchpost-agent.service")...); err != nil {
			errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabledWord, err))
		}
		if err := m.systemctlSuccess(paths, activeRestoreArgs(priorActiveWord, "watchpost-agent.service")...); err != nil {
			errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActiveWord, err))
		}
	}
	if len(errs) > 0 {
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	return ""
}

func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

var (
	linkFile     = os.Link
	removeFile   = os.Remove
	randomSuffix = func() (string, error) {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}
)

// backupManagedUnit moves the managed unit aside to a unique hidden backup name
// in the same directory. It uses an exclusive hard link so an existing retained
// backup is never overwritten; the original is unlinked only after the backup
// link exists, and on any failure the original stays intact with no backup
// artifact left behind.
func backupManagedUnit(path string) (string, error) {
	dir := filepath.Dir(path)
	for i := 0; i < 32; i++ {
		suffix, err := randomSuffix()
		if err != nil {
			return "", fmt.Errorf("cannot generate a backup name: %w", err)
		}
		backup := filepath.Join(dir, "."+filepath.Base(path)+".unit-backup-"+suffix)
		if err := linkFile(path, backup); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // candidate already exists; try another name
			}
			return "", err
		}
		if err := removeFile(path); err != nil {
			_ = os.Remove(backup)
			return "", fmt.Errorf("cannot remove the original after backing it up: %w", err)
		}
		syncDir(dir)
		return backup, nil
	}
	return "", errors.New("could not allocate a unique backup name")
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

// Install publishes a new unit and binary as a failure-atomic transaction:
// inputs are validated, the replacement binary is staged first (no published
// change), then the unit and binary are published, then the lifecycle runs.
// Any copy, reload, enable or restart failure restores the prior unit and
// binary (or removes them for a fresh install), so the installed state is
// never a mix of old and new. A byte-identical unit and binary on an already
// enabled and active service is a true no-op. Upgrade is the same call.
func (m Manager) Install(source string, paths Paths, listen, envfile string) error {
	for _, v := range []struct{ val, name string }{
		{listen, "listen"}, {paths.DataDir, "data-dir"},
	} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return err
		}
	}
	if err := validateReadWritePath(paths.DataDir); err != nil {
		return err
	}
	if err := prepareDataDir(paths.DataDir); err != nil {
		return err
	}
	if envfile != "" {
		if err := validateEnvFile(envfile); err != nil {
			return err
		}
	}
	// A repeat install/upgrade must not overwrite a foreign or modified unit,
	// and the exact prior enabled/active states are snapshotted so a failed
	// operation restores the previous systemd lifecycle state precisely.
	oldUnit, hasUnit := readFileIfPresent(paths.Unit)
	priorEnabledWord, priorActiveWord := "", ""
	if hasUnit {
		if _, err := readManagedUnit(paths.Unit); err != nil {
			return fmt.Errorf("refusing to overwrite the existing unit: %w", err)
		}
		var err error
		if priorEnabledWord, err = m.rawState(paths, "is-enabled"); err != nil {
			return err
		}
		if !restorableEnabledWord(priorEnabledWord) {
			return fmt.Errorf("refusing to reinstall the service: prior enablement state %q cannot be restored exactly; disable or unmask it first", priorEnabledWord)
		}
		if priorActiveWord, err = m.rawState(paths, "is-active"); err != nil {
			return err
		}
		if !restorableActiveWord(priorActiveWord) {
			return fmt.Errorf("refusing to reinstall the service: prior active state %q cannot be restored exactly; stop or restart it first", priorActiveWord)
		}
	}
	oldBinary, hasBinary := readFileIfPresent(paths.Binary)
	// Stage the replacement binary before any published change.
	stagedBin, err := stageCopy(source, paths.Binary, 0755)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(stagedBin) }()
	stagedBytes, err := os.ReadFile(stagedBin)
	if err != nil {
		return err
	}
	unit := Unit(paths, listen, envfile)
	unitChanged := !hasUnit || string(oldUnit) != unit
	binaryChanged := !hasBinary || !bytes.Equal(oldBinary, stagedBytes)
	if !unitChanged && !binaryChanged {
		// True no-op: byte-identical unit and binary already enabled and active.
		if priorEnabledWord == "enabled" && priorActiveWord == "active" {
			return nil
		}
		// Unchanged artifacts: only perform the lifecycle work required to
		// reach the documented installed state (enabled and active).
		steps := [][]string{}
		if priorEnabledWord != "enabled" {
			steps = append(steps, []string{"enable", "watchpost-agent.service"})
		}
		if priorActiveWord != "active" {
			steps = append(steps, []string{"start", "watchpost-agent.service"})
		}
		for _, args := range steps {
			if err := m.systemctlSuccess(paths, args...); err != nil {
				if rb := m.rollbackInstall(paths, oldUnit, oldBinary, hasUnit, hasBinary, priorEnabledWord, priorActiveWord); rb != "" {
					return fmt.Errorf("bringing the service to the installed state: %w%s", err, rb)
				}
				return fmt.Errorf("bringing the service to the installed state: %w", err)
			}
		}
		return nil
	}
	// Publish the unit, then the binary.
	if err := writeManagedUnit(paths.Unit, unit); err != nil {
		return err
	}
	if err := os.Rename(stagedBin, paths.Binary); err != nil {
		if rb := m.rollbackInstall(paths, oldUnit, oldBinary, hasUnit, hasBinary, priorEnabledWord, priorActiveWord); rb != "" {
			return fmt.Errorf("cannot publish the binary: %w%s", err, rb)
		}
		return fmt.Errorf("cannot publish the binary: %w", err)
	}
	for _, step := range []struct {
		verb string
		args []string
	}{
		{"reload", []string{"daemon-reload"}},
		{"enable", []string{"enable", "watchpost-agent.service"}},
		{"restart", []string{"restart", "watchpost-agent.service"}},
	} {
		if err := m.systemctlSuccess(paths, step.args...); err != nil {
			if rb := m.rollbackInstall(paths, oldUnit, oldBinary, hasUnit, hasBinary, priorEnabledWord, priorActiveWord); rb != "" {
				return fmt.Errorf("%s failed: %w%s", step.verb, err, rb)
			}
			return fmt.Errorf("%s failed: %w", step.verb, err)
		}
	}
	return nil
}

// Upgrade reinstalls the current binary, preserving installed configuration.
func (m Manager) Upgrade(source string, paths Paths, listen, envfile string) error {
	return m.Install(source, paths, listen, envfile)
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
	if verb == "start" || verb == "restart" {
		if err := m.revalidateEnv(paths); err != nil {
			return fmt.Errorf("refusing to %s the service: %w", verb, err)
		}
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

// revalidateEnv checks the currently recorded environment file again so a file
// deleted or made unsafe since install cannot silently change the service's
// configuration. Stop, logs and uninstall intentionally skip this so operators
// are never trapped with an unmanageable service.
func (m Manager) revalidateEnv(paths Paths) error {
	meta, err := readManagedUnit(paths.Unit)
	if err != nil {
		return err
	}
	if meta.envfile == "" {
		return nil
	}
	if err := validateEnvFile(meta.envfile); err != nil {
		return fmt.Errorf("the recorded environment file is no longer valid: %w", err)
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
	if err := m.revalidateEnv(paths); err != nil {
		return fmt.Errorf("cannot report status: %w", err)
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
	if meta.envfile != "" {
		fmt.Fprintf(out, "env:     %s\n", meta.envfile)
	}
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
