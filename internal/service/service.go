// Package service implements the machine-service lifecycle for the Watchpost
// Agent: a systemd system unit backed by a dedicated unprivileged account, a
// canonical /var/lib/watchpost-agent data directory and root-protected
// /etc/watchpost-agent configuration. The CLI surface, exit-code model and
// transaction semantics mirror the canonical Web Fleet reference so the whole
// ecosystem behaves predictably.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// unitMarker marks unit files written by `watchpost-agent service`.
const unitMarker = "# Managed by watchpost-agent. Do not edit manually."

// managedPrefix introduces the versioned integrity header followed by a SHA-256
// of everything below it, so any hand edit is detected.
const managedPrefix = "# watchpost-agent-managed: "

// healthPath is the public, read-only liveness endpoint.
const healthPath = "/healthz"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// Paths holds the resolved installation paths for the machine service.
type Paths struct {
	Binary  string
	DataDir string
	Unit    string
	System  bool
}

// DefaultDataDir is the canonical data directory the installed service owns.
const DefaultDataDir = "/var/lib/watchpost-agent"

// DefaultPaths returns the canonical machine-service paths.
func DefaultPaths() Paths {
	return Paths{
		Binary:  "/usr/local/bin/watchpost-agent",
		DataDir: DefaultDataDir,
		Unit:    "/etc/systemd/system/watchpost-agent.service",
		System:  true,
	}
}

// Resolve returns the canonical machine-service paths. System-wide mode is the
// default and the only supported mode: the agent is a machine service running
// under a dedicated unprivileged account. The system flag is accepted for
// compatibility with callers that pass it explicitly.
func Resolve(system bool) (Paths, error) {
	if runtime.GOOS != "linux" {
		return Paths{}, errors.New("service installation currently requires Linux systemd")
	}
	return DefaultPaths(), nil
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

// unitStateWord runs a state verb (is-enabled/is-active), tolerating a nonzero
// exit for legitimate negative answers and returning the trimmed word.
func (m Manager) unitStateWord(paths Paths, verb string) (string, error) {
	out, _, err := m.systemctl(paths, verb, "watchpost-agent.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	return strings.TrimSpace(out), nil
}

// validateEnvFile validates an EnvironmentFile path for the service unit:
// absolute, a regular non-symlink file with exactly owner-only 0600
// permissions, owned by root (uid 0). Secret values are never read or embedded.
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
	if fileUID(info) != 0 {
		return fmt.Errorf("environment file %q must be owned by root (uid 0); machine configuration is root-owned", path)
	}
	return nil
}

// dataDirStatus classifies the outcome of the non-mutating data-path
// inspection so the installer can defer every filesystem mutation until after
// all preflight succeeds.
type dataDirStatus int

const (
	// dataDirAcceptFresh means the final leaf is missing but its parent already
	// exists and was safely opened; the leaf may be created during the mutation
	// phase, relative to the retained parent descriptor.
	dataDirAcceptFresh dataDirStatus = iota
	// dataDirAcceptExisting means the leaf already exists and is a safe,
	// service-owned directory.
	dataDirAcceptExisting
)

// dataLeafInfo carries the leaf stat fields the installer needs, kept
// cross-platform so the descriptor-relative primitives can be declared and
// stubbed on every build target.
type dataLeafInfo struct {
	isDir     bool
	isSymlink bool
	mode      os.FileMode
	uid       int
}

// dataDirPlan is the result of the non-mutating inspection. It retains the
// validated parent directory descriptor AND, for an existing leaf, the retained
// leaf descriptor, so the mutation phase is bound to the exact objects
// inspected, never re-walked by pathname.
type dataDirPlan struct {
	status   dataDirStatus
	parentFd int
	leafFd   int // retained leaf descriptor for an existing leaf; -1 for a fresh leaf
	leafName string
	path     string
}

// close releases the retained descriptors exactly once (idempotent).
func (p *dataDirPlan) close() {
	if p.parentFd >= 0 {
		closeFdSeam(p.parentFd)
		p.parentFd = -1
	}
	if p.leafFd >= 0 {
		closeFdSeam(p.leafFd)
		p.leafFd = -1
	}
}

// inspectDataDir and establishDataDir are implemented on Linux using a
// descriptor-relative, no-symlink walk of the parent chain (see datadir_linux.go)
// so the validated parent is the exact directory mutated; non-Linux stubs fail
// (Install is Linux-gated).

// validateReadWritePath validates a data directory for ReadWritePaths=.
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

// ServiceAccount are the dedicated unprivileged account constants.
const ServiceUser = "watchpost-agent"
const ServiceGroup = "watchpost-agent"

// DefaultListen is the canonical loopback listen address embedded in the unit.
const DefaultListen = "127.0.0.1:7335"

// Options describes the listener and unit settings recorded by service install.
// Legacy bootstrap units set Listen (single address, recorded as --listen);
// explicit host/port units set Host and Port (recorded as canonical --host and
// --port in ExecStart).
type Options struct {
	Host    string
	Port    string
	Listen  string
	EnvFile string
}

// listenMode is the unit metadata marker distinguishing an explicit host/port
// unit from a legacy bootstrap unit.
const (
	listenModeExplicit  = "explicit"
	listenModeBootstrap = "bootstrap"
)

// listener returns the canonical listen address recorded in the unit metadata:
// the legacy single address when set, otherwise the trimmed host/port pair
// joined safely (so IPv6 hosts are bracketed). Values are canonicalized before
// being written so surrounding whitespace can never leak into the unit.
func (o Options) listener() string {
	if o.Listen != "" {
		return o.Listen
	}
	return net.JoinHostPort(strings.TrimSpace(o.Host), strings.TrimSpace(o.Port))
}

// mode reports the unit listen mode recorded in the metadata marker: explicit
// host/port units versus legacy bootstrap units.
func (o Options) mode() string {
	if o.Listen != "" {
		return listenModeBootstrap
	}
	return listenModeExplicit
}

// DefaultEnvFile is the root-protected environment file for protected
// WATCHPOST_AGENT_* configuration.
const DefaultEnvFile = "/etc/watchpost-agent/watchpost-agent.env"

// renderUnitBody renders the systemd directives (no managed header). Explicit
// host/port units record canonical --host/--port so their recorded listener is
// the runtime listener; legacy bootstrap units keep the single-address --listen
// form.
func renderUnitBody(paths Paths, opts Options) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Watchpost Agent\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("ExecStart=" + systemdQuote(paths.Binary))
	if opts.Listen != "" {
		b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(opts.Listen))
	} else {
		b.WriteString(" " + systemdQuote("--host") + " " + systemdQuote(strings.TrimSpace(opts.Host)))
		b.WriteString(" " + systemdQuote("--port") + " " + systemdQuote(strings.TrimSpace(opts.Port)))
	}
	b.WriteString(" " + systemdQuote("--data-dir") + " " + systemdQuote(paths.DataDir))
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=5s\n")
	b.WriteString("UMask=0077\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(paths.DataDir) + "\n")
	b.WriteString("Environment=HOME=%h\n")
	if opts.EnvFile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(opts.EnvFile) + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// buildUnit renders the full managed unit: a marker line, a versioned integrity
// header carrying the SHA-256 of the managed content below it, the runtime
// metadata (listen/listen-mode/health/envfile) used by status, and the body.
func buildUnit(paths Paths, opts Options) string {
	meta := "# watchpost-agent-listen: " + opts.listener() + "\n"
	meta += "# watchpost-agent-listen-mode: " + opts.mode() + "\n"
	if opts.EnvFile != "" {
		meta += "# watchpost-agent-envfile: " + opts.EnvFile + "\n"
	}
	meta += "# watchpost-agent-health: " + healthPath + "\n"
	content := meta + renderUnitBody(paths, opts)
	sum := sha256.Sum256([]byte(content))
	header := unitMarker + "\n" + managedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

// Unit renders the full managed unit for a legacy bootstrap listen address
// (exported for tests and legacy compatibility).
func Unit(paths Paths, listen, envfile string) string {
	return buildUnit(paths, Options{Listen: listen, EnvFile: envfile})
}

// UnitOptions renders the full managed unit for explicit host/port options
// (exported for tests).
func UnitOptions(paths Paths, opts Options) string {
	return buildUnit(paths, opts)
}

type unitMeta struct {
	listen     string
	listenMode string
	envfile    string
	health     string
}

// Meta is the exported view of a managed unit's integrity-checked metadata.
type Meta struct {
	Listen     string
	ListenMode string
	EnvFile    string
}

// ExistingMeta returns the installed managed unit's integrity-checked metadata, or
// ok=false when no unit is installed. A foreign or modified unit is an error so
// install/upgrade never silently diverge from it.
func (m Manager) ExistingMeta(paths Paths) (Meta, bool, error) {
	meta, err := readManagedUnitFile(paths.Unit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Meta{}, false, nil
		}
		return Meta{}, false, fmt.Errorf("existing unit at %s is not valid: %w", paths.Unit, err)
	}
	return Meta{Listen: meta.listen, ListenMode: meta.listenMode, EnvFile: meta.envfile}, true, nil
}

// OptionsFromMeta reconstructs the recorded options from an existing managed
// unit's metadata, preserving the recorded listener in its recorded form
// (explicit host/port vs legacy --listen) so a bare reinstall or upgrade never
// silently changes the runtime listener. envfile overrides the recorded value.
func OptionsFromMeta(meta Meta, envfile string) Options {
	if meta.ListenMode == listenModeExplicit {
		if host, port, err := net.SplitHostPort(meta.Listen); err == nil {
			return Options{Host: host, Port: port, EnvFile: envfile}
		}
	}
	return Options{Listen: meta.Listen, EnvFile: envfile}
}

// readManagedUnitFile reads a unit file path and parses its managed content.
func readManagedUnitFile(path string) (unitMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unitMeta{}, err
	}
	return readManagedUnit(string(data))
}

func readManagedUnit(content string) (unitMeta, error) {
	lines := strings.Split(content, "\n")
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
	body := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(body))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	meta := unitMeta{listenMode: listenModeBootstrap}
	listenSeen, envfileSeen, healthSeen, modeSeen := 0, 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# watchpost-agent-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-listen: "))
		case strings.HasPrefix(ln, "# watchpost-agent-listen-mode: "):
			modeSeen++
			if modeSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listenMode = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-agent-listen-mode: "))
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
	// Old units predating the mode marker default to bootstrap: their recorded
	// listener remains a bootstrap/durable value, matching legacy behaviour.
	if meta.listenMode != listenModeExplicit && meta.listenMode != listenModeBootstrap {
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

// validateManagedUnit performs the structural ownership/integrity check: the
// unit must carry the agent managed header AND the required directives, so a
// stale or malformed managed unit is classified rather than treated healthy.
func validateManagedUnit(body []byte) error {
	if _, err := readManagedUnit(string(body)); err != nil {
		return err
	}
	t := string(body)
	for _, want := range []string{"[Unit]", "[Service]", "[Install]", "Description=Watchpost Agent", "ExecStart=", "User=" + ServiceUser, "WantedBy=multi-user.target"} {
		if !strings.Contains(t, want) {
			return fmt.Errorf("malformed managed unit: missing %q", want)
		}
	}
	return nil
}

func (m Manager) requireManaged(paths Paths, verb string) error {
	b, e := os.ReadFile(paths.Unit)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("refusing to %s the service: unit is not installed (run `watchpost-agent service install`)", verb)
	}
	if e != nil {
		return fmt.Errorf("refusing to %s the service: %w", verb, e)
	}
	if ve := validateManagedUnit(b); ve != nil {
		return fmt.Errorf("refusing to %s the service: %v", verb, ve)
	}
	return nil
}

func writeManagedUnit(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		if _, err := readManagedUnitFile(path); err != nil {
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

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-agent-write-*")
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

func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp := dst + ".new"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, dst)
}

func fileSHA256(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

func ensureServiceAccount() error {
	if out, e := exec.Command("groupadd", "--system", ServiceGroup).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("groupadd: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, e := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", ServiceGroup, ServiceUser).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("useradd: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

// ensureAccount is a test seam for service-account creation.
var ensureAccount = func() error { return ensureServiceAccount() }

// Install publishes a new unit and binary as a failure-atomic transaction with
// legacy single-address listen options (bootstrap mode). It is retained for
// compatibility; InstallOptions is the canonical entry point.
func (m Manager) Install(source string, paths Paths, listen, envfile string) (retErr error) {
	return m.InstallOptions(source, paths, Options{Listen: listen, EnvFile: envfile})
}

// InstallOptions publishes a new unit and binary as a failure-atomic
// transaction. Explicit host/port units record canonical --host/--port so their
// recorded listener is the runtime listener; legacy bootstrap units record the
// single-address --listen form. A partial failure restores the prior unit,
// enablement, active state and binary, and the returned error combines the
// original failure with any rollback failure.
func (m Manager) InstallOptions(source string, paths Paths, o Options) (retErr error) {
	if o.Listen == "" && o.Host == "" && o.Port == "" {
		o.Listen = DefaultListen
	}
	// Non-mutating preflight runs first so a foreign/tampered unit, unsupported
	// state, state-query failure, invalid executable, invalid environment file
	// or unacceptable data directory is rejected with zero account, mkdir,
	// chmod, chown, binary, unit or lifecycle mutation.
	for _, v := range []struct{ val, name string }{
		{o.listener(), "listen"}, {paths.DataDir, "data-dir"},
	} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return err
		}
	}
	if err := validateReadWritePath(paths.DataDir); err != nil {
		return err
	}
	if err := validateDataDirPath(paths.DataDir); err != nil {
		return err
	}
	if o.EnvFile != "" {
		if err := validateEnvFile(o.EnvFile); err != nil {
			return err
		}
	}
	if _, e := exec.LookPath("systemctl"); e != nil {
		return errors.New("systemctl not found; is systemd installed?")
	}
	// Read and authenticate the existing managed unit (non-mutating).
	unit := buildUnit(paths, o)
	oldUnit, hasUnit := readFileIfPresent(paths.Unit)
	priorEnabled, priorActive := "", ""
	if hasUnit {
		if _, err := readManagedUnitFile(paths.Unit); err != nil {
			return fmt.Errorf("refusing to overwrite the existing unit: %w", err)
		}
		var err error
		if priorEnabled, err = m.unitStateWord(paths, "is-enabled"); err != nil {
			return fmt.Errorf("refusing to reinstall the service: %w", err)
		}
		if !restorableEnabledWord(priorEnabled) {
			return fmt.Errorf("refusing to reinstall the service: prior enablement state %q cannot be restored exactly; disable or unmask it first", priorEnabled)
		}
		if priorActive, err = m.unitStateWord(paths, "is-active"); err != nil {
			return fmt.Errorf("refusing to reinstall the service: %w", err)
		}
		if !restorableActiveWord(priorActive) {
			return fmt.Errorf("refusing to reinstall the service: prior active state %q cannot be restored exactly; stop or restart it first", priorActive)
		}
		if !restorablePriorState(priorEnabled, priorActive) {
			return fmt.Errorf("refusing to reinstall the service: prior state %s+%s cannot be restored exactly; unmask it first", priorEnabled, priorActive)
		}
	}
	// Inspect the incoming and installed executables (non-mutating).
	incomingDigest, err := fileSHA256(source)
	if err != nil {
		return fmt.Errorf("read incoming executable: %w", err)
	}
	hasBinary := false
	priorDigest := ""
	if _, e := os.Stat(paths.Binary); e == nil {
		hasBinary = true
		priorDigest, _ = fileSHA256(paths.Binary)
	}
	binaryChanged := !hasBinary || incomingDigest != priorDigest
	unitChanged := !hasUnit || string(oldUnit) != unit
	// Non-mutating data-path inspection: classify the requested directory
	// (acceptable fresh leaf with a safe existing parent, or acceptable existing
	// service-owned leaf) or refuse it. This runs before the genuine-no-op
	// return so a reinstall never claims "already correct" while a recorded
	// runtime prerequisite (the data directory) is missing or unsafe, and it
	// runs before any account/data mutation so an unacceptable existing
	// directory cannot trigger account creation first.
	dataPlan, dErr := inspectDataDir(paths.DataDir)
	if dErr != nil {
		return fmt.Errorf("refusing to install the service: %w", dErr)
	}
	defer dataPlan.close()
	// Genuine no-op: the installed unit and executable already match the request
	// AND the recorded data directory already exists as a safe service-owned
	// leaf, so the service is already running the requested version in its prior
	// state; nothing is rewritten, reloaded, enabled or started.
	if hasUnit && string(oldUnit) == unit && !binaryChanged && dataPlan.status == dataDirAcceptExisting {
		return nil
	}
	// ---- Mutation phase begins here ----
	if e := ensureAccount(); e != nil {
		return e
	}
	if e := establishDataDir(&dataPlan); e != nil {
		return e
	}
	// Repair-only: the unit and binary already match the request, so the only
	// reason the no-op check did not return early was a missing data leaf, which
	// has just been recreated. No systemd state change is needed.
	if hasUnit && string(oldUnit) == unit && !binaryChanged {
		return nil
	}
	if hasBinary {
		if e := copyFile(paths.Binary, paths.Binary+".preinstall", 0o755); e != nil {
			return e
		}
	}
	installOK := false
	restore := func() string {
		var errs []string
		if e := m.systemctlSuccess(paths, "stop", "watchpost-agent.service"); e != nil {
			errs = append(errs, fmt.Sprintf("neutralize stop: %v", e))
		}
		if e := m.systemctlSuccess(paths, "disable", "watchpost-agent.service"); e != nil {
			errs = append(errs, fmt.Sprintf("neutralize disable: %v", e))
		}
		if hasBinary {
			if e := copyFile(paths.Binary+".preinstall", paths.Binary, 0o755); e != nil {
				errs = append(errs, fmt.Sprintf("restore binary: %v", e))
			}
		} else {
			_ = os.Remove(paths.Binary)
		}
		_ = os.Remove(paths.Binary + ".preinstall")
		if hasUnit {
			if e := writeFileAtomic(paths.Unit, oldUnit, 0644); e != nil {
				errs = append(errs, fmt.Sprintf("restore unit: %v", e))
			}
		} else {
			_ = os.Remove(paths.Unit)
		}
		if e := m.systemctlSuccess(paths, "daemon-reload"); e != nil {
			errs = append(errs, fmt.Sprintf("reload systemd: %v", e))
		}
		if hasUnit {
			for _, args := range enableRestoreSteps(priorEnabled, "watchpost-agent.service") {
				if e := m.systemctlSuccess(paths, args...); e != nil {
					errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabled, e))
					break
				}
			}
			if e := m.systemctlSuccess(paths, activeRestoreArgs(priorActive, "watchpost-agent.service")...); e != nil {
				errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActive, e))
			}
		}
		if len(errs) == 0 {
			return ""
		}
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	defer func() {
		if !installOK && retErr != nil {
			if rb := restore(); rb != "" {
				retErr = fmt.Errorf("%v%s", retErr, rb)
			}
		}
	}()
	if e := writeManagedUnit(paths.Unit, unit); e != nil {
		return e
	}
	if e := copyFile(source, paths.Binary, 0o755); e != nil {
		return e
	}
	// Forward path: a fresh install establishes the machine-service default
	// (enabled + active). An EXISTING managed installation (changed OR
	// unchanged) must preserve its exact prior enablement and activity states
	// through the same canonical restoration helpers used by failed-install
	// rollback.
	steps := [][]string{}
	if unitChanged {
		steps = append(steps, []string{"daemon-reload"})
	}
	if !hasUnit {
		steps = append(steps, []string{"enable", "watchpost-agent.service"}, []string{"restart", "watchpost-agent.service"})
	} else {
		steps = append(steps, enableRestoreSteps(priorEnabled, "watchpost-agent.service")...)
		steps = append(steps, activeRestoreArgs(priorActive, "watchpost-agent.service"))
	}
	for _, a := range steps {
		if err := m.systemctlSuccess(paths, a...); err != nil {
			retErr = fmt.Errorf("systemctl %s: %w (installation rolled back)", strings.Join(a, " "), err)
			return retErr
		}
	}
	installOK = true
	_ = os.Remove(paths.Binary + ".preinstall")
	return nil
}

// Upgrade reinstalls the current binary, preserving installed configuration.
func (m Manager) Upgrade(source string, paths Paths, listen, envfile string) error {
	return m.Install(source, paths, listen, envfile)
}

func (m Manager) Start(paths Paths) error { return m.lifecycle(paths, "start") }
func (m Manager) Stop(paths Paths) error  { return m.lifecycle(paths, "stop") }
func (m Manager) Restart(paths Paths) error {
	return m.lifecycle(paths, "restart")
}
func (m Manager) Enable(paths Paths) error  { return m.lifecycle(paths, "enable") }
func (m Manager) Disable(paths Paths) error { return m.lifecycle(paths, "disable") }

func (m Manager) lifecycle(paths Paths, verb string) error {
	if err := m.requireManaged(paths, verb); err != nil {
		return err
	}
	if err := m.systemctlSuccess(paths, verb, "watchpost-agent.service"); err != nil {
		return err
	}
	return nil
}

// revalidateEnv checks the currently recorded environment file again so a file
// deleted or made unsafe since install cannot silently change the service's
// configuration. Stop, logs and uninstall intentionally skip this so operators
// are never trapped with an unmanageable service.
func (m Manager) revalidateEnv(paths Paths) error {
	meta, err := readManagedUnitFile(paths.Unit)
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
	meta, err := readManagedUnitFile(paths.Unit)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("the service is not installed (no unit at %s)", paths.Unit)
		}
		return fmt.Errorf("the service unit is not valid: %w", err)
	}
	enabled, err := m.unitStateWord(paths, "is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine enablement state: %w", err)
	}
	if err := m.revalidateEnv(paths); err != nil {
		return fmt.Errorf("cannot report status: %w", err)
	}
	active, err := m.unitStateWord(paths, "is-active")
	if err != nil {
		return fmt.Errorf("cannot determine service state: %w", err)
	}
	pid, _, _ := m.systemctl(paths, "show", "-p", "MainPID", "--value", "watchpost-agent.service")
	fmt.Fprintf(out, "unit:    watchpost-agent.service\n")
	fmt.Fprintf(out, "file:    %s\n", paths.Unit)
	fmt.Fprintf(out, "enabled: %s\n", enabled)
	fmt.Fprintf(out, "active:  %s\n", active)
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "user:    %s\n", ServiceUser)
	fmt.Fprintf(out, "version: %s\n", version)
	// The actual runtime listener: explicit host/port units record an
	// authoritative --host/--port listener in ExecStart; legacy bootstrap units
	// record the durable --listen address that governs the runtime service. In
	// both modes the recorded listener is what the process binds, so the
	// metadata value is the effective runtime listener.
	fmt.Fprintf(out, "listen:  %s\n", meta.listen)
	fmt.Fprintf(out, "data:    %s\n", paths.DataDir)
	if meta.envfile != "" {
		fmt.Fprintf(out, "env:     %s\n", meta.envfile)
	}
	if active != "active" {
		return fmt.Errorf("service is %q; expected active", active)
	}
	if err := healthCheck("http://" + meta.listen + meta.health); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

var healthCheck = healthCheckReal

func healthCheckReal(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("expected 2xx, got HTTP %d", resp.StatusCode)
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

func (m Manager) Logs(follow bool, out io.Writer, paths Paths) error {
	if err := m.requireManaged(paths, "view logs for"); err != nil {
		return err
	}
	args := []string{"--unit", "watchpost-agent.service"}
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

// Uninstall stops and disables the service, removes the unit and reloads
// systemd. The data directory and installed binary are deliberately preserved.
func (m Manager) Uninstall(out io.Writer, paths Paths) error {
	if err := m.requireManaged(paths, "uninstall"); err != nil {
		return err
	}
	if e := m.systemctlSuccess(paths, "disable", "--now", "watchpost-agent.service"); e != nil {
		return fmt.Errorf("uninstall: %w", e)
	}
	if e := os.Remove(paths.Unit); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	if e := m.systemctlSuccess(paths, "daemon-reload"); e != nil {
		return e
	}
	fmt.Fprintf(out, "Removed the Watchpost Agent service. Agent data in %s and the binary were preserved.\n", paths.DataDir)
	return nil
}

// readPriorActiveMarker reads and validates the prior-state marker.
func (m Manager) readPriorActiveMarker(paths Paths) (string, error) {
	b, err := os.ReadFile(paths.Binary + ".prior-active")
	if err != nil {
		return "", err
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return "", fmt.Errorf("invalid prior-state marker %q", priorActive)
	}
	return priorActive, nil
}

// Update replaces the binary with a checksum-verified artifact, preserving the
// prior running/stopped state and enablement, and retaining rollback metadata.
func (m Manager) Update(artifact, want string, paths Paths) error {
	if err := m.requireManaged(paths, "update"); err != nil {
		return err
	}
	if err := Verify(artifact, want); err != nil {
		return err
	}
	priorActive, err := m.unitStateWord(paths, "is-active")
	if err != nil {
		return fmt.Errorf("update: cannot determine current service state: %w", err)
	}
	priorActive = strings.TrimSpace(priorActive)
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("update: unexpected service state %q; refusing to update", priorActive)
	}
	wasActive := priorActive == "active"
	if _, e := os.Stat(paths.Binary); e == nil {
		if e := copyFile(paths.Binary, paths.Binary+".rollback", 0o755); e != nil {
			return e
		}
		if e := writeFileAtomic(paths.Binary+".prior-active", []byte(priorActive), 0o600); e != nil {
			_ = os.Remove(paths.Binary + ".rollback")
			return fmt.Errorf("update: cannot record rollback state: %w", e)
		}
	}
	if e := copyFile(artifact, paths.Binary, 0o755); e != nil {
		return e
	}
	if !wasActive {
		return nil
	}
	if out, code, err := m.systemctl(paths, "restart", "watchpost-agent.service"); err != nil || code != 0 {
		updateErr := fmt.Errorf("restart after update: %s: %w", bounded(strings.TrimSpace(out)), errOrCode(err, code))
		return updateFailureWithRecovery(updateErr, m.restoreAfterFailedUpdate(paths))
	}
	if e := m.verifyActiveAndHealthy(paths); e != nil {
		updateErr := fmt.Errorf("update: new binary failed to become healthy: %w", e)
		return updateFailureWithRecovery(updateErr, m.restoreAfterFailedUpdate(paths))
	}
	return nil
}

func errOrCode(err error, code int) error {
	if err != nil {
		return err
	}
	return fmt.Errorf("exited %d", code)
}

func updateFailureWithRecovery(updateErr, recoveryErr error) error {
	if recoveryErr != nil {
		return fmt.Errorf("%v; recovery also failed: %v", updateErr, recoveryErr)
	}
	return updateErr
}

func (m Manager) verifyActiveAndHealthy(paths Paths) error {
	listen := DefaultListen
	if meta, err := readManagedUnitFile(paths.Unit); err == nil && meta.listen != "" {
		listen = meta.listen
	}
	deadline := time.Now().Add(healthWindow())
	for time.Now().Before(deadline) {
		active, _ := m.unitStateWord(paths, "is-active")
		if strings.TrimSpace(active) == "active" {
			if err := healthCheck("http://" + listen + healthPath); err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active and healthy within the health window")
}

var healthWindow = func() time.Duration { return 30 * time.Second }

// restoreAfterFailedUpdate verifiably restores the previous version and its
// operational state after a failed update. It fails closed if the prior-state
// marker is missing or invalid at recovery time.
func (m Manager) restoreAfterFailedUpdate(paths Paths) error {
	b, err := priorStateFileRead(paths.Binary + ".prior-active")
	if err != nil {
		return fmt.Errorf("recovery: no prior-state marker: %w", err)
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("recovery: invalid prior-state marker %q", priorActive)
	}
	if e := m.systemctlSuccess(paths, "stop", "watchpost-agent.service"); e != nil {
		return fmt.Errorf("recovery: stop failed service: %w", e)
	}
	if e := copyFile(paths.Binary+".rollback", paths.Binary, 0o755); e != nil {
		return fmt.Errorf("recovery: restore old binary: %w", e)
	}
	if priorActive == "active" {
		if e := m.systemctlSuccess(paths, "restart", "watchpost-agent.service"); e != nil {
			return fmt.Errorf("recovery: restart old service: %w", e)
		}
		if e := m.verifyActiveAndHealthy(paths); e != nil {
			return fmt.Errorf("recovery: restored service not healthy: %w", e)
		}
	}
	_ = os.Remove(paths.Binary + ".prior-active")
	_ = os.Remove(paths.Binary + ".rollback")
	return nil
}

// Rollback restores the previous version and its operational state.
func (m Manager) Rollback(paths Paths) error {
	if err := m.requireManaged(paths, "rollback"); err != nil {
		return err
	}
	if _, e := os.Stat(paths.Binary + ".rollback"); e != nil {
		return errors.New("no rollback binary available")
	}
	b, err := priorStateFileRead(paths.Binary + ".prior-active")
	if err != nil {
		return fmt.Errorf("rollback: no prior-state marker; refusing to guess the service state")
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("rollback: invalid prior-state marker %q", priorActive)
	}
	wasActive := priorActive == "active"
	cur := paths.Binary + ".failed"
	_ = os.Remove(cur)
	if e := os.Rename(paths.Binary, cur); e != nil {
		return e
	}
	if e := os.Rename(paths.Binary+".rollback", paths.Binary); e != nil {
		_ = os.Rename(cur, paths.Binary)
		return e
	}
	if !wasActive {
		_ = os.Remove(paths.Binary + ".prior-active")
		_ = os.Remove(paths.Binary + ".rollback")
		return nil
	}
	if e := m.systemctlSuccess(paths, "restart", "watchpost-agent.service"); e != nil {
		return e
	}
	if e := m.verifyActiveAndHealthy(paths); e != nil {
		return e
	}
	_ = os.Remove(paths.Binary + ".prior-active")
	_ = os.Remove(paths.Binary + ".rollback")
	return nil
}

// priorStateFileRead is a narrow injectable seam so tests can corrupt the
// marker at the exact recovery-time stage (after Update has written it).
var priorStateFileRead = os.ReadFile

// Verify returns nil when the artifact's SHA-256 matches want.
func Verify(path, want string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	got := hex.EncodeToString(h[:])
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("checksum mismatch: got %s", got)
	}
	return nil
}

func readFileIfPresent(path string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

// restorableEnabledWord reports whether a prior is-enabled word can be
// recreated exactly by the rollback enablement sequence. Persistent enablement
// (enabled), runtime-only enablement (enabled-runtime) and their absence
// (disabled) are restorable. Masked/static/linked/generated/transient and other
// unit-file states are refused before mutation because enable/disable cannot
// reproduce them.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "disabled":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active word can be recreated
// exactly by the rollback activation sequence. Running and stopped are
// restorable; transient, failed, reloading and unknown states are not.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive":
		return true
	}
	return false
}

// restorablePriorState reports whether the enablement/active pair can be
// reproduced exactly. Only the states restorableEnabledWord and
// restorableActiveWord accept are combined here; this guard exists so any
// future widening of the accept sets must also prove the pair is restorable.
func restorablePriorState(enabledWord, activeWord string) bool {
	return restorableEnabledWord(enabledWord) && restorableActiveWord(activeWord)
}

// enableRestoreSteps returns the systemctl calls that reproduce a prior
// is-enabled word exactly. Enablement is normalized first: the persistent
// enablement link created by the attempted install is removed with disable,
// then the intended persistent or runtime link is recreated, so a runtime-only
// prior never leaves a persistent enablement behind.
func enableRestoreSteps(word, unit string) [][]string {
	switch word {
	case "enabled":
		return [][]string{{"disable", unit}, {"enable", unit}}
	case "enabled-runtime":
		return [][]string{{"disable", unit}, {"enable", "--runtime", unit}}
	default: // disabled
		return [][]string{{"disable", unit}}
	}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior
// is-active word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

func lookupServiceIDs() (int, int, error) {
	u, e := user.Lookup(ServiceUser)
	if e != nil {
		return 0, 0, fmt.Errorf("service user not found: %w", e)
	}
	uid, _ := strconv.Atoi(u.Uid)
	g, e := user.LookupGroup(ServiceGroup)
	if e != nil {
		return 0, 0, fmt.Errorf("service group not found: %w", e)
	}
	gid, _ := strconv.Atoi(g.Gid)
	return uid, gid, nil
}

// serviceUID returns the numeric UID of the service account. It is a variable
// so tests can simulate the account without a real system user.
var serviceUID = func() (int, error) {
	uid, _, e := lookupServiceIDs()
	return uid, e
}

// topLevelSystemRoots are filesystem roots that can never be a service data
// directory even as a direct target (e.g. `--data /var`).
var topLevelSystemRoots = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
	"/home": true, "/lib": true, "/lib64": true, "/opt": true, "/proc": true,
	"/root": true, "/run": true, "/sbin": true, "/srv": true, "/sys": true,
	"/tmp": true, "/usr": true, "/var": true,
}

// protectedSystemTrees are system trees beneath which arbitrary application
// data does not belong. /var and /srv are intentionally NOT in this set so
// canonical /var/lib/<project> and /srv/<project> locations remain valid.
var protectedSystemTrees = map[string]bool{
	"/bin": true, "/boot": true, "/dev": true, "/etc": true, "/lib": true,
	"/lib64": true, "/proc": true, "/root": true, "/run": true, "/sbin": true,
	"/sys": true, "/usr": true,
}

// validateDataDirPath rejects data-directory paths that are dangerous system
// roots or live beneath protected system trees. It must run before any
// ownership or mode mutation.
func validateDataDirPath(path string) error {
	clean := filepath.Clean(path)
	if topLevelSystemRoots[clean] {
		return fmt.Errorf("data directory %q is a system directory and cannot be adopted as a service data directory", path)
	}
	for p := clean; p != "/"; p = filepath.Dir(p) {
		if protectedSystemTrees[p] {
			return fmt.Errorf("data directory %q lives beneath protected system tree %q and cannot be used as a service data directory", path, p)
		}
	}
	return nil
}
