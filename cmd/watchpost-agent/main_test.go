package main

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/watchpost-ops/watchpost-agent/internal/app"
	"github.com/watchpost-ops/watchpost-agent/internal/service"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

// captureStderr runs f while capturing os.Stderr, returning the captured text
// and f's result.
func captureStderr(t *testing.T, f func() int) (string, int) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	code := f()
	_ = w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

func TestUnitMatchesForegroundConfig(t *testing.T) {
	paths := service.Paths{Binary: "/usr/local/bin/watchpost-agent", DataDir: "/var/lib/watchpost-agent", System: true}
	unit := service.UnitOptions(paths, service.Options{Host: "127.0.0.1", Port: "7335"})
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7335"`, `"--data-dir" "` + paths.DataDir + `"`, "WantedBy=multi-user.target"} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit does not match foreground defaults (%s):\n%s", want, unit)
		}
	}
}

func TestGoDirectiveAllowsToolchainSelection(t *testing.T) {
	// A patch-level `go` directive (go 1.25.0) lets the Go toolchain manager
	// auto-select a matching toolchain, whereas a bare `go 1.25` may attempt to
	// download an unavailable toolchain on older hosts.
	for _, candidate := range []string{"go.mod", "../../go.mod"} {
		data, err := os.ReadFile(candidate)
		if err != nil {
			continue
		}
		re := regexp.MustCompile(`(?m)^go (\d+\.\d+\.\d+)\s*$`)
		if m := re.FindStringSubmatch(string(data)); m != nil {
			return
		}
		t.Fatalf("go directive must be a full patch version (go 1.25.0):\n%s", data)
	}
	t.Fatal("could not locate go.mod")
}

func TestServiceNamespaceDispatch(t *testing.T) {
	// `watchpost-agent service status` reports a missing unit without touching
	// systemd (exit code 1, diagnostic on stderr). The top-level status alias is
	// removed in the clean machine-service break; only the service namespace is
	// canonical.
	for _, args := range [][]string{{"status"}, {"service", "status"}} {
		var code int
		if args[0] == "service" {
			code = runServiceCommand(args[1:])
		} else {
			// `watchpost-agent status` is not a service alias; it is treated as
			// an unexpected argument and exits with a usage error (exit 1 path).
			err := run(args)
			if err == nil {
				t.Fatalf("%v unexpectedly succeeded", args)
			}
			continue
		}
		if code == 0 {
			t.Fatalf("%v unexpectedly succeeded (exit 0)", args)
		}
	}
}

func TestAppOptionsRequireExplicitRemoteExposure(t *testing.T) {
	if _, err := appOptions("127.0.0.1:7335"); err != nil {
		t.Fatalf("loopback binding rejected: %v", err)
	}
	_, err := appOptions("0.0.0.0:7335")
	if err == nil || !strings.Contains(err.Error(), "WATCHPOST_AGENT_EXPOSE") {
		t.Fatalf("non-loopback binding without explicit opt-in: %v", err)
	}
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "1")
	if _, err := appOptions("0.0.0.0:7335"); err != nil {
		t.Fatalf("non-loopback binding with explicit opt-in rejected: %v", err)
	}
}

func TestAppOptionsParseCIDRs(t *testing.T) {
	options, err := appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if len(options.AllowCIDRs) != 0 || len(options.DenyCIDRs) != 0 {
		t.Fatalf("unexpected default CIDRs: %#v", options)
	}
	t.Setenv("WATCHPOST_AGENT_ALLOW_CIDRS", "10.0.0.0/8")
	t.Setenv("WATCHPOST_AGENT_DENY_CIDRS", "not-a-cidr")
	if _, err := appOptions("127.0.0.1:7335"); err == nil {
		t.Fatal("invalid deny CIDR accepted")
	}
	t.Setenv("WATCHPOST_AGENT_DENY_CIDRS", "")
	options, err = appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if len(options.AllowCIDRs) != 1 || options.AllowCIDRs[0].String() != "10.0.0.0/8" {
		t.Fatalf("allow CIDRs not parsed: %#v", options.AllowCIDRs)
	}
}
func TestAppOptionsSetupTokenRequired(t *testing.T) {
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN", "")
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN_FILE", "")
	options, err := appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if options.SetupTokenRequired {
		t.Fatal("loopback setup should not require a token")
	}
	options, err = appOptions("0.0.0.0:7335")
	if err == nil || !strings.Contains(err.Error(), "WATCHPOST_AGENT_EXPOSE") {
		t.Fatalf("non-loopback without expose: %v", err)
	}
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "1")
	options, err = appOptions("0.0.0.0:7335")
	if err != nil {
		t.Fatal(err)
	}
	if !options.SetupTokenRequired {
		t.Fatal("remote exposure must require a setup token")
	}
	// An operator-supplied token requires it even on loopback.
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "")
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN", "operator-supplied-token")
	options, err = appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if !options.SetupTokenRequired {
		t.Fatal("operator-supplied token must require setup token")
	}
}

func TestAppOptionsDocumentedProxyConfigRequiresToken(t *testing.T) {
	// The documented loopback-behind-proxy deployment keeps the listener on
	// loopback and supplies a protected setup-token file; the token gate must
	// be active even though WATCHPOST_AGENT_EXPOSE is not set (EXPOSE only
	// permits a non-loopback bind and does not enable the gate on loopback).
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "")
	t.Setenv("WATCHPOST_AGENT_SECURE_COOKIES", "1")
	t.Setenv("WATCHPOST_AGENT_TRUSTED_PROXIES", "127.0.0.0/8")
	t.Setenv("WATCHPOST_AGENT_ALLOW_CIDRS", "192.0.2.0/24")
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN", "")
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN_FILE", "/run/watchpost-agent/setup-token")
	options, err := appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if !options.SetupTokenRequired {
		t.Fatal("documented loopback-behind-proxy config must require a setup token")
	}
	if !options.SecureCookies || len(options.TrustedProxies) != 1 || len(options.AllowCIDRs) != 1 {
		t.Fatalf("documented security options not applied: %#v", options)
	}
}

func TestProvisionSetupTokenStoresOnlyHash(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN", "operator-token-value")
	if err := provisionSetupToken(store, app.Options{SetupTokenRequired: true}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if snapshot.LocalAuth.Bootstrap.Hash == "operator-token-value" || snapshot.LocalAuth.Bootstrap.Hash == "" {
		t.Fatal("raw token persisted instead of a hash")
	}
	if snapshot.LocalAuth.Bootstrap.ExpiresAt.IsZero() {
		t.Fatal("bootstrap token expiry missing")
	}
}

func TestAppOptionsParseTrustedProxies(t *testing.T) {
	t.Setenv("WATCHPOST_AGENT_TRUSTED_PROXIES", "127.0.0.0/8,10.0.0.5,::1")
	options, err := appOptions("127.0.0.1:7335")
	if err != nil {
		t.Fatal(err)
	}
	if len(options.TrustedProxies) != 3 {
		t.Fatalf("trusted proxies=%d want 3", len(options.TrustedProxies))
	}
	if !options.TrustedProxies[1].Contains(net.ParseIP("10.0.0.5")) || options.TrustedProxies[1].Contains(net.ParseIP("10.0.0.6")) {
		t.Fatalf("bare IPv4 trusted proxy not treated as an exact host: %v", options.TrustedProxies[1])
	}
	t.Setenv("WATCHPOST_AGENT_TRUSTED_PROXIES", "not-a-cidr")
	if _, err := appOptions("127.0.0.1:7335"); err == nil {
		t.Fatal("invalid trusted proxy accepted")
	}
}

// TestRunServiceInstallUsageErrors proves the service install/upgrade path
// validates the explicit host/port listener before any operational work and
// reports malformed selections as usage errors (exit 2). These cases also
// exercise the value-flag parser, so the flag's value is consumed rather than
// misclassified as a positional argument.
func TestRunServiceInstallUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"malformed port", []string{"install", "--port", "abc"}, "port must be an integer"},
		{"oversized port", []string{"install", "--port", "65536"}, "65535"},
		{"zero port", []string{"install", "--port", "0"}, "port must be an integer"},
		{"negative port", []string{"install", "--port", "-5"}, "port must be an integer"},
		{"empty port", []string{"install", "--port", ""}, "port must be an integer"},
		{"empty host", []string{"install", "--host", ""}, "--host is set but empty"},
		{"listen combined with host/port", []string{"install", "--host", "127.0.0.1", "--port", "7405", "--listen", "127.0.0.1:8080"}, "--listen cannot be combined"},
		{"unknown flag", []string{"install", "--bogus"}, "unknown flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := captureStderr(t, func() int { return runServiceCommand(tc.args) })
			if code != 2 {
				t.Fatalf("exit = %d want 2; output: %s", code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output %q missing %q", out, tc.want)
			}
		})
	}
}

// TestRunServiceInstallValidFlagsReachOperationalPath proves the canonical
// --host/--port install example and the retained legacy --listen form pass
// listener validation (previously the --listen value was misparsed as a
// positional argument) and proceed to the operational path rather than a usage
// error. The unit-test environment runs unprivileged, so the install fails
// safely at account creation; the assertion is that parsing and resolution
// succeeded (exit 1, not exit 2). Skipped when running as root to avoid a real
// machine-service mutation.
func TestRunServiceInstallValidFlagsReachOperationalPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("skipping operational install path when running as root")
	}
	for _, args := range [][]string{
		{"install", "--host", "127.0.0.1", "--port", "7405"},
		{"install", "--listen", "127.0.0.1:8080"},
	} {
		out, code := captureStderr(t, func() int { return runServiceCommand(args) })
		if code != 1 {
			t.Fatalf("%v: exit = %d want 1 (operational failure); output: %s", args, code, out)
		}
		for _, forbidden := range []string{"requires an address", "takes no positional", "unknown flag", "cannot be combined", "port must be an integer", "--host is set but empty"} {
			if strings.Contains(out, forbidden) {
				t.Fatalf("%v: output %q contains usage error %q", args, out, forbidden)
			}
		}
	}
}

// TestRunServiceInstallRejectsFlagsForNonInstallCommands proves only
// install/upgrade accept the listener flags; every other lifecycle command
// rejects them as usage errors so malformed shell environment can never be
// resolved outside install.
func TestRunServiceInstallRejectsFlagsForNonInstallCommands(t *testing.T) {
	for _, cmd := range []string{"start", "stop", "restart", "enable", "disable", "status", "uninstall", "rollback"} {
		out, code := captureStderr(t, func() int { return runServiceCommand([]string{cmd, "--host", "127.0.0.1", "--port", "7405"}) })
		if code != 2 {
			t.Fatalf("%s --host/--port: exit = %d want 2; output: %s", cmd, code, out)
		}
		if !strings.Contains(out, "no flags are accepted") {
			t.Fatalf("%s: output %q missing no-flags message", cmd, out)
		}
	}
	// logs accepts only --follow; listener flags are still refused as usage
	// errors and never resolved.
	out, code := captureStderr(t, func() int { return runServiceCommand([]string{"logs", "--host", "127.0.0.1", "--port", "7405"}) })
	if code != 2 {
		t.Fatalf("logs --host/--port: exit = %d want 2; output: %s", code, out)
	}
	if !strings.Contains(out, "logs accepts only --follow") {
		t.Fatalf("logs: output %q missing logs message", out)
	}
	if strings.Contains(out, "port must be an integer") || strings.Contains(out, "cannot be combined") {
		t.Fatalf("logs resolved listener flags: %q", out)
	}
}

func TestServiceLifecycleSuccessGrammar(t *testing.T) {
	want := map[string]string{
		"start": "watchpost-agent.service started.",
		"stop": "watchpost-agent.service stopped.",
		"restart": "watchpost-agent.service restarted.",
		"enable": "watchpost-agent.service enabled.",
		"disable": "watchpost-agent.service disabled.",
	}
	for verb, expected := range want {
		if got := serviceLifecycleSuccess(verb); got != expected {
			t.Fatalf("%s message = %q, want %q", verb, got, expected)
		}
	}
}
