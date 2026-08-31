package main

import (
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchpost-ops/watchpost-agent/internal/app"
	"github.com/watchpost-ops/watchpost-agent/internal/service"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

func TestUnitMatchesForegroundConfig(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	paths := service.Paths{Binary: "/usr/local/lib/watchpost-agent/watchpost-agent", DataDir: defaultDataDir()}
	unit := service.Unit(paths, "127.0.0.1:8090", "")
	for _, want := range []string{`"--listen" "127.0.0.1:8090"`, `"--data-dir" "` + paths.DataDir + `"`} {
		if !strings.Contains(unit, want) {
			t.Fatalf("unit does not match foreground defaults (%s):\n%s", want, unit)
		}
	}
}

func TestServiceNamespaceDispatch(t *testing.T) {
	// `watchpost-agent service status` and `watchpost-agent status` both resolve
	// to the service command and report a missing unit without touching systemd.
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{{"service", "status"}, {"status"}} {
		err := run(args)
		if err == nil {
			t.Fatalf("%v unexpectedly succeeded", args)
		}
		if !strings.Contains(err.Error(), "not installed") {
			t.Fatalf("%v error: %v", args, err)
		}
	}
}

func TestAppOptionsRequireExplicitRemoteExposure(t *testing.T) {
	if _, err := appOptions("127.0.0.1:8090"); err != nil {
		t.Fatalf("loopback binding rejected: %v", err)
	}
	_, err := appOptions("0.0.0.0:8090")
	if err == nil || !strings.Contains(err.Error(), "WATCHPOST_AGENT_EXPOSE") {
		t.Fatalf("non-loopback binding without explicit opt-in: %v", err)
	}
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "1")
	if _, err := appOptions("0.0.0.0:8090"); err != nil {
		t.Fatalf("non-loopback binding with explicit opt-in rejected: %v", err)
	}
}

func TestAppOptionsParseCIDRs(t *testing.T) {
	options, err := appOptions("127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	if len(options.AllowCIDRs) != 0 || len(options.DenyCIDRs) != 0 {
		t.Fatalf("unexpected default CIDRs: %#v", options)
	}
	t.Setenv("WATCHPOST_AGENT_ALLOW_CIDRS", "10.0.0.0/8")
	t.Setenv("WATCHPOST_AGENT_DENY_CIDRS", "not-a-cidr")
	if _, err := appOptions("127.0.0.1:8090"); err == nil {
		t.Fatal("invalid deny CIDR accepted")
	}
	t.Setenv("WATCHPOST_AGENT_DENY_CIDRS", "")
	options, err = appOptions("127.0.0.1:8090")
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
	options, err := appOptions("127.0.0.1:8090")
	if err != nil {
		t.Fatal(err)
	}
	if options.SetupTokenRequired {
		t.Fatal("loopback setup should not require a token")
	}
	options, err = appOptions("0.0.0.0:8090")
	if err == nil || !strings.Contains(err.Error(), "WATCHPOST_AGENT_EXPOSE") {
		t.Fatalf("non-loopback without expose: %v", err)
	}
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "1")
	options, err = appOptions("0.0.0.0:8090")
	if err != nil {
		t.Fatal(err)
	}
	if !options.SetupTokenRequired {
		t.Fatal("remote exposure must require a setup token")
	}
	// An operator-supplied token requires it even on loopback.
	t.Setenv("WATCHPOST_AGENT_EXPOSE", "")
	t.Setenv("WATCHPOST_AGENT_SETUP_TOKEN", "operator-supplied-token")
	options, err = appOptions("127.0.0.1:8090")
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
	options, err := appOptions("127.0.0.1:8090")
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
	options, err := appOptions("127.0.0.1:8090")
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
	if _, err := appOptions("127.0.0.1:8090"); err == nil {
		t.Fatal("invalid trusted proxy accepted")
	}
}
