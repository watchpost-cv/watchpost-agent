package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchpost-ops/watchpost-agent/internal/app"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

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
