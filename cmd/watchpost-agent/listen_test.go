package main

import (
	"flag"
	"os"
	"testing"
)

// listenerFlags parses raw argv through the same flag definitions the CLI uses
// so "provided but empty" (--host "") is distinguishable from "not provided".
func listenerFlags(args ...string) (h, p, l string, hs, ps, ls bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("host", "", "")
	fs.String("port", "", "")
	fs.String("listen", "", "")
	_ = fs.Parse(args)
	return fs.Lookup("host").Value.String(),
		fs.Lookup("port").Value.String(),
		fs.Lookup("listen").Value.String(),
		flagProvided(fs, "host"),
		flagProvided(fs, "port"),
		flagProvided(fs, "listen")
}

func TestResolveListenerDefaults(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7335" {
		t.Fatalf("default listener = %q want 127.0.0.1:7335", addr)
	}
}

func TestResolveListenerEnvOnly(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_AGENT_PORT", "7402")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0:7402" {
		t.Fatalf("env listener = %q want 0.0.0.0:7402", addr)
	}
}

func TestResolveListenerCLIOnly(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "192.0.2.1")
	t.Setenv("WATCHPOST_AGENT_PORT", "9999")
	h, p, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli listener = %q want 127.0.0.1:7402", addr)
	}
}

func TestResolveListenerCLIOverridesEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_AGENT_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli should override env: %q", addr)
	}
}

func TestResolveListenerInvalidPorts(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	for _, p := range []string{"abc", "0", "-5", "65536", "70000", "7 4 0 2", "7402x"} {
		h, pp, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", p)
		if _, err := resolveListener(h, pp, l, hs, ps, ls); err == nil {
			t.Fatalf("invalid --port %q accepted", p)
		}
	}
	for _, p := range []string{"abc", "0", "-5", "65536", "70000"} {
		t.Setenv("WATCHPOST_AGENT_HOST", "127.0.0.1")
		t.Setenv("WATCHPOST_AGENT_PORT", p)
		h, pp, l, hs, ps, ls := listenerFlags()
		if _, err := resolveListener(h, pp, l, hs, ps, ls); err == nil {
			t.Fatalf("invalid WATCHPOST_AGENT_PORT %q accepted", p)
		}
	}
}

func TestResolveListenerEmptyEnvFails(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "127.0.0.1")
	t.Setenv("WATCHPOST_AGENT_PORT", "")
	h, p, l, hs, ps, ls := listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty WATCHPOST_AGENT_PORT accepted")
	}
	t.Setenv("WATCHPOST_AGENT_HOST", "")
	t.Setenv("WATCHPOST_AGENT_PORT", "7335")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty WATCHPOST_AGENT_HOST accepted")
	}
}

func TestResolveListenerEmptyCLIValuesFail(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "127.0.0.1")
	t.Setenv("WATCHPOST_AGENT_PORT", "7335")
	h, p, l, hs, ps, ls := listenerFlags("--host", "", "--port", "7335")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty --host accepted")
	}
	h, p, l, hs, ps, ls = listenerFlags("--host", "127.0.0.1", "--port", "")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty --port accepted")
	}
}

func TestResolveListenerIPv6(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "::1")
	t.Setenv("WATCHPOST_AGENT_PORT", "7335")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "[::1]:7335" {
		t.Fatalf("IPv6 listener = %q want [::1]:7335", addr)
	}
}

func TestResolveListenerLegacyListen(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_AGENT_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--listen", "127.0.0.1:8080")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("legacy --listen = %q", addr)
	}
	// WATCHPOST_AGENT_LISTEN environment is honored as the legacy single-address form.
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	t.Setenv("WATCHPOST_AGENT_LISTEN", "127.0.0.1:9000")
	h, p, l, hs, ps, ls = listenerFlags()
	addr, err = resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:9000" {
		t.Fatalf("WATCHPOST_AGENT_LISTEN = %q", addr)
	}
	// Legacy form combined with --host/--port must fail.
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	h2, p2, l2, hs2, ps2, ls2 := listenerFlags("--host", "127.0.0.1", "--port", "7402", "--listen", "127.0.0.1:8080")
	if _, err := resolveListener(h2, p2, l2, hs2, ps2, ls2); err == nil {
		t.Fatal("--listen combined with --host/--port accepted")
	}
}

func TestResolveListenerTrimsWhitespace(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags("--host", "  127.0.0.1  ", "--port", "  7402  ")
	host, port, err := resolveHostPort(h, p, hs, ps)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != "7402" {
		t.Fatalf("cli trimmed host/port = %q/%q want 127.0.0.1/7402", host, port)
	}
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli listener = %q want 127.0.0.1:7402", addr)
	}
	t.Setenv("WATCHPOST_AGENT_HOST", "  0.0.0.0  ")
	t.Setenv("WATCHPOST_AGENT_PORT", "  7403  ")
	h, p, l, hs, ps, ls = listenerFlags()
	host, port, err = resolveHostPort(h, p, hs, ps)
	if err != nil {
		t.Fatal(err)
	}
	if host != "0.0.0.0" || port != "7403" {
		t.Fatalf("env trimmed host/port = %q/%q want 0.0.0.0/7403", host, port)
	}
	addr, err = resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0:7403" {
		t.Fatalf("env listener = %q want 0.0.0.0:7403", addr)
	}
}

func TestResolveListenerWhitespaceOnlyFails(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags("--host", "   ", "--port", "   ")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only --host/--port accepted")
	}
	t.Setenv("WATCHPOST_AGENT_HOST", "   ")
	t.Setenv("WATCHPOST_AGENT_PORT", "   ")
	h, p, l, hs, ps, ls = listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only WATCHPOST_AGENT_HOST/WATCHPOST_AGENT_PORT accepted")
	}
	t.Setenv("WATCHPOST_AGENT_HOST", "   ")
	t.Setenv("WATCHPOST_AGENT_PORT", "7402")
	h, p, l, hs, ps, ls = listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only host accepted with valid port")
	}
}

func TestValidatePort(t *testing.T) {
	for _, ok := range []string{"1", "7335", "65535"} {
		if err := validatePort(ok); err != nil {
			t.Fatalf("valid port %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0", "-1", "65536", "7335.5", "x"} {
		if err := validatePort(bad); err == nil {
			t.Fatalf("invalid port %q accepted", bad)
		}
	}
}

func TestResolveListenerExplicitPortOverridesLegacyEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	t.Setenv("WATCHPOST_AGENT_LISTEN", "127.0.0.1:8080")
	h, p, l, hs, ps, ls := listenerFlags("--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("explicit --port must override WATCHPOST_AGENT_LISTEN: %q", addr)
	}
}

func TestResolveListenerExplicitHostOverridesLegacyEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	t.Setenv("WATCHPOST_AGENT_LISTEN", "127.0.0.1:8080")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	h, p, l, hs, ps, ls := listenerFlags("--host", "10.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.0.0.1:7402" {
		t.Fatalf("explicit --host/--port must override WATCHPOST_AGENT_LISTEN: %q", addr)
	}
}

func TestResolveListenerExplicitListenOverridesHostPortEnv(t *testing.T) {
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_AGENT_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--listen", "127.0.0.1:8080")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("explicit --listen must override host/port env: %q", addr)
	}
}

func TestResolveListenerEnvConflict(t *testing.T) {
	// Only environment variables involved: legacy WATCHPOST_AGENT_LISTEN
	// conflicts with WATCHPOST_AGENT_HOST or WATCHPOST_AGENT_PORT and must fail
	// rather than silently pick one.
	t.Setenv("WATCHPOST_AGENT_LISTEN", "127.0.0.1:8080")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	h, p, l, hs, ps, ls := listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("WATCHPOST_AGENT_LISTEN + WATCHPOST_AGENT_HOST conflict accepted")
	}
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	t.Setenv("WATCHPOST_AGENT_PORT", "9000")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("WATCHPOST_AGENT_LISTEN + WATCHPOST_AGENT_PORT conflict accepted")
	}
}

func TestListenerOverrideSelected(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("host", "", "")
	fs.String("port", "", "")
	fs.String("listen", "", "")
	_ = fs.Parse(nil)
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	if listenerOverrideSelected(fs) {
		t.Fatal("bare invocation must not override durable config")
	}
	// WATCHPOST_AGENT_LISTEN only: not an explicit new-form override.
	t.Setenv("WATCHPOST_AGENT_LISTEN", "127.0.0.1:8080")
	if listenerOverrideSelected(fs) {
		t.Fatal("legacy WATCHPOST_AGENT_LISTEN must not override durable config")
	}
	// WATCHPOST_AGENT_HOST / WATCHPOST_AGENT_PORT environment: override.
	os.Unsetenv("WATCHPOST_AGENT_LISTEN")
	t.Setenv("WATCHPOST_AGENT_HOST", "0.0.0.0")
	if !listenerOverrideSelected(fs) {
		t.Fatal("WATCHPOST_AGENT_HOST must override durable config")
	}
	os.Unsetenv("WATCHPOST_AGENT_HOST")
	t.Setenv("WATCHPOST_AGENT_PORT", "7402")
	if !listenerOverrideSelected(fs) {
		t.Fatal("WATCHPOST_AGENT_PORT must override durable config")
	}
	// Explicit CLI --host/--port: override.
	os.Unsetenv("WATCHPOST_AGENT_PORT")
	_ = fs.Set("host", "127.0.0.1")
	_ = fs.Set("port", "7402")
	if !listenerOverrideSelected(fs) {
		t.Fatal("explicit --host/--port must override durable config")
	}
}

func TestValidateNoControlListen(t *testing.T) {
	if err := validateNoControl("127.0.0.1:7335", "listen"); err != nil {
		t.Fatal(err)
	}
	if err := validateNoControl("127.0.0.1:7335\nfoo", "listen"); err == nil {
		t.Fatal("newline accepted")
	}
}
