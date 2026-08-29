package main

import (
	"strings"
	"testing"
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