package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

// Default Watchpost Agent host and port used by the shared project configuration
// pattern. The agent's default listener is 127.0.0.1:7335; both remain
// configurable. An installed service unit stays the durable source of truth
// once it exists.
const (
	defaultHost = "127.0.0.1"
	defaultPort = "7335"
)

// flagProvided reports whether name was explicitly supplied on the command
// line. Standard flag strings cannot otherwise distinguish `--port ""` from an
// absent flag, and the contract requires empty CLI values to fail.
func flagProvided(fs *flag.FlagSet, name string) bool {
	provided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			provided = true
		}
	})
	return provided
}

// validatePort reports whether p is a valid TCP port: an integer from 1
// through 65535. It never silently falls back to a default.
func validatePort(p string) error {
	n, err := strconv.Atoi(strings.TrimSpace(p))
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("port must be an integer from 1 through 65535; got %q", p)
	}
	return nil
}

// resolveHostPort computes the effective bind host and port. Precedence per
// field is CLI flag > environment variable > default. Values are trimmed once
// and the canonical trimmed form is returned, so surrounding whitespace cannot
// leak into the listener string. A port that is present but empty, malformed,
// zero, negative or greater than 65535 is an error; an empty host value is
// rejected rather than silently meaning "all interfaces".
func resolveHostPort(hostFlag, portFlag string, hostSet, portSet bool) (host, port string, err error) {
	host = defaultHost
	if hostSet {
		host = strings.TrimSpace(hostFlag)
		if host == "" {
			return "", "", errors.New("--host is set but empty")
		}
	} else if v, ok := os.LookupEnv("WATCHPOST_AGENT_HOST"); ok {
		host = strings.TrimSpace(v)
		if host == "" {
			return "", "", errors.New("WATCHPOST_AGENT_HOST is set but empty")
		}
	}
	port = defaultPort
	if portSet {
		if err := validatePort(portFlag); err != nil {
			return "", "", fmt.Errorf("--port: %w", err)
		}
		port = strings.TrimSpace(portFlag)
	} else if v, ok := os.LookupEnv("WATCHPOST_AGENT_PORT"); ok {
		if err := validatePort(v); err != nil {
			return "", "", fmt.Errorf("WATCHPOST_AGENT_PORT: %w", err)
		}
		port = strings.TrimSpace(v)
	}
	return host, port, nil
}

// resolveListener computes the effective HTTP listen address from the CLI
// flags and environment with the contract CLI > environment > default.
//
//   - explicit --listen wins and cannot be combined with explicit --host/--port;
//   - explicit --host and/or --port override the legacy
//     WATCHPOST_AGENT_LISTEN variable;
//   - with only environment variables, legacy WATCHPOST_AGENT_LISTEN conflicts
//     with WATCHPOST_AGENT_HOST/WATCHPOST_AGENT_PORT rather than silently
//     picking one;
//   - otherwise WATCHPOST_AGENT_LISTEN is used, then host/port defaults.
//
// IPv6 hosts are bracketed via net.JoinHostPort.
func resolveListener(hostFlag, portFlag, listenFlag string, hostSet, portSet, listenSet bool) (string, error) {
	if listenSet {
		if hostSet || portSet {
			return "", errors.New("--listen cannot be combined with --host or --port")
		}
		if strings.TrimSpace(listenFlag) == "" {
			return "", errors.New("--listen is set but empty")
		}
		return listenFlag, nil
	}
	// Explicit --host/--port override the legacy WATCHPOST_AGENT_LISTEN variable.
	if hostSet || portSet {
		host, port, err := resolveHostPort(hostFlag, portFlag, hostSet, portSet)
		if err != nil {
			return "", err
		}
		return net.JoinHostPort(host, port), nil
	}
	// Only environment variables are involved: legacy WATCHPOST_AGENT_LISTEN
	// versus the new WATCHPOST_AGENT_HOST/WATCHPOST_AGENT_PORT forms must not
	// silently pick one.
	if v, ok := os.LookupEnv("WATCHPOST_AGENT_LISTEN"); ok {
		if _, hasHost := os.LookupEnv("WATCHPOST_AGENT_HOST"); hasHost {
			return "", errors.New("WATCHPOST_AGENT_LISTEN cannot be combined with WATCHPOST_AGENT_HOST")
		}
		if _, hasPort := os.LookupEnv("WATCHPOST_AGENT_PORT"); hasPort {
			return "", errors.New("WATCHPOST_AGENT_LISTEN cannot be combined with WATCHPOST_AGENT_PORT")
		}
		if strings.TrimSpace(v) == "" {
			return "", errors.New("WATCHPOST_AGENT_LISTEN is set but empty")
		}
		return v, nil
	}
	host, port, err := resolveHostPort(hostFlag, portFlag, hostSet, portSet)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(host, port), nil
}

// listenerOverrideSelected reports whether the user explicitly selected the new
// host/port listener form (CLI flags or WATCHPOST_AGENT_HOST/WATCHPOST_AGENT_PORT
// environment). Legacy --listen and bare invocations keep the durable config
// listener. Watchpost Agent has no durable config file, so in the foreground
// the resolved listener is the runtime listener in either case; the helper is
// retained as part of the shared host/port pattern.
func listenerOverrideSelected(fs *flag.FlagSet) bool {
	if flagProvided(fs, "host") || flagProvided(fs, "port") {
		return true
	}
	if _, ok := os.LookupEnv("WATCHPOST_AGENT_HOST"); ok {
		return true
	}
	if _, ok := os.LookupEnv("WATCHPOST_AGENT_PORT"); ok {
		return true
	}
	return false
}

// validateNoControl rejects CR, LF, NUL and other control characters so no
// user-supplied listener value can inject directives into a systemd unit.
func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}
