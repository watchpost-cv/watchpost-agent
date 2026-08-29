package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	agentassets "github.com/watchpost-ops/watchpost-agent"
	"github.com/watchpost-ops/watchpost-agent/internal/app"
	"github.com/watchpost-ops/watchpost-agent/internal/auth"
	"github.com/watchpost-ops/watchpost-agent/internal/pairing"
	"github.com/watchpost-ops/watchpost-agent/internal/service"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
	"github.com/watchpost-ops/watchpost-agent/internal/telemetry"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "watchpost-agent:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) > 0 && (arguments[0] == "setup" || arguments[0] == "info" || arguments[0] == "pair" || arguments[0] == "pair-status" || arguments[0] == "configure" || arguments[0] == "rotate" || arguments[0] == "unpair" || arguments[0] == "reset") {
		return localCommand(arguments[0], arguments[1:])
	}
	if len(arguments) > 0 && (arguments[0] == "install" || arguments[0] == "upgrade" || arguments[0] == "status" || arguments[0] == "uninstall") {
		return serviceCommand(arguments[0], arguments[1:])
	}
	flags := flag.NewFlagSet("watchpost-agent", flag.ContinueOnError)
	listen := flags.String("listen", "127.0.0.1:8090", "local agent UI address")
	dataDir := flags.String("data-dir", defaultDataDir(), "private agent data directory")
	showVersion := flags.Bool("version", false, "print version")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	if *showVersion {
		fmt.Println(version)
		return nil
	}
	store, err := state.Open(filepath.Join(*dataDir, "agent.json"))
	if err != nil {
		return err
	}
	options, err := appOptions(*listen)
	if err != nil {
		return err
	}
	if err := provisionSetupToken(store, options); err != nil {
		return err
	}
	public, err := fs.Sub(agentassets.Public, "public")
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: app.New(store, version, public, options).Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go deliveryLoop(ctx, store)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("Watchpost Agent %s\nLocal interface: http://%s\n", version, *listen)
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func deliveryLoop(ctx context.Context, store *state.Store) {
	for {
		interval := store.Snapshot().Collectors.IntervalSeconds
		if interval < 15 {
			interval = 60
		}
		timer := time.NewTimer(time.Duration(interval) * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
			current := store.Snapshot()
			if current.Connection.RevocationPending && current.Connection.Credential != "" {
				_ = pairing.New(store, version).RetryPendingRevocation(ctx)
				continue
			}
			_ = telemetry.Send(ctx, store)
		}
	}
}

func localCommand(action string, arguments []string) error {
	flags := flag.NewFlagSet("watchpost-agent "+action, flag.ContinueOnError)
	dataDir := flags.String("data-dir", defaultDataDir(), "private agent data directory")
	passwordFile := flags.String("password-file", "", "file containing the local UI password")
	email := flags.String("email", "", "email address for the first local administrator")
	emailFile := flags.String("email-file", "", "file containing the first local administrator email")
	jsonOutput := flags.Bool("json", false, "print machine-readable status")
	serverURL := flags.String("server", "", "Watchpost URL")
	interval := flags.Int("interval", 60, "collection interval in seconds")
	cpu := flags.Bool("cpu", true, "collect CPU utilisation")
	memory := flags.Bool("memory", true, "collect memory utilisation")
	load := flags.Bool("load", true, "collect one-minute load")
	uptime := flags.Bool("uptime", true, "collect uptime")
	filesystems := flags.String("filesystems", "/", "comma-separated absolute filesystem paths")
	confirm := flags.String("confirm", "", "installation ID confirmation for reset")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected local command arguments")
	}
	store, err := state.Open(filepath.Join(*dataDir, "agent.json"))
	if err != nil {
		return err
	}
	switch action {
	case "setup":
		address := *email
		if *emailFile != "" {
			content, err := os.ReadFile(*emailFile)
			if err != nil {
				return err
			}
			address = strings.TrimRight(string(content), "\r\n")
		}
		if address == "" || *passwordFile == "" {
			return fmt.Errorf("--email (or --email-file) and --password-file are required")
		}
		password, err := os.ReadFile(*passwordFile)
		if err != nil {
			return err
		}
		if err = auth.New(store).Setup(address, strings.TrimRight(string(password), "\r\n"), ""); err != nil {
			return err
		}
		fmt.Println("Local agent administrator configured.")
		return nil
	case "info":
		current := store.Snapshot()
		result := map[string]any{"installation_id": current.InstallationID, "configured": current.LocalAuth.PasswordHash != "", "paired": current.Connection.Credential != "", "watchpost_url": current.Connection.WatchpostURL, "post_id": current.Connection.PostID, "queued_batches": len(current.Delivery.Queue), "delivery_failures": current.Delivery.ConsecutiveFailures, "last_delivery_error": current.Delivery.LastError, "dropped_collections": current.Delivery.DroppedCollections}
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		fmt.Printf("Installation: %s\nConfigured: %t\nPaired: %t\nWatchpost: %s\nPost: %s\n", current.InstallationID, result["configured"], result["paired"], current.Connection.WatchpostURL, current.Connection.PostID)
		return nil
	case "pair":
		if *serverURL == "" {
			return fmt.Errorf("--server is required")
		}
		result, err := pairing.New(store, version).Request(context.Background(), *serverURL)
		if err != nil {
			return err
		}
		fmt.Printf("Pairing requested.\nMatch this phrase in Watchpost: %s\nExpires: %s\n", result.Phrase, result.ExpiresAt.Format(time.RFC3339))
		return nil
	case "pair-status":
		result, err := pairing.New(store, version).Poll(context.Background())
		if err != nil {
			return err
		}
		if *jsonOutput {
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		fmt.Printf("Pairing: %s\n", result.State)
		if result.PostID != "" {
			fmt.Printf("Post: %s\n", result.PostID)
		}
		return nil
	case "configure":
		paths := []string{}
		for _, path := range strings.Split(*filesystems, ",") {
			path = strings.TrimSpace(path)
			if path != "" {
				paths = append(paths, path)
			}
		}
		config := state.CollectorConfig{IntervalSeconds: *interval, CPU: *cpu, Memory: *memory, Load: *load, Uptime: *uptime, Filesystems: paths}
		if err := config.Validate(); err != nil {
			return err
		}
		if err := store.Update(func(value *state.State) error { value.Collectors = config; return nil }); err != nil {
			return err
		}
		fmt.Printf("Collectors updated: every %d seconds.\n", config.IntervalSeconds)
		return nil
	case "unpair":
		if err := pairing.New(store, version).Unpair(context.Background()); err != nil {
			return err
		}
		fmt.Println("Agent unpaired. The connection was revoked at Watchpost; local configuration and administrator retained.")
		return nil
	case "rotate":
		if err := pairing.New(store, version).Rotate(context.Background()); err != nil {
			return err
		}
		fmt.Println("Post-scoped credential rotated atomically.")
		return nil
	case "reset":
		if *confirm == "" {
			return fmt.Errorf("--confirm with the installation ID is required")
		}
		if err := store.Reset(*confirm); err != nil {
			return err
		}
		fmt.Println("Agent reset. Warning: this does not revoke the connection centrally; an administrator must revoke it in Watchpost if this machine was lost.")
		return nil
	}
	return fmt.Errorf("unknown local action")
}

func serviceCommand(action string, arguments []string) error {
	flags := flag.NewFlagSet("watchpost-agent "+action, flag.ContinueOnError)
	system := flags.Bool("system", false, "manage a system-wide service")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected service arguments")
	}
	paths, err := service.Resolve(*system)
	if err != nil {
		return err
	}
	manager := service.New()
	switch action {
	case "install":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return manager.Install(executable, paths)
	case "upgrade":
		executable, err := os.Executable()
		if err != nil {
			return err
		}
		return manager.Install(executable, paths)
	case "status":
		return manager.Status(paths)
	case "uninstall":
		return manager.Uninstall(paths)
	}
	return fmt.Errorf("unknown service action")
}

func defaultDataDir() string {
	if value := os.Getenv("WATCHPOST_AGENT_DATA_DIR"); value != "" {
		return value
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".watchpost-agent"
	}
	return filepath.Join(home, ".local", "share", "watchpost-agent")
}

// appOptions reads remote-management security options. Binding to a
// non-loopback interface requires an explicit WATCHPOST_AGENT_EXPOSE opt-in
// and prints a prominent warning, because the local interface is not a
// hardened internet service.
func appOptions(listen string) (app.Options, error) {
	options := app.Options{
		SecureCookies: envBool("WATCHPOST_AGENT_SECURE_COOKIES"),
	}
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return options, fmt.Errorf("invalid listen address %q", listen)
	}
	loopback := host == "localhost" || (net.ParseIP(host) != nil && net.ParseIP(host).IsLoopback())
	if !loopback && !envBool("WATCHPOST_AGENT_EXPOSE") {
		return options, fmt.Errorf("binding to %s exposes the local agent interface beyond loopback; set WATCHPOST_AGENT_EXPOSE=1 only after reviewing HTTPS/reverse-proxy deployment and local roles", listen)
	}
	if !loopback {
		fmt.Fprintf(os.Stderr, "WARNING: Watchpost Agent interface is bound to %s (non-loopback).\nThis is experimental. Terminate HTTPS at a reverse proxy, enable WATCHPOST_AGENT_SECURE_COOKIES, restrict client CIDRs, and review the local audit log.\n", listen)
	}
	allow, err := parseCIDRs(os.Getenv("WATCHPOST_AGENT_ALLOW_CIDRS"))
	if err != nil {
		return options, err
	}
	deny, err := parseCIDRs(os.Getenv("WATCHPOST_AGENT_DENY_CIDRS"))
	if err != nil {
		return options, err
	}
	trusted, err := parseCIDRs(os.Getenv("WATCHPOST_AGENT_TRUSTED_PROXIES"))
	if err != nil {
		return options, err
	}
	options.AllowCIDRs = allow
	options.DenyCIDRs = deny
	options.TrustedProxies = trusted
	// First-admin setup requires a bootstrap token whenever agent management is
	// remotely exposed or an operator-supplied token is configured.
	operatorToken := os.Getenv("WATCHPOST_AGENT_SETUP_TOKEN") != "" || os.Getenv("WATCHPOST_AGENT_SETUP_TOKEN_FILE") != ""
	options.SetupTokenRequired = operatorToken || !loopback
	return options, nil
}

// provisionSetupToken stores or generates the first-admin bootstrap token. The
// raw value is printed once (or comes from a protected operator file); only a
// hash is persisted. The token is never returned by any API.
func provisionSetupToken(store *state.Store, options app.Options) error {
	if !options.SetupTokenRequired {
		return nil
	}
	manager := auth.New(store)
	if !manager.SetupRequired() {
		return nil
	}
	raw := os.Getenv("WATCHPOST_AGENT_SETUP_TOKEN")
	if raw == "" {
		if file := os.Getenv("WATCHPOST_AGENT_SETUP_TOKEN_FILE"); file != "" {
			content, err := os.ReadFile(file)
			if err != nil {
				return err
			}
			raw = strings.TrimRight(string(content), "\r\n")
		}
	}
	ttl := time.Hour
	if value := os.Getenv("WATCHPOST_AGENT_SETUP_TOKEN_TTL"); value != "" {
		duration, err := time.ParseDuration(value)
		if err != nil || duration <= 0 {
			return fmt.Errorf("WATCHPOST_AGENT_SETUP_TOKEN_TTL: invalid value")
		}
		ttl = duration
	}
	if raw != "" {
		return manager.StoreBootstrapToken(raw, time.Now().Add(ttl))
	}
	token, err := manager.GenerateBootstrapToken(ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Watchpost Agent first-run setup requires a bootstrap token.\nToken: %s (expires %s)\n", token, time.Now().Add(ttl).Format(time.RFC3339))
	return nil
}

func parseCIDRs(value string) ([]*net.IPNet, error) {
	nets := []*net.IPNet{}
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, network, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, network)
			continue
		}
		// Bare addresses are treated as exact hosts.
		if ip := net.ParseIP(strings.Trim(part, "[]")); ip != nil {
			bits := 128
			if ip.To4() != nil {
				bits = 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		return nil, fmt.Errorf("invalid agent CIDR or address %q", part)
	}
	return nets, nil
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}
