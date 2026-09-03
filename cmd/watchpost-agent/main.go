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
	// Service-management commands must remain usable even when the application
	// configuration is unhealthy, so dispatch before any runtime config load.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runServiceCommand(os.Args[2:]))
	}
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "watchpost-agent:", err)
		os.Exit(1)
	}
}

// runServiceCommand dispatches `watchpost-agent service <command>` operating the
// Watchpost Agent systemd **system** unit. Exit codes: 0 success, 1 operational
// failure, 2 usage error (canonical Web Fleet convention).
func runServiceCommand(args []string) int {
	cmd := "status"
	// Flags that consume a following value are recorded as pairs so their value
	// is never misclassified as a positional argument.
	valueFlags := map[string]bool{"--host": true, "--port": true, "--listen": true, "--env-file": true}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a != "" && !strings.HasPrefix(a, "-") {
			if cmd == "status" && len(positional) == 0 {
				cmd = a
				continue
			}
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if valueFlags[a] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	usage := func(msg string) int {
		fmt.Fprintf(os.Stderr, "watchpost-agent service %s: %s\n", cmd, msg)
		return 2
	}
	if len(flags) > 0 {
		switch cmd {
		case "install", "upgrade":
			for i := 0; i < len(flags); i++ {
				switch flags[i] {
				case "--host":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--host requires an address")
					}
				case "--port":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--port requires a number")
					}
				case "--listen":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--listen requires an address")
					}
				case "--env-file":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--env-file requires a path")
					}
				default:
					return usage("unknown flag " + flags[i])
				}
			}
		case "logs":
			if len(flags) > 1 || flags[0] != "--follow" {
				return usage("logs accepts only --follow")
			}
		default:
			return usage("no flags are accepted for " + cmd)
		}
	}
	paths := service.DefaultPaths()
	switch cmd {
	case "install", "upgrade":
		if len(positional) != 0 {
			return usage(cmd + " takes no positional arguments")
		}
		executable, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent:", err)
			return 1
		}
		// Resolve the requested listener from the explicit CLI flags and the
		// environment (CLI > environment > default). Only install/upgrade
		// resolve the listener, so a malformed WATCHPOST_AGENT_HOST/PORT in the
		// shell can never break start/stop/restart/status/logs/uninstall.
		listen, host, port, envfile := "", "", "", ""
		hostSet, portSet, listenSet, envfileSet := false, false, false, false
		for i := 0; i < len(flags); i++ {
			switch flags[i] {
			case "--host":
				if i+1 < len(flags) {
					i++
					host = flags[i]
					hostSet = true
				}
			case "--port":
				if i+1 < len(flags) {
					i++
					port = flags[i]
					portSet = true
				}
			case "--listen":
				if i+1 < len(flags) {
					i++
					listen = flags[i]
					listenSet = true
				}
			case "--env-file":
				if i+1 < len(flags) {
					i++
					envfile = flags[i]
					envfileSet = true
				}
			}
		}
		addr, err := resolveListener(host, port, listen, hostSet, portSet, listenSet)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service "+cmd+":", err)
			return 2
		}
		if err := validateNoControl(addr, "listen"); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service "+cmd+":", err)
			return 2
		}
		// Resolve the recorded listener and its mode (explicit host/port vs
		// legacy --listen/WATCHPOST_AGENT_LISTEN bootstrap) for the generated
		// unit.
		legacy := listenSet
		if !legacy {
			if _, hasListen := os.LookupEnv("WATCHPOST_AGENT_LISTEN"); hasListen && !hostSet && !portSet {
				legacy = true
			}
		}
		explicit := hostSet || portSet || listenSet
		for _, key := range []string{"WATCHPOST_AGENT_HOST", "WATCHPOST_AGENT_PORT", "WATCHPOST_AGENT_LISTEN"} {
			if _, ok := os.LookupEnv(key); ok {
				explicit = true
			}
		}
		manager := service.New()
		var opts service.Options
		if explicit {
			opts, err = installOptions(addr, legacy, envfile)
		} else if meta, ok, metaErr := manager.ExistingMeta(paths); metaErr != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent:", metaErr)
			return 1
		} else if ok {
			// No explicit listener selection: preserve the existing recorded
			// listener in its recorded form so a bare reinstall or upgrade
			// never silently changes the runtime listener.
			if !envfileSet && meta.EnvFile != "" {
				envfile = meta.EnvFile
			}
			opts = service.OptionsFromMeta(meta, envfile)
		} else {
			opts, err = installOptions(addr, false, envfile)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service "+cmd+":", err)
			return 2
		}
		if err := manager.InstallOptions(executable, paths, opts); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service "+cmd+":", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost-agent.service installed.")
		return 0
	case "uninstall":
		if len(positional) != 0 {
			return usage("uninstall takes no positional arguments")
		}
		manager := service.New()
		if err := manager.Uninstall(os.Stdout, paths); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service uninstall:", err)
			return 1
		}
		return 0
	case "start", "stop", "restart", "enable", "disable":
		if len(positional) != 0 {
			return usage(cmd + " takes no positional arguments")
		}
		manager := service.New()
		if err := lifecycleErr(manager, paths, cmd); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service "+cmd+":", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, serviceLifecycleSuccess(cmd))
		return 0
	case "status":
		if len(positional) != 0 {
			return usage("status takes no positional arguments")
		}
		manager := service.New()
		if err := manager.Status(os.Stdout, paths, version); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service status:", err)
			return 1
		}
		return 0
	case "logs":
		if len(positional) != 0 {
			return usage("logs takes no positional arguments")
		}
		manager := service.New()
		follow := len(flags) > 0 && flags[0] == "--follow"
		if err := manager.Logs(follow, os.Stdout, paths); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service logs:", err)
			return 1
		}
		return 0
	case "update":
		if len(positional) != 2 {
			return usage("usage: watchpost-agent service update ARTIFACT SHA256")
		}
		manager := service.New()
		if err := manager.Update(positional[0], positional[1], paths); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service update:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost-agent.service updated.")
		return 0
	case "rollback":
		if len(positional) != 0 {
			return usage("rollback takes no positional arguments")
		}
		manager := service.New()
		if err := manager.Rollback(paths); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost-agent service rollback:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost-agent.service rolled back.")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "watchpost-agent: unknown service command %q\n\nUsage: watchpost-agent service <install|uninstall|start|stop|restart|status|enable|disable|logs|update|rollback> [flags]\n", cmd)
		return 2
	}
}

func serviceLifecycleSuccess(verb string) string {
	words := map[string]string{
		"start": "started", "stop": "stopped", "restart": "restarted",
		"enable": "enabled", "disable": "disabled",
	}
	return "watchpost-agent.service " + words[verb] + "."
}

// installOptions builds the service.Options recorded in a newly installed unit
// from the resolved listener. Legacy bootstrap units keep the single-address
// --listen form; explicit host/port units are split back into --host/--port so
// their recorded listener is the runtime listener across restart and reboot.
func installOptions(addr string, legacy bool, envfile string) (service.Options, error) {
	if legacy {
		return service.Options{Listen: addr, EnvFile: envfile}, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return service.Options{}, fmt.Errorf("cannot split resolved listener %q: %w", addr, err)
	}
	return service.Options{Host: host, Port: port, EnvFile: envfile}, nil
}

func lifecycleErr(m service.Manager, paths service.Paths, verb string) error {
	switch verb {
	case "start":
		return m.Start(paths)
	case "stop":
		return m.Stop(paths)
	case "restart":
		return m.Restart(paths)
	case "enable":
		return m.Enable(paths)
	case "disable":
		return m.Disable(paths)
	}
	return fmt.Errorf("unknown lifecycle verb")
}

func run(arguments []string) error {
	if len(arguments) > 0 && (arguments[0] == "setup" || arguments[0] == "info" || arguments[0] == "pair" || arguments[0] == "pair-status" || arguments[0] == "configure" || arguments[0] == "rotate" || arguments[0] == "unpair" || arguments[0] == "reset") {
		return localCommand(arguments[0], arguments[1:])
	}
	flags := flag.NewFlagSet("watchpost-agent", flag.ContinueOnError)
	host := flags.String("host", "", "HTTP bind host (default 127.0.0.1; WATCHPOST_AGENT_HOST overrides, CLI wins)")
	port := flags.String("port", "", "HTTP bind port, 1-65535 (default 7335; WATCHPOST_AGENT_PORT overrides, CLI wins)")
	listen := flags.String("listen", "", "local agent UI address (legacy; alternative to --host/--port, honors WATCHPOST_AGENT_LISTEN)")
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
	addr, err := resolveListener(*host, *port, *listen, flagProvided(flags, "host"), flagProvided(flags, "port"), flagProvided(flags, "listen"))
	if err != nil {
		return err
	}
	// The resolved listener is the runtime listener. Watchpost Agent has no
	// durable config file: explicit --host/--port selection (CLI or
	// WATCHPOST_AGENT_HOST/WATCHPOST_AGENT_PORT) and bare or legacy --listen
	// invocations all resolve to the same canonical address here.
	store, err := state.Open(filepath.Join(*dataDir, "agent.json"))
	if err != nil {
		return err
	}
	options, err := appOptions(addr)
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
	server := &http.Server{Addr: addr, Handler: app.New(store, version, public, options).Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go deliveryLoop(ctx, store)
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	fmt.Printf("Watchpost Agent %s\nLocal interface: http://%s\n", version, addr)
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return fmt.Errorf("%v (listener: %s)", err, addr)
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
				_ = pairing.New(store, version).RetryPendingRevocation(ctx, "cli")
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
		result, err := pairing.New(store, version).Request(context.Background(), *serverURL, "cli")
		if err != nil {
			return err
		}
		fmt.Printf("Pairing requested.\nMatch this phrase in Watchpost: %s\nExpires: %s\n", result.Phrase, result.ExpiresAt.Format(time.RFC3339))
		return nil
	case "pair-status":
		result, err := pairing.New(store, version).Poll(context.Background(), "cli")
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
		if err := pairing.New(store, version).Unpair(context.Background(), "cli"); err != nil {
			return err
		}
		fmt.Println("Agent unpaired. The connection was revoked at Watchpost; local configuration and administrator retained.")
		return nil
	case "rotate":
		if err := pairing.New(store, version).Rotate(context.Background(), "cli"); err != nil {
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

func defaultDataDir() string {
	if value := os.Getenv("WATCHPOST_AGENT_DATA_DIR"); value != "" {
		return value
	}
	return "/var/lib/watchpost-agent"
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
