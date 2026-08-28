package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
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
	if len(arguments) > 0 && (arguments[0] == "setup" || arguments[0] == "info" || arguments[0] == "pair" || arguments[0] == "pair-status") {
		return localCommand(arguments[0], arguments[1:])
	}
	if len(arguments) > 0 && (arguments[0] == "install" || arguments[0] == "status" || arguments[0] == "uninstall") {
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
	public, err := fs.Sub(agentassets.Public, "public")
	if err != nil {
		return err
	}
	server := &http.Server{Addr: *listen, Handler: app.New(store, version, public).Handler(), ReadHeaderTimeout: 5 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go deliveryLoop(ctx,store)
	go func() { <-ctx.Done(); shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel(); _ = server.Shutdown(shutdown) }()
	fmt.Printf("Watchpost Agent %s\nLocal interface: http://%s\n", version, *listen)
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

func deliveryLoop(ctx context.Context,store *state.Store){ticker:=time.NewTicker(time.Minute);defer ticker.Stop();for{select{case<-ctx.Done():return;case<-ticker.C:_=telemetry.Send(ctx,store)}}}

func localCommand(action string, arguments []string) error {
	flags := flag.NewFlagSet("watchpost-agent "+action, flag.ContinueOnError)
	dataDir := flags.String("data-dir", defaultDataDir(), "private agent data directory")
	passwordFile := flags.String("password-file", "", "file containing the local UI password")
	jsonOutput := flags.Bool("json", false, "print machine-readable status")
	serverURL := flags.String("server", "", "Watchpost URL")
	if err := flags.Parse(arguments); err != nil { return err }
	if flags.NArg() != 0 { return fmt.Errorf("unexpected local command arguments") }
	store, err := state.Open(filepath.Join(*dataDir, "agent.json"))
	if err != nil { return err }
	switch action {
	case "setup":
		if *passwordFile == "" { return fmt.Errorf("--password-file is required") }
		password, err := os.ReadFile(*passwordFile)
		if err != nil { return err }
		if err = auth.New(store).Setup(strings.TrimRight(string(password), "\r\n")); err != nil { return err }
		fmt.Println("Local agent administrator configured.")
		return nil
	case "info":
		current := store.Snapshot()
		result := map[string]any{"installation_id": current.InstallationID, "configured": current.LocalAuth.PasswordHash != "", "paired": current.Connection.Credential != "", "watchpost_url": current.Connection.WatchpostURL, "post_id": current.Connection.PostID}
		if *jsonOutput { return json.NewEncoder(os.Stdout).Encode(result) }
		fmt.Printf("Installation: %s\nConfigured: %t\nPaired: %t\nWatchpost: %s\nPost: %s\n", current.InstallationID, result["configured"], result["paired"], current.Connection.WatchpostURL, current.Connection.PostID)
		return nil
	case "pair":
		if *serverURL=="" { return fmt.Errorf("--server is required") }
		result,err:=pairing.New(store,version).Request(context.Background(),*serverURL);if err!=nil{return err};fmt.Printf("Pairing requested.\nMatch this phrase in Watchpost: %s\nExpires: %s\n",result.Phrase,result.ExpiresAt.Format(time.RFC3339));return nil
	case "pair-status":
		result,err:=pairing.New(store,version).Poll(context.Background());if err!=nil{return err};if *jsonOutput{return json.NewEncoder(os.Stdout).Encode(result)};fmt.Printf("Pairing: %s\n",result.State);if result.PostID!=""{fmt.Printf("Post: %s\n",result.PostID)};return nil
	}
	return fmt.Errorf("unknown local action")
}

func serviceCommand(action string, arguments []string) error {
	flags := flag.NewFlagSet("watchpost-agent "+action, flag.ContinueOnError)
	system := flags.Bool("system", false, "manage a system-wide service")
	if err := flags.Parse(arguments); err != nil { return err }
	if flags.NArg() != 0 { return fmt.Errorf("unexpected service arguments") }
	paths, err := service.Resolve(*system)
	if err != nil { return err }
	manager := service.New()
	switch action {
	case "install":
		executable, err := os.Executable()
		if err != nil { return err }
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
