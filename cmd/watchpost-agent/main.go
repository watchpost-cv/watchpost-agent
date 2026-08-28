package main

import (
	"context"
	"flag"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	agentassets "github.com/watchpost-ops/watchpost-agent"
	"github.com/watchpost-ops/watchpost-agent/internal/app"
	"github.com/watchpost-ops/watchpost-agent/internal/state"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "watchpost-agent:", err)
		os.Exit(1)
	}
}

func run(arguments []string) error {
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
	go func() { <-ctx.Done(); shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second); defer cancel(); _ = server.Shutdown(shutdown) }()
	fmt.Printf("Watchpost Agent %s\nLocal interface: http://%s\n", version, *listen)
	err = server.ListenAndServe()
	if err == http.ErrServerClosed {
		return nil
	}
	return err
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
