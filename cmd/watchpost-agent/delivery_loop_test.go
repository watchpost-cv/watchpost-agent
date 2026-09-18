package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

// TestDeliveryLoopObservesCrossProcessPairing reproduces the campaign finding
// where pairing is completed by the separate `watchpost-agent pair-status` CLI
// (a different process that writes agent.json) while the service's delivery
// loop is already running. Without reloading agent.json each cycle the running
// loop would keep seeing "agent is not paired" and never deliver telemetry
// until a restart.
func TestDeliveryLoopObservesCrossProcessPairing(t *testing.T) {
	delivered := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered <- struct{}{}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	store.Update(func(value *state.State) error {
		value.Collectors = state.CollectorConfig{IntervalSeconds: 15, CPU: true, Memory: true, Load: true, Uptime: true, Filesystems: []string{"/"}}
		return nil
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		deliveryLoop(ctx, store)
		close(done)
	}()

	// A "separate process" pairs by reopening the same agent.json (exactly what
	// the pair-status CLI does) and writing the approved connection.
	external, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = external.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: server.URL, PostID: "host-one", Credential: "secret"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-delivered:
	case <-time.After(25 * time.Second):
		t.Fatal("delivery loop never observed the cross-process pairing")
	}
	cancel()
	<-done
}
