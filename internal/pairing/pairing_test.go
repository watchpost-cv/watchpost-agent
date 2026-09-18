package pairing

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

func TestUnpairClearsStateAfterServerRevocation(t *testing.T) {
	var sawAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/v2/unpair" {
			http.NotFound(w, r)
			return
		}
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	store := openStore(t)
	store.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: server.URL, PostID: "post-a", Credential: "active-credential"}
		return nil
	})
	client := New(store, "test")
	if err := client.Unpair(context.Background(), "cli"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sawAuth, "Bearer active-credential") {
		t.Fatalf("unpair did not authenticate: %q", sawAuth)
	}
	current := store.Snapshot()
	if current.Connection.Credential != "" || current.Connection.RevocationPending {
		t.Fatalf("local state not cleared after confirmed revocation: %#v", current.Connection)
	}
}

func TestUnpairMarksRevocationPendingWhenServerUnreachable(t *testing.T) {
	store := openStore(t)
	store.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: "http://127.0.0.1:1", PostID: "post-a", Credential: "active-credential"}
		return nil
	})
	client := New(store, "test")
	err := client.Unpair(context.Background(), "cli")
	if err == nil {
		t.Fatal("unpair succeeded against an unreachable server")
	}
	current := store.Snapshot()
	if !current.Connection.RevocationPending || current.Connection.Credential == "" {
		t.Fatalf("revocation pending not recorded: %#v", current.Connection)
	}
}

func TestRetryPendingRevocationCompletes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	store := openStore(t)
	store.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: server.URL, PostID: "post-a", Credential: "active-credential", RevocationPending: true}
		return nil
	})
	client := New(store, "test")
	if err := client.RetryPendingRevocation(context.Background(), "cli"); err != nil {
		t.Fatal(err)
	}
	current := store.Snapshot()
	if current.Connection.Credential != "" || current.Connection.RevocationPending {
		t.Fatalf("pending revocation not completed: %#v", current.Connection)
	}
}

func openStore(t *testing.T) *state.Store {
	t.Helper()
	store, err := state.Open(filepath.Join(t.TempDir(), "agent.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {})
	return store
}

func TestPairingTransportGuard(t *testing.T) {
	store := openStore(t)
	client := New(store, "test")
	// Default: non-loopback HTTP rejected; HTTPS and loopback HTTP accepted.
	if err := client.allowServer("http://remote.example"); err == nil {
		t.Fatal("non-loopback http accepted by default")
	}
	if err := client.allowServer("https://remote.example"); err != nil {
		t.Fatalf("https rejected: %v", err)
	}
	if err := client.allowServer("http://127.0.0.1:9"); err != nil {
		t.Fatalf("loopback http rejected: %v", err)
	}
	if err := client.allowServer("http://localhost:9"); err != nil {
		t.Fatalf("localhost http rejected: %v", err)
	}
	// Explicit plaintext: non-loopback HTTP accepted.
	client.SetInsecurePlaintext(true)
	if err := client.allowServer("http://remote.example"); err != nil {
		t.Fatalf("http rejected in explicit plaintext mode: %v", err)
	}
	// Request-level default: a remote HTTP Watchpost is rejected before any
	// network call.
	if _, err := New(store, "test").Request(context.Background(), "http://remote.example", "cli"); err == nil || !strings.Contains(err.Error(), "HTTPS is required") {
		t.Fatalf("http pairing request accepted by default (err=%v)", err)
	}
}
