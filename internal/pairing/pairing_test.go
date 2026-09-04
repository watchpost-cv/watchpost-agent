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
