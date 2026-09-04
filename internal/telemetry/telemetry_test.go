package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/watchpost-cv/watchpost-agent/internal/state"
)

func TestFailedDeliverySurvivesRestart(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "offline", http.StatusServiceUnavailable) }))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: server.URL, PostID: "host-one", Credential: "secret"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if Send(context.Background(), store) == nil {
		t.Fatal("expected delivery failure")
	}
	before := store.Snapshot()
	if len(before.Delivery.Queue) != 1 || before.NextSequence <= 1 || before.Delivery.LastError == "" {
		t.Fatalf("queue not retained: %#v", before.Delivery)
	}
	if err = Send(context.Background(), store); err != nil {
		t.Fatalf("collect during backoff: %v", err)
	}
	before = store.Snapshot()
	if len(before.Delivery.Queue) != 2 {
		t.Fatalf("backoff stopped durable collection: queued=%d", len(before.Delivery.Queue))
	}
	reopened, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	after := reopened.Snapshot()
	if len(after.Delivery.Queue) != 2 || after.NextSequence != before.NextSequence {
		t.Fatal("queue or sequence did not survive restart")
	}
}
