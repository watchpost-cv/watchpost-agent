package telemetry

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

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

func TestConcurrentEnqueueAssignsDisjointSequences(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Update(func(value *state.State) error {
		value.Connection = state.Connection{WatchpostURL: "https://watchpost.test", PostID: "host-one", Credential: "secret"}
		value.Collectors = state.CollectorConfig{IntervalSeconds: 60, CPU: false, Memory: true, Load: false, Uptime: false, Filesystems: []string{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	const senders = 16
	var wg sync.WaitGroup
	for i := 0; i < senders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = enqueue(store, snapshot)
		}()
	}
	wg.Wait()
	after := store.Snapshot()
	if len(after.Delivery.Queue) != senders {
		t.Fatalf("expected %d queued batches, got %d", senders, len(after.Delivery.Queue))
	}
	// Every queued batch must occupy a distinct, non-overlapping sequence range.
	seen := map[int64]bool{}
	for _, raw := range after.Delivery.Queue {
		var batch Batch
		if err := json.Unmarshal(raw, &batch); err != nil {
			t.Fatal(err)
		}
		for _, sample := range batch.Samples {
			if seen[sample.Sequence] {
				t.Fatalf("duplicate sequence %d across concurrent enqueues", sample.Sequence)
			}
			seen[sample.Sequence] = true
		}
	}
	// Memory-only collector produces memory.percent plus collector.up per batch;
	// the first batch starts at sequence 1.
	const metricsPerBatch = 2
	if after.NextSequence != 1+int64(senders*metricsPerBatch) {
		t.Fatalf("next_sequence=%d want %d", after.NextSequence, 1+int64(senders*metricsPerBatch))
	}
}

func TestFlushDropsStaleHeadBatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("stale batch must be dropped before delivery")
	}))
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
	stale := Batch{Version: 1, PostID: "host-one", CollectorID: store.Snapshot().InstallationID, BatchID: "agent-stale", SentAt: time.Now().UTC().Add(-25 * time.Hour), Samples: []Sample{{Sequence: 1, ObservedAt: time.Now().UTC().Add(-25 * time.Hour), Signal: "collector.up", Value: ptr(1.0), Unit: "boolean", Quality: "good", Labels: map[string]string{}}}}
	body, err := json.Marshal(stale)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Update(func(value *state.State) error {
		value.Delivery.Queue = append(value.Delivery.Queue, json.RawMessage(body))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err = flush(context.Background(), store); err != nil {
		t.Fatalf("flush with stale head must converge: %v", err)
	}
	after := store.Snapshot()
	if len(after.Delivery.Queue) != 0 {
		t.Fatalf("stale batch not dropped: queued=%d", len(after.Delivery.Queue))
	}
	if after.Delivery.DroppedCollections != 1 {
		t.Fatalf("dropped_collections=%d want 1", after.Delivery.DroppedCollections)
	}
}

func ptr(value float64) *float64 { return &value }
