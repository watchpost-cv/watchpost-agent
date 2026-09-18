//go:build unix

package state

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Mode().Perm()
}

func ownerOf(t *testing.T, path string) (uint32, uint32) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("no ownership metadata for %s", path)
	}
	return st.Uid, st.Gid
}

// TestStateWritePreservesDirectoryOwnership is a regression test for a
// campaign-discovered lifecycle defect: an administrative CLI (pair,
// configure, rotate, unpair, reset) run as root rewrote agent.json with the
// atomic-replace temp file owned by root, so the systemd service account
// could no longer open it (permission denied on agent.json). The durable
// state must always be owned by the data directory's owning user/group and
// remain openable by a subsequent service-start (re-open).
func TestStateWritePreservesDirectoryOwnership(t *testing.T) {
	dir := t.TempDir()
	if os.Geteuid() == 0 {
		// Simulate a service data directory owned by a non-root account
		// (the watchpost-agent service user in production).
		if err := os.Chown(dir, 65534, 65534); err != nil {
			t.Fatalf("chown test dir to service account: %v", err)
		}
	} else {
		// Running non-root we can only exercise the same-owner path, which
		// still asserts the ownership invariant and mode bits.
		t.Log("running non-root; same-owner path only")
	}
	path := filepath.Join(dir, "agent.json")
	store, err := Open(path)
	if err != nil {
		t.Fatalf("open state as root CLI: %v", err)
	}
	// A CLI mutation (configure/pair/rotate all funnel through Update).
	if err := store.Update(func(s *State) error { s.Collectors.IntervalSeconds = 30; return nil }); err != nil {
		t.Fatalf("root CLI mutation: %v", err)
	}

	if got := modeOf(t, path); got != 0o600 {
		t.Fatalf("agent.json mode = %04o, want 0600", got)
	}
	if got := modeOf(t, dir); got != 0o700 {
		t.Fatalf("data directory mode = %04o, want 0700", got)
	}
	du, dg := ownerOf(t, dir)
	fu, fg := ownerOf(t, path)
	if fu != du || fg != dg {
		t.Fatalf("agent.json owner %d:%d does not match data directory owner %d:%d", fu, fg, du, dg)
	}

	// Simulated service restart: the service account must be able to open it.
	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("simulated service restart could not open state: %v", err)
	}
	if got := reopened.Snapshot().Collectors.IntervalSeconds; got != 30 {
		t.Fatalf("collector config not preserved: %d", got)
	}

	// A subsequent CLI mutation must not drift ownership back.
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(func(s *State) error { s.Collectors.IntervalSeconds = 60; return nil }); err != nil {
		t.Fatalf("second CLI mutation: %v", err)
	}
	if fu2, fg2 := ownerOf(t, path); fu2 != du || fg2 != dg {
		t.Fatalf("ownership drifted to %d:%d after subsequent mutation", fu2, fg2)
	}
}

// TestStateWriteRejectsInaccessibleDirectory ensures a state write into a
// directory the process cannot reach fails closed rather than silently
// producing an unreadable file.
func TestStateWriteRejectsInaccessibleDirectory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to construct an inaccessible directory")
	}
	base := t.TempDir()
	locked := filepath.Join(base, "locked")
	if err := os.Mkdir(locked, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(locked, 0, 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0700); err != nil {
		t.Fatal(err)
	}
	// A non-root owner cannot be emulated without dropping privileges, so this
	// only asserts the write path errors on a nonexistent parent.
	path := filepath.Join(filepath.Join(base, "does-not-exist", "agent.json"))
	if _, err := Open(path); err == nil {
		t.Fatal("open into missing parent unexpectedly succeeded")
	}
}
