//go:build !unix

package state

// preserveFileOwnership is a no-op on platforms without Unix ownership
// semantics (for example Windows, where the agent's systemd service model
// does not apply).
func preserveFileOwnership(dataDir, path string) error { return nil }
