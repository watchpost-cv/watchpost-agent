//go:build unix

package state

import (
	"errors"
	"os"
	"syscall"
)

// preserveFileOwnership ensures a freshly written state file is owned by the
// owning user/group of its data directory and that the data directory itself
// stays owner-only. This keeps durable state readable and writable by the
// systemd service account even when an administrative CLI (pair, pair-status,
// configure, rotate, unpair, reset, update) is invoked as root: without this,
// the atomic-replace temp file would be created root-owned and the service
// could no longer open agent.json.
func preserveFileOwnership(dataDir, path string) error {
	if err := os.Chmod(dataDir, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
		return err
	}
	dirInfo, err := os.Stat(dataDir)
	if err != nil {
		return err
	}
	dirStat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return err
	}
	fileStat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if fileStat.Uid == dirStat.Uid && fileStat.Gid == dirStat.Gid {
		return nil
	}
	return os.Chown(path, int(dirStat.Uid), int(dirStat.Gid))
}
