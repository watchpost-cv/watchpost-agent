//go:build linux || darwin

package telemetry

import "syscall"

func filesystemPercent(path string) (float64, error) {
	var disk syscall.Statfs_t
	if err := syscall.Statfs(path, &disk); err != nil {
		return 0, err
	}
	if disk.Blocks == 0 {
		return 0, nil
	}
	return 100 * (float64(disk.Blocks) - float64(disk.Bfree)) / float64(disk.Blocks), nil
}
