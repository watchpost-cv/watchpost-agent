//go:build unix

package main

import (
	"fmt"
	"os"
	"syscall"
)

func restoreFileOwner(path string, prior os.FileInfo) error {
	stat, ok := prior.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("cannot determine prior file owner")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}
