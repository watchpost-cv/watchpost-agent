//go:build !windows

package service

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// fileOwnerOK verifies that a file or directory used by the user-mode service
// is owned by the invoking user, so systemd (running as that user) can read it
// and another user cannot swap it.
func fileOwnerOK(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot determine file ownership")
	}
	if int(stat.Uid) != os.Getuid() {
		return fmt.Errorf("must be owned by the invoking user")
	}
	return nil
}