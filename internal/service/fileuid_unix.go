//go:build !windows

package service

import (
	"os"
	"syscall"
)

// fileUID returns the numeric owning UID of a file or directory. It is a
// variable so tests can simulate root-owned versus service-account-owned
// files without requiring real chown privileges.
var fileUID = func(info os.FileInfo) int {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return -1
	}
	return int(st.Uid)
}
