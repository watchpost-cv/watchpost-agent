//go:build windows

package service

import (
	"errors"
	"os"
)

// fileOwnerOK is a compile-time stub for non-Linux platforms. The service
// feature itself requires Linux systemd and is guarded before use; this keeps
// the package compiling on every release target.
func fileOwnerOK(os.FileInfo) error {
	return errors.New("service installation requires Linux systemd")
}