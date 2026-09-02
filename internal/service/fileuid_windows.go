//go:build windows

package service

import "os"

// fileUID is a stub for non-Linux platforms. Service management is Linux-only
// (requireLinux), so ownership checks never run here; returning 0 keeps the
// package compilable across the release matrix.
var fileUID = func(os.FileInfo) int { return 0 }
