//go:build !linux

package service

import "errors"

// errDataDirUnsupported marks the non-Linux data-directory stubs. Install is
// Linux-gated, so these are never reached in practice; they exist so the
// cross-platform package compiles.
var errDataDirUnsupported = errors.New("data directory management is supported on Linux only")

var (
	openDataParentSeam       = func(string) (int, error) { return -1, errDataDirUnsupported }
	dataParentConsistentSeam = func(int, string) bool { return false }
	parentSafeSeam           = func(int) error { return errDataDirUnsupported }
	statDataLeafSeam         = func(int, string) (dataLeafInfo, error) { return dataLeafInfo{}, errDataDirUnsupported }
	mkdirAtLeafSeam          = func(int, string) error { return errDataDirUnsupported }
	openAtLeafSeam           = func(int, string) (int, error) { return -1, errDataDirUnsupported }
	fchmodLeafSeam           = func(int) error { return errDataDirUnsupported }
	fchownLeafSeam           = func(int) error { return errDataDirUnsupported }
	fstatLeafSeam            = func(int) (dataLeafInfo, error) { return dataLeafInfo{}, errDataDirUnsupported }
	unlinkAtSeam             = func(int, string) error { return errDataDirUnsupported }
	closeFdSeam              = func(int) error { return nil }
)

func inspectDataDir(string) (dataDirPlan, error) {
	return dataDirPlan{}, errDataDirUnsupported
}

func establishDataDir(*dataDirPlan) error { return errDataDirUnsupported }
