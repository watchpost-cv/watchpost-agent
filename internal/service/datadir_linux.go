//go:build linux

package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Descriptor-relative data-directory establishment. The validated parent is
// opened as a directory descriptor with a component-by-component no-symlink
// walk; the final leaf is created, bound, chmod'd, chown'd and inspected all
// relative to that same descriptor, so a concurrent pathname swap cannot
// redirect the privileged mutation to an unrelated or protected location.

var (
	openDataParentSeam       = openDataParentReal
	dataParentConsistentSeam = dataParentConsistentReal
	statDataLeafSeam         = statDataLeafReal
	mkdirAtLeafSeam          = mkdirAtLeafReal
	openAtLeafSeam           = openAtLeafReal
	fchmodLeafSeam           = fchmodLeafReal
	fchownLeafSeam           = fchownLeafReal
	fstatLeafSeam            = fstatLeafReal
	unlinkAtSeam             = unlinkAtLeafReal
	closeFdSeam              = closeFdReal
)

// inspectDataDir performs the NON-MUTATING data-path preflight: it opens the
// parent chain of the requested directory without following any symlink,
// inspects the final leaf relative to the retained parent descriptor, and
// classifies the directory as an acceptable fresh leaf or an acceptable
// existing service-owned leaf, or refuses it. It never creates, chmods or
// chowns anything, and it refuses an existing directory it cannot prove is
// service-owned (including when the service account does not yet exist) rather
// than creating the account first just to discover the directory is unsuitable.
func inspectDataDir(path string) (dataDirPlan, error) {
	parent := filepath.Dir(path)
	fd, pe := openDataParentSeam(parent)
	if pe != nil {
		return dataDirPlan{}, fmt.Errorf("data directory %q: %v", path, pe)
	}
	leafName := filepath.Base(path)
	info, le := statDataLeafSeam(fd, leafName)
	if errors.Is(le, os.ErrNotExist) {
		return dataDirPlan{status: dataDirAcceptFresh, parentFd: fd, leafName: leafName, path: path}, nil
	}
	if le != nil {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: %v", path, le)
	}
	if info.isSymlink {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q must not be a symlink", path)
	}
	if !info.isDir {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q is not a directory", path)
	}
	if info.mode&0o022 != 0 {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q must not be group- or world-writable", path)
	}
	// Ownership must be validated against the service account. If the account
	// does not yet exist the directory cannot be shown to be service-owned and
	// is refused rather than adopted; the account is never created merely to
	// discover the directory is unsuitable.
	uid, ue := serviceUID()
	if ue != nil {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: cannot validate ownership (service account missing?): %v", path, ue)
	}
	if info.uid != uid {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q already exists and is owned by UID %d; the watchpost-agent service requires it to be owned by %s:%s with mode 0700. Move existing data under %s or re-home it; the installer will not adopt an existing directory", path, info.uid, ServiceUser, ServiceGroup, DefaultDataDir)
	}
	return dataDirPlan{status: dataDirAcceptExisting, parentFd: fd, leafName: leafName, path: path}, nil
}

// establishDataDir performs the MUTATION phase after inspectDataDir accepted the
// path. It first confirms the pathname still resolves to the retained parent
// descriptor (refusing an ancestor swap), then creates the final leaf relative
// to that descriptor (fresh) or normalizes its mode (existing). The retained
// descriptor is closed by the caller's plan.close().
func establishDataDir(plan *dataDirPlan) error {
	if !dataParentConsistentSeam(plan.parentFd, plan.path) {
		return fmt.Errorf("data directory %q: parent changed after validation; refusing", plan.path)
	}
	if plan.status == dataDirAcceptFresh {
		return establishFreshLeaf(plan.parentFd, plan.leafName, plan.path)
	}
	// Existing leaf: normalize mode 0700 relative to the validated parent.
	leafFd, oe := openAtLeafSeam(plan.parentFd, plan.leafName)
	if oe != nil {
		return fmt.Errorf("data directory %q: open existing leaf: %v", plan.path, oe)
	}
	defer closeFdSeam(leafFd)
	if e := fchmodLeafSeam(leafFd); e != nil {
		return fmt.Errorf("data directory %q: set mode 0700: %w", plan.path, e)
	}
	return nil
}

// establishFreshLeaf creates the final leaf below the retained parent descriptor
// (mkdirat), binds a descriptor to the created entry without following symlinks,
// applies mode 0700 and service ownership via that leaf descriptor, and inspects
// the result relative to the same descriptor. On any failure it removes the
// partial leaf via the parent descriptor and reports the cleanup result, never
// silently claiming success.
func establishFreshLeaf(parentFd int, name, path string) error {
	if e := mkdirAtLeafSeam(parentFd, name); e != nil {
		return fmt.Errorf("data directory %q: create leaf: %w", path, e)
	}
	leafFd, oe := openAtLeafSeam(parentFd, name)
	if oe != nil {
		return cleanupLeafError(path, fmt.Errorf("bind created leaf: %v", oe), parentFd, name)
	}
	if e := fchmodLeafSeam(leafFd); e != nil {
		closeFdSeam(leafFd)
		return cleanupLeafError(path, fmt.Errorf("set mode 0700: %v", e), parentFd, name)
	}
	if e := fchownLeafSeam(leafFd); e != nil {
		closeFdSeam(leafFd)
		return cleanupLeafError(path, fmt.Errorf("set service ownership: %v", e), parentFd, name)
	}
	if _, e := fstatLeafSeam(leafFd); e != nil {
		closeFdSeam(leafFd)
		return cleanupLeafError(path, fmt.Errorf("inspect created leaf: %v", e), parentFd, name)
	}
	closeFdSeam(leafFd)
	return nil
}

// cleanupLeafError removes a partially established leaf via the parent
// descriptor and returns an error that reports the cleanup result.
func cleanupLeafError(path string, cause error, parentFd int, name string) error {
	if e := unlinkAtSeam(parentFd, name); e != nil {
		return fmt.Errorf("data directory %q: %v; partial leaf cleanup incomplete: %v", path, cause, e)
	}
	return fmt.Errorf("data directory %q: %v; partial leaf removed", path, cause)
}

// openDataParentReal walks the existing parent chain of leafPath component by
// component with O_DIRECTORY|O_NOFOLLOW, refusing any symlink ancestor, and
// returns the retained descriptor of the validated parent directory. leafPath
// is the leaf's parent directory (the directory that will contain the leaf).
func openDataParentReal(leafPath string) (int, error) {
	dir := filepath.Clean(leafPath)
	if !filepath.IsAbs(dir) {
		return -1, fmt.Errorf("parent %q must be an absolute path", dir)
	}
	fd, e := unix.Open("/", unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return -1, fmt.Errorf("cannot open root: %w", e)
	}
	for _, comp := range strings.Split(dir, "/") {
		if comp == "" || comp == "." {
			continue
		}
		nfd, oe := unix.Openat(fd, comp, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if oe != nil {
			closeFdReal(fd)
			switch {
			case oe == unix.ELOOP:
				return -1, fmt.Errorf("parent %q contains a symlink at %q; refusing symlinked service-data ancestry", dir, comp)
			case oe == unix.ENOENT:
				return -1, fmt.Errorf("parent %q does not exist; create the parent hierarchy first", dir)
			default:
				return -1, fmt.Errorf("cannot open parent %q: %w", dir, oe)
			}
		}
		closeFdReal(fd)
		fd = nfd
	}
	return fd, nil
}

// dataParentConsistentReal reports whether the pathname leafPath still resolves
// to the retained parent descriptor, detecting an ancestor swap between
// inspection and establishment.
func dataParentConsistentReal(fd int, leafPath string) bool {
	var fdStat unix.Stat_t
	if e := unix.Fstat(fd, &fdStat); e != nil {
		return false
	}
	resolved, e := filepath.EvalSymlinks(filepath.Dir(leafPath))
	if e != nil {
		return false
	}
	var st unix.Stat_t
	if e := unix.Stat(resolved, &st); e != nil {
		return false
	}
	return st.Dev == fdStat.Dev && st.Ino == fdStat.Ino
}

// statDataLeafReal inspects the final leaf below the parent descriptor without
// following a symlink (AT_SYMLINK_NOFOLLOW). A missing leaf surfaces os.ErrNotExist.
func statDataLeafReal(fd int, name string) (dataLeafInfo, error) {
	var st unix.Stat_t
	if e := unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW); e != nil {
		return dataLeafInfo{}, e
	}
	return statToInfo(&st), nil
}

func statToInfo(st *unix.Stat_t) dataLeafInfo {
	return dataLeafInfo{
		isDir:     st.Mode&unix.S_IFMT == unix.S_IFDIR,
		isSymlink: st.Mode&unix.S_IFMT == unix.S_IFLNK,
		mode:      os.FileMode(st.Mode & 0o7777),
		uid:       int(st.Uid),
	}
}

func mkdirAtLeafReal(fd int, name string) error { return unix.Mkdirat(fd, name, 0o700) }

func openAtLeafReal(fd int, name string) (int, error) {
	return unix.Openat(fd, name, unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

func fchmodLeafReal(fd int) error { return unix.Fchmod(fd, 0o700) }

func fchownLeafReal(fd int) error {
	uid, gid, e := lookupServiceIDs()
	if e != nil {
		return e
	}
	return unix.Fchown(fd, uid, gid)
}

func fstatLeafReal(fd int) (dataLeafInfo, error) {
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return dataLeafInfo{}, e
	}
	return statToInfo(&st), nil
}

func unlinkAtLeafReal(fd int, name string) error {
	return unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
}

func closeFdReal(fd int) error { return unix.Close(fd) }
