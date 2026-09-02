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
// walk. For an EXISTING leaf, the leaf is opened and its descriptor retained
// during inspection so the object validated is the exact object later mutated.
// For a FRESH leaf, the parent must satisfy a safe-parent contract (root-owned,
// not group/world-writable) so the leaf created under it cannot be replaced by
// an untrusted writer between mkdirat and bind. All mutation and cleanup is
// relative to the retained descriptors, never re-looked-up by pathname.

var (
	openDataParentSeam       = openDataParentReal
	dataParentConsistentSeam = dataParentConsistentReal
	parentSafeSeam           = parentSafeReal
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
// validates the parent against the safe-parent contract, and for an existing
// leaf opens and retains the leaf descriptor so the object validated is the
// object that establishment will mutate. It never creates, chmods or chowns
// anything, and it refuses an existing directory it cannot prove is
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
		if e := parentSafeSeam(fd); e != nil {
			closeFdSeam(fd)
			return dataDirPlan{}, fmt.Errorf("data directory %q: %v", path, e)
		}
		return dataDirPlan{status: dataDirAcceptFresh, parentFd: fd, leafFd: -1, leafName: leafName, path: path}, nil
	}
	if le != nil {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: %v", path, le)
	}
	if info.isSymlink {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q must not be a symlink", path)
	}
	// Open and RETAIN the leaf descriptor during inspection so the object
	// validated is the exact object mutated later (never re-looked-up by name).
	leafFd, oe := openAtLeafSeam(fd, leafName)
	if oe != nil {
		closeFdSeam(fd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: open existing leaf: %v", path, oe)
	}
	linfo, fe := fstatLeafSeam(leafFd)
	if fe != nil {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: fstat existing leaf: %v", path, fe)
	}
	if !linfo.isDir {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q is not a directory", path)
	}
	if linfo.mode&0o022 != 0 {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q must not be group- or world-writable", path)
	}
	uid, ue := serviceUID()
	if ue != nil {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: cannot validate ownership (service account missing?): %v", path, ue)
	}
	if linfo.uid != uid {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q already exists and is owned by UID %d; the watchpost-agent service requires it to be owned by %s:%s with mode 0700. Move existing data under %s or re-home it; the installer will not adopt an existing directory", path, linfo.uid, ServiceUser, ServiceGroup, DefaultDataDir)
	}
	if e := parentSafeSeam(fd); e != nil {
		closeFdSeam(fd)
		closeFdSeam(leafFd)
		return dataDirPlan{}, fmt.Errorf("data directory %q: %v", path, e)
	}
	return dataDirPlan{status: dataDirAcceptExisting, parentFd: fd, leafFd: leafFd, leafName: leafName, path: path}, nil
}

// establishDataDir performs the MUTATION phase after inspectDataDir accepted the
// path. It first confirms the pathname still resolves to the retained parent
// descriptor (refusing an ancestor swap). For an existing leaf it normalizes
// mode 0700 on the RETAINED leaf descriptor; for a fresh leaf it creates,
// binds, chmods and chowns the leaf below the retained parent descriptor. The
// retained descriptors are closed by the caller's plan.close().
func establishDataDir(plan *dataDirPlan) error {
	if !dataParentConsistentSeam(plan.parentFd, plan.path) {
		return fmt.Errorf("data directory %q: parent changed after validation; refusing", plan.path)
	}
	if plan.status == dataDirAcceptFresh {
		return establishFreshLeaf(plan.parentFd, plan.leafName, plan.path)
	}
	// Existing leaf: normalize mode 0700 via the RETAINED leaf descriptor, never
	// re-looked-up by name, so a concurrent replacement is never chmod'd.
	if e := fchmodLeafSeam(plan.leafFd); e != nil {
		return fmt.Errorf("data directory %q: set mode 0700: %w", plan.path, e)
	}
	return nil
}

// establishFreshLeaf creates the final leaf below the retained parent descriptor
// (mkdirat), binds a descriptor to the created entry without following symlinks,
// applies mode 0700 and service ownership via that leaf descriptor, and inspects
// the result relative to the same descriptor. The parent safe-parent contract is
// re-verified immediately before creation so an untrusted writer cannot replace
// the freshly created leaf between mkdirat and bind. On any failure it removes
// the partial leaf via the parent descriptor and reports the cleanup result,
// never silently claiming success.
func establishFreshLeaf(parentFd int, name, path string) error {
	if e := parentSafeSeam(parentFd); e != nil {
		return fmt.Errorf("data directory %q: %v", path, e)
	}
	if e := mkdirAtLeafSeam(parentFd, name); e != nil {
		return fmt.Errorf("data directory %q: create leaf: %w", path, e)
	}
	leafFd, oe := openAtLeafSeam(parentFd, name)
	if oe != nil {
		return cleanupLeafError(path, fmt.Errorf("bind created leaf: %v", oe), parentFd, name)
	}
	linfo, fe := fstatLeafSeam(leafFd)
	if fe != nil {
		closeFdSeam(leafFd)
		return cleanupLeafError(path, fmt.Errorf("inspect created leaf: %v", fe), parentFd, name)
	}
	// Verify the bound entry is the expected freshly created directory: a
	// directory with the mode mkdirat requested (0700). A concurrent replacement
	// (even another ordinary directory) is detected here and refused, so the
	// replacement is never chmod'd or chown'd.
	if !linfo.isDir || linfo.isSymlink || linfo.mode != 0o700 {
		closeFdSeam(leafFd)
		return cleanupLeafError(path, fmt.Errorf("created leaf identity mismatch (mode %o, dir %v, symlink %v)", linfo.mode, linfo.isDir, linfo.isSymlink), parentFd, name)
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
		return cleanupLeafError(path, fmt.Errorf("inspect established leaf: %v", e), parentFd, name)
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

// parentSafeReal validates the final parent used for service-data creation: it
// must be a root-owned directory that is neither group- nor world-writable, so
// an unprivileged user or the service account cannot rewrite it during
// installation (a freshly created leaf below it therefore cannot be replaced).
// This keeps canonical locations (/var/lib, /srv) safe while refusing custom
// parents an unprivileged writer could modify.
func parentSafeReal(fd int) error {
	var st unix.Stat_t
	if e := unix.Fstat(fd, &st); e != nil {
		return fmt.Errorf("cannot fstat parent descriptor: %w", e)
	}
	if int(st.Uid) != 0 {
		return fmt.Errorf("final data-directory parent is owned by UID %d; the installer requires a root-owned parent (e.g. /var/lib or /srv)", int(st.Uid))
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("final data-directory parent is group- or world-writable; the installer requires a root-owned, non-group/world-writable parent")
	}
	return nil
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
