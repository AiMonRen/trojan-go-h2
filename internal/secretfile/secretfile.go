// Package secretfile reads files that hold secrets (credential keys, internal
// service tokens) with the checks such files require.
//
// L-06: the previous pattern was Lstat → ReadFile, which left a TOCTOU window
// where the path could be swapped for a symlink between the two calls, did not
// verify the owner, and did not pass O_NOFOLLOW. Read below opens the path once
// with O_NOFOLLOW and validates the already-open file descriptor with fstat, so
// the checked object and the read object are guaranteed to be the same inode.
package secretfile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// maxSecretSize bounds how much is read from a secret file so a hostile or
// corrupted path cannot exhaust memory.
const maxSecretSize = 1 << 20 // 1 MiB

// Read opens path without following symlinks and returns its contents after
// verifying that the open file is a regular file, is not group/world
// accessible, and is owned by root or by the current process user.
func Read(path string) ([]byte, error) {
	file, err := open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, maxSecretSize+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(data) > maxSecretSize {
		return nil, fmt.Errorf("%s is larger than the %d byte limit for secret files", path, maxSecretSize)
	}
	return data, nil
}

// DefaultPerm is the mode used for a sensitive file whose current mode cannot
// be determined (for example when it does not exist yet).
const DefaultPerm = os.FileMode(0o600)

// WriteAtomic replaces path with content without ever widening its permissions
// and without leaving a truncated file behind if the process dies mid-write.
//
// S-03: the CLI used to rewrite config.yaml with a hardcoded 0644, which was a
// one-way permission downgrade on a file holding proxy passwords — the
// installer had created it as 0600. WriteAtomic instead stats the existing
// file, reuses its mode (falling back to DefaultPerm), writes a temp file in
// the same directory, fsyncs it, and renames it into place. The rename is
// atomic on the same filesystem, so concurrent readers see either the old or
// the new content and never a partial write. The parent directory is synced
// afterwards so the replacement survives a crash.
func WriteAtomic(path string, content []byte) error {
	perm := DefaultPerm
	if info, err := os.Stat(path); err == nil {
		perm = info.Mode().Perm()
		// Never inherit a mode that exposes the file to other users. If the
		// file was already too permissive, tighten it rather than preserving
		// the mistake.
		if perm&0o077 != 0 {
			perm = DefaultPerm
		}
	}

	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".trojan-cfg-*")
	if err != nil {
		return fmt.Errorf("create temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmpPath)
		}
	}()

	if err := tmp.Chmod(perm); err != nil {
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if _, err := tmp.Write(content); err != nil {
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", tmpPath, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, path, err)
	}
	committed = true

	if dirFd, err := os.Open(dir); err == nil {
		_ = dirFd.Sync()
		_ = dirFd.Close()
	}
	return nil
}

// open performs the O_NOFOLLOW open plus the fstat-based validation. It is
// separated out so callers that need the descriptor itself can reuse it.
func open(path string) (*os.File, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		// ELOOP means the final path component is a symlink, which O_NOFOLLOW
		// refuses. Report it explicitly; the generic error text ("too many
		// levels of symbolic links") is misleading here.
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%s must be a regular file, not a symbolic link", path)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		file.Close()
		return nil, fmt.Errorf("%s must be a regular file, not %s", path, info.Mode().Type())
	}
	if info.Mode().Perm()&0o077 != 0 {
		file.Close()
		return nil, fmt.Errorf("%s must be accessible only by its owner (mode 0600)", path)
	}
	if err := checkOwner(path, info); err != nil {
		file.Close()
		return nil, err
	}
	return file, nil
}

// checkOwner rejects files owned by some other unprivileged user. Ownership by
// root is always accepted because the installer provisions these files as root.
func checkOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		// Unsupported platform for uid checks; the mode check above still
		// applies. Do not fail closed here, otherwise the service would refuse
		// to start on any OS without Stat_t.
		return nil
	}
	owner := uint64(stat.Uid)
	if owner == 0 {
		return nil
	}
	if current := uint64(os.Getuid()); owner != current {
		return fmt.Errorf("%s is owned by uid %d, expected root or the service user (uid %d)", path, owner, current)
	}
	return nil
}
