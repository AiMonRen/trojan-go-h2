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
