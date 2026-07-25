package secretfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// L-06 regression coverage: the reader must refuse symlinks, non-regular files,
// group/world-accessible modes and foreign owners, and must not follow a
// symlink even when the target itself is a valid secret file.

func writeSecret(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}
	return path
}

func TestReadAcceptsOwnerOnlyRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "token", "s3cret-token-value", 0o600)

	data, err := Read(path)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(data) != "s3cret-token-value" {
		t.Fatalf("Read returned %q", data)
	}
}

func TestReadRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := writeSecret(t, dir, "real-token", "s3cret-token-value", 0o600)
	link := filepath.Join(dir, "linked-token")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	_, err := Read(link)
	if err == nil {
		t.Fatal("Read must refuse a symlink even when the target is valid")
	}
	if !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("expected a symlink-specific error, got %v", err)
	}
}

func TestReadRejectsWorldReadableMode(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "token", "s3cret-token-value", 0o644)

	if _, err := Read(path); err == nil {
		t.Fatal("Read must refuse a world-readable secret file")
	}
}

func TestReadRejectsGroupReadableMode(t *testing.T) {
	dir := t.TempDir()
	path := writeSecret(t, dir, "token", "s3cret-token-value", 0o640)

	if _, err := Read(path); err == nil {
		t.Fatal("Read must refuse a group-readable secret file")
	}
}

func TestReadRejectsDirectory(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "not-a-file")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	if _, err := Read(sub); err == nil {
		t.Fatal("Read must refuse a directory")
	}
}

func TestReadMissingFileReportsNotExist(t *testing.T) {
	dir := t.TempDir()

	_, err := Read(filepath.Join(dir, "absent"))
	if err == nil {
		t.Fatal("Read must fail for a missing file")
	}
	// Callers distinguish "not provisioned yet" from "unsafe", so the sentinel
	// must survive wrapping.
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got %v", err)
	}
}

func TestReadRejectsOversizedFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "huge")
	if err := os.WriteFile(path, make([]byte, maxSecretSize+1), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := Read(path); err == nil {
		t.Fatal("Read must refuse a file larger than the secret size limit")
	}
}

// TestWriteAtomicPreservesMode covers S-03: rewriting a sensitive config must
// never widen its permissions.
func TestWriteAtomicPreservesMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}

	if err := WriteAtomic(path, []byte("new")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != "new" {
		t.Fatalf("content = %q, want %q", data, "new")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode = %o, want 600", got)
	}
	// No temp files may be left behind on the happy path.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("directory holds %d entries, want only the config file", len(entries))
	}
}

// TestWriteAtomicTightensLooseMode: an already world-readable config must not
// have that mistake preserved, and a brand new file defaults to 0600.
func TestWriteAtomicTightensLooseMode(t *testing.T) {
	dir := t.TempDir()

	loose := filepath.Join(dir, "loose.yaml")
	if err := os.WriteFile(loose, []byte("old"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := WriteAtomic(loose, []byte("new")); err != nil {
		t.Fatalf("WriteAtomic: %v", err)
	}
	info, err := os.Stat(loose)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != DefaultPerm {
		t.Fatalf("mode = %o, want %o", got, DefaultPerm)
	}

	fresh := filepath.Join(dir, "fresh.yaml")
	if err := WriteAtomic(fresh, []byte("new")); err != nil {
		t.Fatalf("WriteAtomic on new path: %v", err)
	}
	info, err = os.Stat(fresh)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != DefaultPerm {
		t.Fatalf("new file mode = %o, want %o", got, DefaultPerm)
	}
}
