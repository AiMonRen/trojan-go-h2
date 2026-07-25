package webserver

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestInternalTokenLoadOrCreateRoundtrip(t *testing.T) {
	root := t.TempDir()
	tokenPath := filepath.Join(root, "internal-token")

	token, err := LoadOrCreateInternalToken(tokenPath)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if len(token) != hex.EncodedLen(internalTokenBytes) {
		t.Fatalf("token length %d != expected %d", len(token), hex.EncodedLen(internalTokenBytes))
	}

	info, err := os.Stat(tokenPath)
	if err != nil {
		t.Fatalf("stat token file: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("wrong permissions: %o", info.Mode().Perm())
	}

	reloaded, err := LoadOrCreateInternalToken(tokenPath)
	if err != nil {
		t.Fatalf("reload token: %v", err)
	}
	if reloaded != token {
		t.Fatalf("token changed: %q != %q", reloaded, token)
	}
}

func TestInternalTokenRejectsTooShort(t *testing.T) {
	root := t.TempDir()
	short := filepath.Join(root, "short-token")
	if err := os.WriteFile(short, []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreateInternalToken(short); err == nil {
		t.Fatal("expected rejection of short token")
	}
}

func TestReadInternalTokenRoundtrip(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "read-token")
	created, err := LoadOrCreateInternalToken(path)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadInternalToken(path)
	if err != nil {
		t.Fatal(err)
	}
	if read != created {
		t.Fatalf("ReadInternalToken: %q != %q", read, created)
	}
}

func TestReadInternalTokenRejectsMissingFile(t *testing.T) {
	if _, err := ReadInternalToken("/no/such/token/path"); err == nil {
		t.Fatal("expected rejection of missing path")
	}
}
