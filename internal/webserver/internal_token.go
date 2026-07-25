package webserver

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/voidluo/trojan-go/internal/secretfile"
)

// DefaultInternalTokenPath is the well-known path for the shared
// internal API token used to authenticate loopback service-to-service
// calls (e.g., control-service → admin-service). It is a var (not a const)
// solely so tests can redirect it to a writable temp directory; production
// code never mutates it.
var DefaultInternalTokenPath = "/var/lib/trojan-go/internal-token"

// internalTokenBytes is the number of random bytes in the token.
const internalTokenBytes = 32

// LoadOrCreateInternalToken reads the existing file at tokenPath, or
// generates a fresh hex-encoded crypto/rand token, atomically writes it,
// and returns the value. The file is created with mode 0600.
func LoadOrCreateInternalToken(tokenPath string) (string, error) {
	// L-06: read through secretfile so an existing token is only accepted from
	// a non-symlink, owner-only, correctly owned regular file.
	data, err := secretfile.Read(tokenPath)
	if err == nil {
		token := string(data)
		if len(token) < 16 {
			return "", fmt.Errorf("internal token file %s is too short (%d bytes)", tokenPath, len(token))
		}
		return token, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("read internal token file %s: %w", tokenPath, err)
	}
	raw := make([]byte, internalTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate internal token: %w", err)
	}
	token := hex.EncodeToString(raw)

	parent := filepath.Dir(tokenPath)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return "", fmt.Errorf("create internal token directory %s: %w", parent, err)
	}
	tmp, err := os.CreateTemp(parent, ".internal-token-*")
	if err != nil {
		return "", fmt.Errorf("create internal token temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := tmp.WriteString(token); err != nil {
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpPath, tokenPath); err != nil {
		return "", err
	}
	committed = true
	return token, nil
}

// ReadInternalToken reads the token from the given path and returns it.
// The token must be at least 16 characters.
func ReadInternalToken(tokenPath string) (string, error) {
	// L-06: same hardened read path as LoadOrCreateInternalToken.
	data, err := secretfile.Read(tokenPath)
	if err != nil {
		return "", fmt.Errorf("read internal token file %s: %w", tokenPath, err)
	}
	token := string(data)
	if len(token) < 16 {
		return "", fmt.Errorf("internal token file %s is too short (%d bytes)", tokenPath, len(token))
	}
	return token, nil
}
