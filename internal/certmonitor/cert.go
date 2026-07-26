package certmonitor

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CertificateNeedsRenewal returns true when the certificate at certificatePath
// expires within the given duration from now.
func CertificateNeedsRenewal(certificatePath string, before time.Duration, now time.Time) (bool, error) {
	data, err := os.ReadFile(certificatePath)
	if err != nil {
		return false, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return false, fmt.Errorf("certificate is not PEM encoded")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	return !certificate.NotAfter.After(now.Add(before)), nil
}

// WriteCertificateFiles atomically installs a certificate/key pair using a
// versioned directory plus a single symlink switch, so a crash can never leave
// a mismatched (new cert, old key) pair on disk.
//
// Layout for a target such as <dir>/example.com.crt / <dir>/example.com.key:
//
//	<dir>/.certstore/<serial>/cert.pem   # this version's certificate
//	<dir>/.certstore/<serial>/key.pem    # this version's key (same dir -> one unit)
//	<dir>/.certstore/current   -> <serial>   # single pointer, switched atomically
//	<dir>/example.com.crt      -> .certstore/current/cert.pem  # stable, never re-pointed
//	<dir>/example.com.key      -> .certstore/current/key.pem   # stable, never re-pointed
func WriteCertificateFiles(certificatePath, privateKeyPath string, certificatePEM, privateKeyPEM []byte) error {
	if _, err := tls.X509KeyPair(certificatePEM, privateKeyPEM); err != nil {
		return fmt.Errorf("certificate and private key do not form a valid pair: %w", err)
	}

	certDir := filepath.Dir(certificatePath)
	if err := os.MkdirAll(certDir, 0755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	store := filepath.Join(certDir, ".certstore")
	if err := os.MkdirAll(store, 0755); err != nil {
		return fmt.Errorf("create certificate store: %w", err)
	}

	versionDir, err := os.MkdirTemp(store, "v-")
	if err != nil {
		return fmt.Errorf("create certificate version directory: %w", err)
	}
	cleanupVersion := true
	defer func() {
		if cleanupVersion {
			_ = os.RemoveAll(versionDir)
		}
	}()
	if err := os.WriteFile(filepath.Join(versionDir, "cert.pem"), certificatePEM, 0644); err != nil {
		return fmt.Errorf("write versioned certificate: %w", err)
	}
	if err := os.WriteFile(filepath.Join(versionDir, "key.pem"), privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("write versioned key: %w", err)
	}
	if err := syncDir(versionDir); err != nil {
		return fmt.Errorf("sync certificate version directory: %w", err)
	}

	if err := atomicSwapSymlink(store, filepath.Base(versionDir), "current"); err != nil {
		return fmt.Errorf("switch current certificate version: %w", err)
	}
	cleanupVersion = false

	if err := ensureCertSymlink(certificatePath, filepath.Join(".certstore", "current", "cert.pem")); err != nil {
		return fmt.Errorf("link certificate path: %w", err)
	}
	if err := ensureCertSymlink(privateKeyPath, filepath.Join(".certstore", "current", "key.pem")); err != nil {
		return fmt.Errorf("link private key path: %w", err)
	}

	pruneOldCertVersions(store, filepath.Base(versionDir))
	return nil
}

func atomicSwapSymlink(dir, target, linkName string) error {
	tmpLink := filepath.Join(dir, "."+linkName+"-staged")
	_ = os.Remove(tmpLink)
	if err := os.Symlink(target, tmpLink); err != nil {
		return err
	}
	if err := os.Rename(tmpLink, filepath.Join(dir, linkName)); err != nil {
		_ = os.Remove(tmpLink)
		return err
	}
	return syncDir(dir)
}

func ensureCertSymlink(path, target string) error {
	if current, err := os.Readlink(path); err == nil && current == target {
		return nil
	}
	dir := filepath.Dir(path)
	tmp := filepath.Join(dir, "."+filepath.Base(path)+"-staged")
	_ = os.Remove(tmp)
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return syncDir(dir)
}

func pruneOldCertVersions(store, keep string) {
	entries, err := os.ReadDir(store)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || entry.Name() == keep {
			continue
		}
		if strings.HasPrefix(entry.Name(), "v-") {
			_ = os.RemoveAll(filepath.Join(store, entry.Name()))
		}
	}
}

func syncDir(dir string) error {
	fd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}
