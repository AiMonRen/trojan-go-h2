package actions

import (
	"bufio"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	hysteriaVersion        = "v2.10.0"
	hysteriaLinuxAMD64URL  = "https://github.com/apernet/hysteria/releases/download/app%2Fv2.10.0/hysteria-linux-amd64"
	hysteriaLinuxAMD64SHA  = "04f7804159ef1d798de12a817d73aab4b9040ebe45fc62e223000c5c59e987fe"
	certificateRenewBefore = 30 * 24 * time.Hour
)

type certificateRenewalConfig struct {
	Domain          string
	Email           string
	CAURL           string
	CertificatePath string
	PrivateKeyPath  string
	ReloadHysteria  bool
}

func verifySHA256(path, expected string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if !strings.EqualFold(actual, expected) {
		return fmt.Errorf("SHA-256 mismatch: got %s, want %s", actual, expected)
	}
	return nil
}

func installHysteriaBinary() error {
	tempFile, err := os.CreateTemp("/usr/local/bin", ".hysteria-download-*")
	if err != nil {
		return fmt.Errorf("create temporary Hysteria2 download: %w", err)
	}
	tempPath := tempFile.Name()
	if err := tempFile.Close(); err != nil {
		_ = os.Remove(tempPath)
		return err
	}
	defer os.Remove(tempPath)

	if err := runCmd("wget", "-qO", tempPath, hysteriaLinuxAMD64URL); err != nil {
		return fmt.Errorf("download Hysteria2 %s: %w", hysteriaVersion, err)
	}
	if err := verifySHA256(tempPath, hysteriaLinuxAMD64SHA); err != nil {
		return fmt.Errorf("verify Hysteria2 %s: %w", hysteriaVersion, err)
	}
	if err := os.Chmod(tempPath, 0755); err != nil {
		return fmt.Errorf("set Hysteria2 permissions: %w", err)
	}
	if err := runCmd(tempPath, "version"); err != nil {
		return fmt.Errorf("verify Hysteria2 executable: %w", err)
	}
	if err := os.Rename(tempPath, "/usr/local/bin/hysteria"); err != nil {
		return fmt.Errorf("install verified Hysteria2 binary: %w", err)
	}
	return nil
}

// writeCertificateFiles atomically installs a certificate/key pair using a
// versioned directory plus a single symlink switch, so a crash can never leave
// a mismatched (new cert, old key) pair on disk.
//
// Layout for a target such as <dir>/example.com.crt / <dir>/example.com.key:
//
//	<dir>/.certstore/<serial>/cert.pem   # this version's certificate
//	<dir>/.certstore/<serial>/key.pem    # this version's key (same dir → one unit)
//	<dir>/.certstore/current   -> <serial>   # single pointer, switched atomically
//	<dir>/example.com.crt      -> .certstore/current/cert.pem  # stable, never re-pointed
//	<dir>/example.com.key      -> .certstore/current/key.pem   # stable, never re-pointed
//
// Only the `current` symlink is ever swapped, and it is swapped with a single
// rename of a staged symlink. Because both cert.pem and key.pem live inside the
// same version directory that `current` points at, they always switch together.
func writeCertificateFiles(certificatePath, privateKeyPath string, certificatePEM, privateKeyPEM []byte) error {
	// Validate that certificate and private key are a matching pair before
	// touching any production files.
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

	// 1. Write this version into a fresh, uniquely named version directory.
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

	// 2. Atomically point `current` at the new version via a single symlink
	// rename. This is the only mutation that flips the live pair.
	if err := atomicSwapSymlink(store, filepath.Base(versionDir), "current"); err != nil {
		return fmt.Errorf("switch current certificate version: %w", err)
	}
	cleanupVersion = false

	// 3. Ensure the stable cert/key paths are symlinks into current/. These are
	// created once and never re-pointed, so they stay valid across renewals.
	if err := ensureCertSymlink(certificatePath, filepath.Join(".certstore", "current", "cert.pem")); err != nil {
		return fmt.Errorf("link certificate path: %w", err)
	}
	if err := ensureCertSymlink(privateKeyPath, filepath.Join(".certstore", "current", "key.pem")); err != nil {
		return fmt.Errorf("link private key path: %w", err)
	}

	// 4. Best-effort prune of superseded version directories.
	pruneOldCertVersions(store, filepath.Base(versionDir))
	return nil
}

// atomicSwapSymlink creates a symlink named linkName in dir pointing at target,
// staging it under a temp name first and renaming into place so the swap is
// atomic even if a previous link already exists.
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

// ensureCertSymlink makes path a symlink to target (relative to path's dir).
// If path already points at target it is left untouched; otherwise any existing
// file/symlink is replaced atomically.
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

// pruneOldCertVersions removes version directories other than the one currently
// in use. Failures are ignored: stale directories are harmless.
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

// syncDir fsyncs a directory so that a rename/symlink within it is durable.
func syncDir(dir string) error {
	fd, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer fd.Close()
	return fd.Sync()
}

func certificateNeedsRenewal(certificatePath string, before time.Duration, now time.Time) (bool, error) {
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

func writeCertificateRenewalConfig(path string, config certificateRenewalConfig) error {
	content := strings.Join([]string{
		"domain=" + config.Domain,
		"email=" + config.Email,
		"ca_url=" + config.CAURL,
		"certificate_path=" + config.CertificatePath,
		"private_key_path=" + config.PrivateKeyPath,
		fmt.Sprintf("reload_hysteria=%t", config.ReloadHysteria),
	}, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0600)
}

func readCertificateRenewalConfig(path string) (certificateRenewalConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return certificateRenewalConfig{}, err
	}
	defer file.Close()

	values := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return certificateRenewalConfig{}, fmt.Errorf("invalid renewal config line %q", line)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return certificateRenewalConfig{}, err
	}

	config := certificateRenewalConfig{
		Domain:          values["domain"],
		Email:           values["email"],
		CAURL:           values["ca_url"],
		CertificatePath: values["certificate_path"],
		PrivateKeyPath:  values["private_key_path"],
		ReloadHysteria:  values["reload_hysteria"] == "true",
	}
	if config.Domain == "" || config.Email == "" || config.CertificatePath == "" || config.PrivateKeyPath == "" {
		return certificateRenewalConfig{}, fmt.Errorf("renewal config is missing required values")
	}
	return config, nil
}

func installCertificateRenewalTimer(deployPath string, config certificateRenewalConfig) error {
	configPath := filepath.Join(deployPath, "acme-renewal.conf")
	if err := writeCertificateRenewalConfig(configPath, config); err != nil {
		return err
	}

	service := `[Unit]
Description=Trojan-Go ACME certificate renewal
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/bin/trojan cert-renew --config ` + configPath + `
`
	timer := `[Unit]
Description=Run Trojan-Go ACME certificate renewal daily

[Timer]
OnCalendar=daily
RandomizedDelaySec=30m
Persistent=true

[Install]
WantedBy=timers.target
`
	if err := os.WriteFile("/etc/systemd/system/trojan-cert-renew.service", []byte(service), 0644); err != nil {
		return fmt.Errorf("write certificate renewal service: %w", err)
	}
	if err := os.WriteFile("/etc/systemd/system/trojan-cert-renew.timer", []byte(timer), 0644); err != nil {
		return fmt.Errorf("write certificate renewal timer: %w", err)
	}
	return nil
}

// RenewCertificateFromConfig is used by the systemd renewal timer. It reissues
// only certificates that expire within the configured renewal window.
func RenewCertificateFromConfig(configPath string) error {
	config, err := readCertificateRenewalConfig(configPath)
	if err != nil {
		return err
	}
	needsRenewal, err := certificateNeedsRenewal(config.CertificatePath, certificateRenewBefore, time.Now())
	if err != nil {
		return fmt.Errorf("inspect current certificate: %w", err)
	}
	if !needsRenewal {
		fmt.Println("certificate remains valid beyond renewal window; no action needed")
		return nil
	}

	certificate, err := obtainCert(config.Domain, config.Email, config.CAURL)
	if err != nil {
		return fmt.Errorf("renew certificate for %s: %w", config.Domain, err)
	}
	if err := writeCertificateFiles(config.CertificatePath, config.PrivateKeyPath, certificate.Certificate, certificate.PrivateKey); err != nil {
		return err
	}
	if err := runCmd("systemctl", "restart", "gateway-service"); err != nil {
		return fmt.Errorf("restart Gateway after certificate renewal: %w", err)
	}
	if config.ReloadHysteria {
		if err := runCmd("systemctl", "restart", "hysteria"); err != nil {
			return fmt.Errorf("restart Hysteria2 after certificate renewal: %w", err)
		}
	}
	fmt.Printf("renewed certificate for %s\n", config.Domain)
	return nil
}
