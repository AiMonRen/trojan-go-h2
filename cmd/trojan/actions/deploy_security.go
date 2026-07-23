package actions

import (
	"bufio"
	"crypto/sha256"
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

func writeCertificateFiles(certificatePath, privateKeyPath string, certificatePEM, privateKeyPEM []byte) error {
	if err := os.MkdirAll(filepath.Dir(certificatePath), 0755); err != nil {
		return fmt.Errorf("create certificate directory: %w", err)
	}
	if err := os.WriteFile(certificatePath, certificatePEM, 0644); err != nil {
		return fmt.Errorf("write certificate: %w", err)
	}
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	return nil
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
	if err := runCmd("systemctl", "restart", "trojan-web", "trojan-go"); err != nil {
		return fmt.Errorf("restart Trojan-Go services after certificate renewal: %w", err)
	}
	if config.ReloadHysteria {
		if err := runCmd("systemctl", "restart", "hysteria"); err != nil {
			return fmt.Errorf("restart Hysteria2 after certificate renewal: %w", err)
		}
	}
	fmt.Printf("renewed certificate for %s\n", config.Domain)
	return nil
}
