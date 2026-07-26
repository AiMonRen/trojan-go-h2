package actions

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/voidluo/trojan-go/internal/certmonitor"
)

const (
	hysteriaVersion       = "v2.10.0"
	hysteriaLinuxAMD64URL = "https://github.com/apernet/hysteria/releases/download/app%2Fv2.10.0/hysteria-linux-amd64"
	hysteriaLinuxAMD64SHA = "04f7804159ef1d798de12a817d73aab4b9040ebe45fc62e223000c5c59e987fe"
)

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

func installCertificateRenewalTimer(deployPath string, config certmonitor.CertificateRenewalConfig) error {
	configPath := filepath.Join(deployPath, "acme-renewal.conf")
	if err := certmonitor.WriteCertificateRenewalConfig(configPath, config); err != nil {
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
	config, err := certmonitor.ReadCertificateRenewalConfig(configPath)
	if err != nil {
		return err
	}
	needsRenewal, err := certmonitor.CertificateNeedsRenewal(config.CertificatePath, certmonitor.CertificateRenewBefore, time.Now())
	if err != nil {
		return fmt.Errorf("inspect current certificate: %w", err)
	}
	if !needsRenewal {
		fmt.Println("certificate remains valid beyond renewal window; no action needed")
		return nil
	}

	certificate, err := certmonitor.ObtainCert(config.Domain, config.Email, config.CAURL)
	if err != nil {
		return fmt.Errorf("renew certificate for %s: %w", config.Domain, err)
	}
	if err := certmonitor.WriteCertificateFiles(config.CertificatePath, config.PrivateKeyPath, certificate.Certificate, certificate.PrivateKey); err != nil {
		return err
	}

	// B-3: Use the service names from the renewal config, falling back to
	// install.sh-compatible defaults instead of hardcoded gateway-service/hysteria.
	gatewaySvc := config.GatewayService
	if gatewaySvc == "" {
		gatewaySvc = "trojan-go-gateway"
	}
	if err := runCmd("systemctl", "restart", gatewaySvc); err != nil {
		return fmt.Errorf("restart Gateway (%s) after certificate renewal: %w", gatewaySvc, err)
	}
	if config.ReloadHysteria {
		hysteriaSvc := config.HysteriaService
		if hysteriaSvc == "" {
			hysteriaSvc = "trojan-go-hysteria"
		}
		if err := runCmd("systemctl", "restart", hysteriaSvc); err != nil {
			return fmt.Errorf("restart Hysteria2 (%s) after certificate renewal: %w", hysteriaSvc, err)
		}
	}
	fmt.Printf("renewed certificate for %s\n", config.Domain)
	return nil
}
