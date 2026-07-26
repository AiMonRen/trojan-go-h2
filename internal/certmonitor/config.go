// Package certmonitor provides ACME certificate management and automatic
// renewal for trojan-go gateway deployments.
package certmonitor

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"
)

// CertificateRenewBefore is the default window before certificate expiry in
// which automatic renewal is triggered.
const CertificateRenewBefore = 30 * 24 * time.Hour

// CertificateRenewalConfig holds all parameters needed to issue or renew a
// single certificate via ACME.
type CertificateRenewalConfig struct {
	Domain          string
	Email           string
	CAURL           string
	CertificatePath string
	PrivateKeyPath  string
	ReloadHysteria  bool
	// GatewayService is the systemd unit name for the gateway (used by
	// RenewCertificateFromConfig to restart after renewal). When empty
	// it defaults to "trojan-go-gateway".
	GatewayService string
	// HysteriaService is the systemd unit name for Hysteria2 (used by
	// RenewCertificateFromConfig to restart after renewal when
	// ReloadHysteria is true). When empty it defaults to
	// "trojan-go-hysteria".
	HysteriaService string
}

// WriteCertificateRenewalConfig persists a CertificateRenewalConfig to disk
// for consumption by the systemd cert-renew timer.
func WriteCertificateRenewalConfig(path string, config CertificateRenewalConfig) error {
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

// ReadCertificateRenewalConfig reads a previously persisted renewal config.
func ReadCertificateRenewalConfig(path string) (CertificateRenewalConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return CertificateRenewalConfig{}, err
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
			return CertificateRenewalConfig{}, fmt.Errorf("invalid renewal config line %q", line)
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return CertificateRenewalConfig{}, err
	}

	config := CertificateRenewalConfig{
		Domain:          values["domain"],
		Email:           values["email"],
		CAURL:           values["ca_url"],
		CertificatePath: values["certificate_path"],
		PrivateKeyPath:  values["private_key_path"],
		ReloadHysteria:  values["reload_hysteria"] == "true",
	}
	if config.Domain == "" || config.Email == "" || config.CertificatePath == "" || config.PrivateKeyPath == "" {
		return CertificateRenewalConfig{}, fmt.Errorf("renewal config is missing required values")
	}
	return config, nil
}
