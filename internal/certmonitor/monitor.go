package certmonitor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// PostRenewAction is called after a successful certificate renewal.
// If RestartGateway is true the caller should restart the Gateway service.
// If RestartHysteria is true the caller should restart the Hysteria2 service.
type PostRenewAction struct {
	RestartGateway  bool
	RestartHysteria bool
}

// CertMonitor periodically checks certificate expiry and triggers ACME
// renewal when the certificate is within the configured renewal window.
type CertMonitor struct {
	cfg CertificateRenewalConfig

	checkInterval time.Duration
	renewBefore   time.Duration

	// OnRenewed is called after every successful renewal. The returned
	// PostRenewAction describes which services need a restart.
	OnRenewed func() PostRenewAction

	mu       sync.Mutex
	renewing bool
}

// MonitorOption customises CertMonitor behaviour.
type MonitorOption func(*CertMonitor)

// WithCheckInterval overrides the default 12-hour check interval.
func WithCheckInterval(d time.Duration) MonitorOption {
	return func(m *CertMonitor) { m.checkInterval = d }
}

// WithRenewBefore overrides the default 30-day renewal window.
func WithRenewBefore(d time.Duration) MonitorOption {
	return func(m *CertMonitor) { m.renewBefore = d }
}

// NewCertMonitor creates a certificate monitor from a renewal configuration.
// By default it checks every 12 hours and renews when expiry is within 30 days.
func NewCertMonitor(cfg CertificateRenewalConfig, onRenewed func() PostRenewAction, opts ...MonitorOption) *CertMonitor {
	m := &CertMonitor{
		cfg:           cfg,
		checkInterval: 12 * time.Hour,
		renewBefore:   CertificateRenewBefore,
		OnRenewed:     onRenewed,
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Run starts the monitoring loop. It blocks until ctx is cancelled. Callers
// should run this in a separate goroutine.
func (m *CertMonitor) Run(ctx context.Context) {
	ticker := time.NewTicker(m.checkInterval)
	defer ticker.Stop()

	// Perform an immediate check on startup.
	m.checkAndRenew()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.checkAndRenew()
		}
	}
}

func (m *CertMonitor) checkAndRenew() {
	needsRenewal, err := CertificateNeedsRenewal(m.cfg.CertificatePath, m.renewBefore, time.Now())
	if err != nil {
		fmt.Printf("[cert-monitor] 检查证书失败: %v\n", err)
		return
	}
	if !needsRenewal {
		return
	}

	// Prevent concurrent renewals.
	m.mu.Lock()
	if m.renewing {
		m.mu.Unlock()
		return
	}
	m.renewing = true
	m.mu.Unlock()

	defer func() {
		m.mu.Lock()
		m.renewing = false
		m.mu.Unlock()
	}()

	fmt.Printf("[cert-monitor] 证书即将到期 (域名: %s)，开始自动续期\n", m.cfg.Domain)

	cert, err := ObtainCert(m.cfg.Domain, m.cfg.Email, m.cfg.CAURL)
	if err != nil {
		fmt.Printf("[cert-monitor] 自动续期��败: %v\n", err)
		return
	}

	if err := WriteCertificateFiles(m.cfg.CertificatePath, m.cfg.PrivateKeyPath, cert.Certificate, cert.PrivateKey); err != nil {
		fmt.Printf("[cert-monitor] 写入新证书失败: %v\n", err)
		return
	}

	fmt.Printf("[cert-monitor] 证书续期成功 (域名: %s)\n", m.cfg.Domain)

	if m.OnRenewed != nil {
		action := m.OnRenewed()
		if action.RestartGateway || action.RestartHysteria {
			fmt.Printf("[cert-monitor] 原子化部署完成，请重启相应服务以加载新证书\n")
		}
	}
}
