package actions

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type deploymentRole string

const (
	deploymentMaster deploymentRole = "master"
	deploymentWorker deploymentRole = "worker"
)

type deploymentServices struct {
	Proxy    string
	Web      string
	Hysteria string
}

func deploymentServiceDescriptions(role deploymentRole) deploymentServices {
	if role == deploymentWorker {
		return deploymentServices{
			Proxy:    "Trojan-Go Worker Proxy Service",
			Web:      "Trojan-Go Worker Web Management Service",
			Hysteria: "Hysteria2 QUIC/UDP Server (Worker)",
		}
	}
	return deploymentServices{
		Proxy:    "Trojan-Go Proxy Service",
		Web:      "Trojan-Go Web Management Service",
		Hysteria: "Hysteria2 QUIC/UDP Server",
	}
}

// deploymentUnitContents creates all unit files without writing to the host.
// Keeping rendering separate makes both roles testable and prevents service
// definitions from drifting when a common property changes.
func deploymentUnitContents(role deploymentRole, deployPath string, hysteriaEnabled bool) map[string]string {
	descriptions := deploymentServiceDescriptions(role)
	units := map[string]string{
		"trojan-go.service": fmt.Sprintf(`[Unit]
Description=%s
After=network.target trojan-web.service

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go -config %s
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`, descriptions.Proxy, filepath.Join(deployPath, "config.yaml")),
		"trojan-web.service": fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go web -config %s
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`, descriptions.Web, filepath.Join(deployPath, "web_config.yaml")),
	}
	if hysteriaEnabled {
		units["hysteria.service"] = fmt.Sprintf(`[Unit]
Description=%s
After=network.target trojan-web.service

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c %s
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`, descriptions.Hysteria, filepath.Join(deployPath, "hysteria.yaml"))
	}
	return units
}

func writeDeploymentUnits(systemdDir string, role deploymentRole, deployPath string, hysteriaEnabled bool) error {
	for name, content := range deploymentUnitContents(role, deployPath, hysteriaEnabled) {
		if err := os.WriteFile(filepath.Join(systemdDir, name), []byte(content), 0644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	return nil
}

func deploymentServiceNames(hysteriaEnabled bool) []string {
	services := []string{"trojan-web", "trojan-go"}
	if hysteriaEnabled {
		services = append(services, "hysteria")
	}
	return services
}

func installDeploymentBinaries(deployPath, tlsDir, certificatePath, privateKeyPath string) error {
	installedProxy := false
	if _, err := os.Stat("./trojan-go"); err == nil {
		if err := runCmd("cp", "-f", "./trojan-go", "/usr/bin/trojan-go"); err != nil {
			return fmt.Errorf("install trojan-go: %w", err)
		}
		if err := runCmd("chmod", "+x", "/usr/bin/trojan-go"); err != nil {
			return fmt.Errorf("mark trojan-go executable: %w", err)
		}
		installedProxy = true
	} else if _, err := os.Stat("./trojan-go-linux-amd64"); err == nil {
		if err := runCmd("cp", "-f", "./trojan-go-linux-amd64", "/usr/bin/trojan-go"); err != nil {
			return fmt.Errorf("install trojan-go: %w", err)
		}
		if err := runCmd("chmod", "+x", "/usr/bin/trojan-go"); err != nil {
			return fmt.Errorf("mark trojan-go executable: %w", err)
		}
		installedProxy = true
	}
	if installedProxy {
		fmt.Println("✓ 已安装 trojan-go 至 /usr/bin/trojan-go")
	}

	installedCLI := false
	if _, err := os.Stat("./trojan"); err == nil {
		if err := runCmd("cp", "-f", "./trojan", "/usr/bin/trojan"); err != nil {
			return fmt.Errorf("install trojan CLI: %w", err)
		}
		if err := runCmd("chmod", "+x", "/usr/bin/trojan"); err != nil {
			return fmt.Errorf("mark trojan CLI executable: %w", err)
		}
		installedCLI = true
	} else if _, err := os.Stat("./trojan-linux-amd64"); err == nil {
		if err := runCmd("cp", "-f", "./trojan-linux-amd64", "/usr/bin/trojan"); err != nil {
			return fmt.Errorf("install trojan CLI: %w", err)
		}
		if err := runCmd("chmod", "+x", "/usr/bin/trojan"); err != nil {
			return fmt.Errorf("mark trojan CLI executable: %w", err)
		}
		installedCLI = true
	}
	if installedCLI {
		fmt.Println("✓ 已安装 trojan 至 /usr/bin/trojan")
	}

	for _, permission := range []struct {
		mode string
		path string
	}{
		{"0755", deployPath},
		{"0755", filepath.Join(deployPath, "tls")},
		{"0755", tlsDir},
		{"0644", certificatePath},
		{"0600", privateKeyPath},
	} {
		if err := runCmd("chmod", permission.mode, permission.path); err != nil {
			return fmt.Errorf("set permission %s on %s: %w", permission.mode, permission.path, err)
		}
	}
	return nil
}

func configureAndStartDeployment(role deploymentRole, deployPath string, hysteriaEnabled bool, renewalConfig certificateRenewalConfig) error {
	if err := writeDeploymentUnits("/etc/systemd/system", role, deployPath, hysteriaEnabled); err != nil {
		return err
	}
	if err := installCertificateRenewalTimer(deployPath, renewalConfig); err != nil {
		return fmt.Errorf("configure certificate renewal: %w", err)
	}
	if err := runCmd("systemctl", "daemon-reload"); err != nil {
		return fmt.Errorf("reload systemd: %w", err)
	}
	if err := runCmd("systemctl", "enable", "--now", "trojan-cert-renew.timer"); err != nil {
		return fmt.Errorf("enable certificate renewal timer: %w", err)
	}

	services := deploymentServiceNames(hysteriaEnabled)
	for _, service := range services {
		fmt.Printf(" [!] 正在激活 %s...\n", service)
		if err := runCmd("systemctl", "enable", service); err != nil {
			return fmt.Errorf("enable %s: %w", service, err)
		}
		if err := runCmd("systemctl", "start", service); err != nil {
			return fmt.Errorf("start %s: %w", service, err)
		}
	}

	fmt.Println("\n正在验证服务存活状态...")
	time.Sleep(2 * time.Second)
	for _, service := range services {
		active, err := exec.Command("systemctl", "is-active", service).Output()
		if err != nil || string(active) != "active\n" {
			out, _ := exec.Command("journalctl", "-u", service, "-n", "10", "--no-pager").CombinedOutput()
			return fmt.Errorf("%s is not active: %w\n%s", service, err, out)
		}
		fmt.Printf("\033[32m✅ %s 运行正常\033[0m\n", service)
	}
	return nil
}
