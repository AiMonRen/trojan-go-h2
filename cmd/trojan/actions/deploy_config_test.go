package actions

import (
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func masterDeploymentInput() deploymentCoreConfigInput {
	deployPath := "/etc/trojan-go"
	return deploymentCoreConfigInput{
		DeployPath:    deployPath,
		Domain:        "master.example.com",
		CertPath:      filepath.Join(deployPath, "tls", "master.example.com", "master.example.com.crt"),
		KeyPath:       filepath.Join(deployPath, "tls", "master.example.com", "master.example.com.key"),
		GatewayPort:   443,
		DataPlanePort: 14443,
		AdminPort:     8081,
		ControlPort:   8082,
		AdminUser:     "admin",
		AdminPass:     "safe: password",
		DBPath:        filepath.Join(deployPath, "trojan-go.db"),
		SubPath:       "/sub-master",
	}
}

func TestBuildMasterProxyConfigRoundTrip(t *testing.T) {
	input := masterDeploymentInput()
	data, err := buildMasterProxyConfig(input)
	if err != nil {
		t.Fatalf("build master data-plane config: %v", err)
	}
	var got deploymentDataPlaneConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal master data-plane config: %v", err)
	}
	if got.RunType != "server" || got.LocalAddr != "127.0.0.1" || got.LocalPort != 14443 {
		t.Fatalf("unexpected data-plane listener: %+v", got)
	}
	if !got.ProxyProtocol || !got.TransportPlugin.Enabled || got.TransportPlugin.Type != "plaintext" {
		t.Fatalf("unexpected private transport config: %+v", got)
	}
	if got.AuthDB != input.DBPath || got.AuthRefresh != 30 {
		t.Fatalf("unexpected cold database auth config: %+v", got)
	}
	wantReport := "http://127.0.0.1:8081/internal/control/v1/data-plane/traffic"
	if got.TrafficReport != wantReport || got.TrafficInterval != 30 {
		t.Fatalf("unexpected master traffic reporting: %+v", got)
	}
	if got.Node != nil {
		t.Fatalf("master data-plane must not include node sync: %+v", got.Node)
	}
}

func TestBuildWorkerProxyConfigRoundTrip(t *testing.T) {
	input := masterDeploymentInput()
	input.Domain = "worker.example.com"
	input.Node = &deploymentNodeConfig{
		Enabled: true, MasterURL: "https://master.example.com/control/v1/nodes/sync", Secret: "node-secret", SyncInterval: 60,
	}
	data, err := buildWorkerProxyConfig(input)
	if err != nil {
		t.Fatalf("build worker data-plane config: %v", err)
	}
	var got deploymentDataPlaneConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal worker data-plane config: %v", err)
	}
	if got.LocalAddr != "127.0.0.1" || got.LocalPort != 14443 || !got.ProxyProtocol {
		t.Fatalf("unexpected worker data-plane listener: %+v", got)
	}
	if got.Node == nil || got.Node.MasterURL != "https://master.example.com/control/v1/nodes/sync" || got.Node.Secret != "node-secret" {
		t.Fatalf("unexpected node synchronization config: %+v", got.Node)
	}
	if got.TrafficReport != "" || got.TrafficInterval != 0 {
		t.Fatalf("worker must report through node sync only: %+v", got)
	}
}

func TestBuildWorkerProxyConfigRequiresNodeSettings(t *testing.T) {
	_, err := buildWorkerProxyConfig(deploymentCoreConfigInput{})
	if err == nil {
		t.Fatal("worker data-plane configuration without node settings must fail")
	}
}

func TestBuildGatewayConfigsRoundTrip(t *testing.T) {
	input := masterDeploymentInput()
	for _, tt := range []struct {
		name          string
		adminDisabled bool
	}{
		{name: "master"},
		{name: "worker", adminDisabled: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := buildGatewayConfig(input, tt.adminDisabled)
			if err != nil {
				t.Fatalf("build gateway config: %v", err)
			}
			var got deploymentGatewayConfig
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal gateway config: %v", err)
			}
			if got.Gateway.Listen != "0.0.0.0:443" || got.Gateway.ControlService != "127.0.0.1:8082" || got.Gateway.TrojanService != "127.0.0.1:14443" {
				t.Fatalf("unexpected gateway backends: %+v", got.Gateway)
			}
			if got.Gateway.AdminDisabled != tt.adminDisabled {
				t.Fatalf("admin disabled = %t, want %t", got.Gateway.AdminDisabled, tt.adminDisabled)
			}
			if tt.adminDisabled && got.Gateway.AdminService != "" {
				t.Fatalf("worker gateway must not expose admin-service: %+v", got.Gateway)
			}
			if !tt.adminDisabled && got.Gateway.AdminService != "127.0.0.1:8081" {
				t.Fatalf("master gateway missing admin-service: %+v", got.Gateway)
			}
			if got.Routes.AdminPrefix != "/admin/" || got.Routes.SubPath != "/sub-master" || got.SSL.Cert == "" || got.SSL.Key == "" {
				t.Fatalf("unexpected gateway routes/TLS: %+v", got)
			}
		})
	}
}

func TestBuildWebConfigsRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name   string
		build  func() ([]byte, error)
		port   int
		worker bool
	}{
		{
			name: "master",
			build: func() ([]byte, error) {
				return buildMasterWebConfig("admin", "password", 8081, "/etc/trojan-go/trojan-go.db", "/sub-master")
			},
			port: 8081,
		},
		{
			name: "worker-control",
			build: func() ([]byte, error) {
				return buildWorkerWebConfig("admin", "password", 8082, "/etc/trojan-go/trojan-go.db", "/sub-worker")
			},
			port:   8082,
			worker: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.build()
			if err != nil {
				t.Fatalf("build service config: %v", err)
			}
			var got deploymentWebConfig
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal service config: %v", err)
			}
			if got.RunType != "server" || !got.Admin.Enabled || got.Admin.Port != tt.port || got.Admin.Path != "/admin/" {
				t.Fatalf("unexpected service config: %+v", got)
			}
			if (got.Node != nil) != tt.worker {
				t.Fatalf("worker node section present = %t, want %t", got.Node != nil, tt.worker)
			}
		})
	}
}

func TestBuildHysteriaConfigRoundTrip(t *testing.T) {
	data, err := buildHysteriaConfig(deploymentHysteriaConfigInput{
		ListenPort: 443, CertPath: "/etc/trojan-go/tls/example.com/example.com.crt", KeyPath: "/etc/trojan-go/tls/example.com/example.com.key",
		ControlPort: 8082, UpMbps: 100, DownMbps: 300,
	})
	if err != nil {
		t.Fatalf("build Hysteria2 config: %v", err)
	}
	var got deploymentHysteriaConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal Hysteria2 config: %v", err)
	}
	if got.Listen != ":443" || got.Auth.HTTP.URL != "http://127.0.0.1:8082/control/v1/hysteria/auth" || !got.Auth.HTTP.Insecure {
		t.Fatalf("unexpected Hysteria2 auth config: %+v", got.Auth)
	}
	if got.Bandwidth.Up != "100 mbps" || got.Bandwidth.Down != "300 mbps" || got.QUIC.MaxIdleTimeout != "60s" || got.QUIC.KeepAliveInterval != "10s" {
		t.Fatalf("unexpected Hysteria2 transport config: %+v %+v", got.Bandwidth, got.QUIC)
	}
}
