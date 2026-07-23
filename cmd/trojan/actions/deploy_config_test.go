package actions

import (
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestBuildMasterProxyConfigRoundTrip(t *testing.T) {
	deployPath := "/etc/trojan-go"
	data, err := buildMasterProxyConfig(deploymentCoreConfigInput{
		DeployPath: deployPath,
		Domain:     "master.example.com",
		CertPath:   filepath.Join(deployPath, "tls", "master.example.com", "master.example.com.crt"),
		KeyPath:    filepath.Join(deployPath, "tls", "master.example.com", "master.example.com.key"),
		LocalPort:  443,
		AdminPort:  8080,
		WSPath:     "/stream-master",
		WSEnabled:  true,
		AdminUser:  "admin",
		AdminPass:  "safe: password",
		DBPath:     filepath.Join(deployPath, "trojan-go.db"),
		SubPath:    "/sub-master",
	})
	if err != nil {
		t.Fatalf("build master proxy config: %v", err)
	}

	var got deploymentProxyConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal master proxy config: %v", err)
	}
	if got.RunType != "server" || got.LocalAddr != "0.0.0.0" || got.LocalPort != 443 {
		t.Fatalf("unexpected core config: %+v", got)
	}
	if got.SSL.Cert == "" || got.SSL.Key == "" || got.SSL.PlainHTTPResponse != filepath.Join(deployPath, "index.html") {
		t.Fatalf("unexpected TLS config: %+v", got.SSL)
	}
	if got.SSL.FallbackAddr != "" || got.SSL.FallbackPort != 0 {
		t.Fatalf("master must not configure fallback: %+v", got.SSL)
	}
	if got.WebSocket.Enabled != true || got.WebSocket.Path != "/stream-master" || got.WebSocket.Host != "master.example.com" {
		t.Fatalf("unexpected WebSocket config: %+v", got.WebSocket)
	}
	if got.Admin.Password != "safe: password" || got.Admin.Path != "/admin" || got.Admin.SubPath != "/sub-master" {
		t.Fatalf("unexpected admin config: %+v", got.Admin)
	}
	if got.Node != nil {
		t.Fatalf("master config must not include node synchronization settings: %+v", got.Node)
	}
}

func TestBuildWorkerProxyConfigRoundTrip(t *testing.T) {
	deployPath := "/etc/trojan-go"
	data, err := buildWorkerProxyConfig(deploymentCoreConfigInput{
		DeployPath: deployPath,
		Domain:     "worker.example.com",
		CertPath:   filepath.Join(deployPath, "tls", "worker.example.com", "worker.example.com.crt"),
		KeyPath:    filepath.Join(deployPath, "tls", "worker.example.com", "worker.example.com.key"),
		LocalPort:  8443,
		AdminPort:  18080,
		WSPath:     "/stream-worker",
		WSEnabled:  false,
		AdminUser:  "worker-admin",
		AdminPass:  "worker-password",
		DBPath:     filepath.Join(deployPath, "trojan-go.db"),
		SubPath:    "/sub-worker",
		Fallback:   true,
		Node: &deploymentNodeConfig{
			Enabled: true, MasterURL: "https://master.example.com/admin/api/node/sync", Secret: "node-secret", SyncInterval: 60,
		},
	})
	if err != nil {
		t.Fatalf("build worker proxy config: %v", err)
	}

	var got deploymentProxyConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal worker proxy config: %v", err)
	}
	if got.WebSocket.Enabled {
		t.Fatal("worker WebSocket should remain disabled")
	}
	if got.SSL.FallbackAddr != "127.0.0.1" || got.SSL.FallbackPort != 18080 {
		t.Fatalf("worker fallback = %+v, want local web backend", got.SSL)
	}
	if got.Node == nil || !got.Node.Enabled || got.Node.MasterURL != "https://master.example.com/admin/api/node/sync" || got.Node.Secret != "node-secret" || got.Node.SyncInterval != 60 {
		t.Fatalf("unexpected node synchronization config: %+v", got.Node)
	}
}

func TestBuildWorkerProxyConfigRequiresNodeSettings(t *testing.T) {
	_, err := buildWorkerProxyConfig(deploymentCoreConfigInput{})
	if err == nil {
		t.Fatal("worker proxy configuration without node settings must fail")
	}
}

func TestBuildWebConfigsRoundTrip(t *testing.T) {
	for _, tt := range []struct {
		name   string
		build  func() ([]byte, error)
		worker bool
	}{
		{
			name: "master",
			build: func() ([]byte, error) {
				return buildMasterWebConfig("admin", "password", 8080, "/etc/trojan-go/trojan-go.db", "/sub-master")
			},
		},
		{
			name: "worker",
			build: func() ([]byte, error) {
				return buildWorkerWebConfig("admin", "password", 8080, "/etc/trojan-go/trojan-go.db", "/sub-worker")
			},
			worker: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.build()
			if err != nil {
				t.Fatalf("build web config: %v", err)
			}
			var got deploymentWebConfig
			if err := yaml.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal web config: %v", err)
			}
			if got.RunType != "server" || !got.Admin.Enabled || got.Admin.Port != 8080 || got.Admin.Path != "/admin/" {
				t.Fatalf("unexpected web config: %+v", got)
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
		AdminPort: 8080, UpMbps: 100, DownMbps: 300,
	})
	if err != nil {
		t.Fatalf("build Hysteria2 config: %v", err)
	}
	var got deploymentHysteriaConfig
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal Hysteria2 config: %v", err)
	}
	if got.Listen != ":443" || got.Auth.HTTP.URL != "http://127.0.0.1:8080/admin/api/hysteria/auth" || !got.Auth.HTTP.Insecure {
		t.Fatalf("unexpected Hysteria2 auth config: %+v", got.Auth)
	}
	if got.Bandwidth.Up != "100 mbps" || got.Bandwidth.Down != "300 mbps" || got.QUIC.MaxIdleTimeout != "60s" || got.QUIC.KeepAliveInterval != "10s" {
		t.Fatalf("unexpected Hysteria2 transport config: %+v %+v", got.Bandwidth, got.QUIC)
	}
}
