package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfigCheckFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestValidateServiceConfigAdminAndWorker(t *testing.T) {
	adminConfig := writeConfigCheckFile(t, `admin:
  enabled: true
  username: admin
  password: secret
  db: /etc/trojan-go/trojan-go.db
  path: /admin/
  sub_path: /sub-admin
`)
	if err := validateServiceConfig([]string{"--service", "admin", "--config", adminConfig}); err != nil {
		t.Fatalf("validate admin config: %v", err)
	}
	if err := validateServiceConfig([]string{"--service", "worker-control", "--config", adminConfig}); err == nil || !strings.Contains(err.Error(), "node.enabled") {
		t.Fatalf("expected worker node validation error, got %v", err)
	}
	missingCredentials := writeConfigCheckFile(t, "admin:\n  enabled: true\n  db: /tmp/test.db\n")
	if err := validateServiceConfig([]string{"--service", "admin", "--config", missingCredentials}); err == nil || !strings.Contains(err.Error(), "username") {
		t.Fatalf("expected missing admin credentials error, got %v", err)
	}
	workerConfig := writeConfigCheckFile(t, `admin:
  enabled: true
  username: admin
  password: secret
  db: /etc/trojan-go/trojan-go.db
  path: /admin/
  sub_path: /sub-worker
node:
  enabled: true
`)
	if err := validateServiceConfig([]string{"--service", "worker-control", "--config", workerConfig}); err != nil {
		t.Fatalf("validate worker control config: %v", err)
	}
}

func TestValidateDataPlaneConfig(t *testing.T) {
	valid := writeConfigCheckFile(t, `run_type: server
local_addr: 127.0.0.1
local_port: 14443
auth_db: /etc/trojan-go/trojan-go.db
traffic_report: http://127.0.0.1:8081/internal/control/v1/data-plane/traffic
traffic_outbox: /etc/trojan-go/state/data-plane-traffic-outbox.json
proxy_protocol: true
transport_plugin:
  enabled: true
  type: plaintext
`)
	if err := validateServiceConfig([]string{"--service", "data-plane", "--config", valid}); err != nil {
		t.Fatalf("validate data-plane config: %v", err)
	}
	publicListener := writeConfigCheckFile(t, `run_type: server
local_addr: 0.0.0.0
local_port: 14443
auth_db: /etc/trojan-go/trojan-go.db
proxy_protocol: true
transport_plugin:
  enabled: true
  type: plaintext
`)
	if err := validateDataPlaneConfig(publicListener); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected public listener rejection, got %v", err)
	}
	missingOutbox := writeConfigCheckFile(t, `run_type: server
local_addr: 127.0.0.1
local_port: 14443
auth_db: /etc/trojan-go/trojan-go.db
traffic_report: http://127.0.0.1:8081/internal/control/v1/data-plane/traffic
proxy_protocol: true
transport_plugin:
  enabled: true
  type: plaintext
`)
	if err := validateDataPlaneConfig(missingOutbox); err == nil || !strings.Contains(err.Error(), "traffic_outbox") {
		t.Fatalf("expected traffic outbox validation error, got %v", err)
	}
}

func TestValidateServiceConfigRejectsPathOverrideForNonGateway(t *testing.T) {
	configPath := writeConfigCheckFile(t, "admin:\n  enabled: true\n  username: admin\n  password: secret\n  db: /tmp/test.db\n  path: /admin/\n  sub_path: /sub-test\n")
	err := validateServiceConfig([]string{"--service", "admin", "--config", configPath, "--path-override", "/target", "/staged"})
	if err == nil || !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("expected path override rejection, got %v", err)
	}
}
