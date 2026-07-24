package webserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/voidluo/trojan-go/internal/database"
)

func TestGetMainNodeInfoUsesGatewayPublicPort(t *testing.T) {
	dir := t.TempDir()
	WebConfigPath = filepath.Join(dir, "web_config.yaml")
	t.Cleanup(func() { WebConfigPath = "" })
	gateway := `gateway:
  listen: 0.0.0.0:443
  trojan_service: 127.0.0.1:14443
ssl:
  cert: /etc/trojan-go/tls/gateway.example.com/gateway.example.com.crt
  key: /etc/trojan-go/tls/gateway.example.com/gateway.example.com.key
`
	if err := os.WriteFile(filepath.Join(dir, "gateway.yaml"), []byte(gateway), 0o600); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}
	srv := &AdminServer{wsEnabled: true, wsPath: "/legacy-ws"}
	domain, port, wsEnabled, wsPath := srv.getMainNodeInfo()
	if domain != "gateway.example.com" || port != 443 || wsEnabled || wsPath != "" {
		t.Fatalf("unexpected gateway node info: domain=%q port=%d ws=%t path=%q", domain, port, wsEnabled, wsPath)
	}
}

func TestGatewaySubscriptionNeverPublishesPrivateDataPlaneOrWebSocket(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	if err := db.Model(&database.Config{}).Where("`key` = ?", "sub_use_ws").Update("value", "true").Error; err != nil {
		t.Fatalf("enable legacy WS setting: %v", err)
	}
	user := database.User{Username: "gateway", Password: "plain-password", Hash: "hash", Quota: -1}
	nodes := []database.Node{{Name: "worker", Address: "worker.example.com", Port: 443, WSEnabled: true, WSPath: "/legacy-worker"}}
	config := generateClashConfigMultiNode(db, user, nodes, "gateway.example.com", 443, false, "")
	if strings.Contains(config, "port: 14443") {
		t.Fatal("subscription must never expose private data-plane port")
	}
	if strings.Contains(config, "network: ws") || strings.Contains(config, "ws-opts") {
		t.Fatal("Gateway deployment must not publish unsupported WebSocket transport")
	}
	if !strings.Contains(config, "server: gateway.example.com\n    port: 443") {
		t.Fatal("subscription must publish Gateway TCP/443")
	}
}
