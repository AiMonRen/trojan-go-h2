package webserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
)

// isolateNodeInfoConfig points WebConfigPath at an empty directory so
// getMainNodeInfo() cannot pick up a gateway.yaml/config.yaml from the
// developer machine. This makes the canonical-domain fallback deterministic.
func isolateNodeInfoConfig(t *testing.T) {
	t.Helper()
	previous := WebConfigPath
	WebConfigPath = filepath.Join(t.TempDir(), "config.yaml")
	t.Cleanup(func() { WebConfigPath = previous })
}

func newHostTrustServer(t *testing.T, serverDomain string) *AdminServer {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "host-trust.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	if err := db.Create(&database.User{Username: "subscriber", Password: "password", Hash: "host-trust-token", Quota: -1}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	return newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", serverDomain, false)
}

// L-04: a poisoned Host header must never reach the generated subscription.
func TestSubscriptionIgnoresRequestHost(t *testing.T) {
	isolateNodeInfoConfig(t)
	srv := newHostTrustServer(t, "vpn.example.com")

	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodGet, "/sub?token=host-trust-token", nil)
	ginContext.Request.Host = "attacker.evil.test"
	srv.handleSub(ginContext)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, "attacker.evil.test") {
		t.Fatalf("subscription echoed attacker Host header:\n%s", body)
	}
	if !strings.Contains(body, "vpn.example.com") {
		t.Fatalf("subscription must publish the canonical domain:\n%s", body)
	}
}

// L-04: without any operator-configured domain the subscription fails closed
// instead of falling back to the request Host.
func TestSubscriptionFailsClosedWithoutCanonicalDomain(t *testing.T) {
	isolateNodeInfoConfig(t)
	srv := newHostTrustServer(t, "")

	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodGet, "/sub?token=host-trust-token", nil)
	ginContext.Request.Host = "attacker.evil.test"
	srv.handleSub(ginContext)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "attacker.evil.test") {
		t.Fatalf("error response leaked attacker Host header: %s", response.Body.String())
	}
}

func listNodes(t *testing.T, srv *AdminServer, host string) []publicNode {
	t.Helper()
	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodGet, "/admin/api/nodes", nil)
	ginContext.Request.Host = host
	srv.handleListNodes(ginContext)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var nodes []publicNode
	if err := json.Unmarshal(response.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode node list: %v (%s)", err, response.Body.String())
	}
	return nodes
}

// L-04: the synthetic main-node entry uses the canonical domain, not Host.
func TestNodeListMainNodeIgnoresRequestHost(t *testing.T) {
	isolateNodeInfoConfig(t)
	srv := newHostTrustServer(t, "vpn.example.com")
	if err := srv.db.Create(&database.Node{Name: "worker", Address: "worker.example.com", Port: 443, TrafficRate: 1, Secret: "worker-secret"}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	nodes := listNodes(t, srv, "attacker.evil.test")
	if len(nodes) != 2 {
		t.Fatalf("node count = %d, want 2: %+v", len(nodes), nodes)
	}
	if nodes[0].ID != 999999 || nodes[0].Address != "vpn.example.com" {
		t.Fatalf("main node entry = %+v, want canonical domain", nodes[0])
	}
	for _, node := range nodes {
		if node.Address == "attacker.evil.test" {
			t.Fatalf("node list echoed attacker Host header: %+v", node)
		}
	}
}

// L-04: with no canonical domain the untrusted Host is not published; the
// synthetic entry is dropped and real nodes are still returned.
func TestNodeListOmitsMainNodeWithoutCanonicalDomain(t *testing.T) {
	isolateNodeInfoConfig(t)
	srv := newHostTrustServer(t, "")
	if err := srv.db.Create(&database.Node{Name: "worker", Address: "worker.example.com", Port: 443, TrafficRate: 1, Secret: "worker-secret"}).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}

	nodes := listNodes(t, srv, "attacker.evil.test")
	if len(nodes) != 1 {
		t.Fatalf("node count = %d, want 1 (synthetic entry must be omitted): %+v", len(nodes), nodes)
	}
	if nodes[0].Address != "worker.example.com" {
		t.Fatalf("unexpected node entry: %+v", nodes[0])
	}
}
