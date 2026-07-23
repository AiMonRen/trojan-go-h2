package webserver

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/voidluo/trojan-go/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "trojan-go-webserver-credentials-*")
	if err != nil {
		panic(err)
	}
	_ = os.Setenv("TROJAN_CREDENTIAL_KEY_FILE", filepath.Join(dir, "credentials.key"))
	if err := database.EnsureCredentialKey(); err != nil {
		panic(err)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func TestWorkerNodeSubBlocking(t *testing.T) {
	// 使用内存 SQLite 作为临时 DB
	db, err := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("Failed to open sqlite: %v", err)
	}
	db.AutoMigrate(&database.User{}, &database.Config{}, &database.Node{})

	// 1. 创建一个 isNode = true （从节点模式）的 AdminServer
	srv := New(db, "admin", "trojan@123", "/admin", 0, false, "", false, true, "", "/sub-test", "vpn.example.com")

	// 2. 模拟请求混淆后的订阅接口
	req, _ := http.NewRequest("GET", "/sub-test?token=some-token", nil)
	resp := httptest.NewRecorder()

	srv.handler.ServeHTTP(resp, req)

	// 3. 验证是否被安全拦截（从节点不提供订阅，应该被拦截并直接返回伪装 Welcome to nginx）
	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK (mask page), got %d", resp.Code)
	}
	if resp.Body.String() != "Welcome to nginx" {
		t.Errorf("Expected 'Welcome to nginx' mask page, got %s", resp.Body.String())
	}
}

func TestLoginFailureRateLimitAndRequestBodyLimit(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	srv := New(db, "admin", "correct-password", "/admin", 0, false, "", false, false, "", "/sub-test", "vpn.example.com")

	for attempt := 0; attempt < loginFailureLimit; attempt++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
		req.RemoteAddr = "203.0.113.10:12345"
		resp := httptest.NewRecorder()
		srv.handler.ServeHTTP(resp, req)
		if resp.Code != http.StatusUnauthorized {
			t.Fatalf("failed login %d returned %d, want %d", attempt+1, resp.Code, http.StatusUnauthorized)
		}
	}
	blockedReq := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"username":"admin","password":"wrong"}`))
	blockedReq.RemoteAddr = "203.0.113.10:12345"
	blockedResp := httptest.NewRecorder()
	srv.handler.ServeHTTP(blockedResp, blockedReq)
	if blockedResp.Code != http.StatusTooManyRequests {
		t.Fatalf("login after %d failures returned %d, want %d", loginFailureLimit, blockedResp.Code, http.StatusTooManyRequests)
	}

	oversized := bytes.Repeat([]byte("x"), maxAdminRequestBody+1)
	bodyReq := httptest.NewRequest(http.MethodPost, "/admin/api/login", bytes.NewReader(oversized))
	bodyReq.RemoteAddr = "203.0.113.11:12345"
	bodyResp := httptest.NewRecorder()
	srv.handler.ServeHTTP(bodyResp, bodyReq)
	if bodyResp.Code != http.StatusBadRequest {
		t.Fatalf("oversized body returned %d, want %d", bodyResp.Code, http.StatusBadRequest)
	}
	if _, err := io.ReadAll(bodyResp.Result().Body); err != nil {
		t.Fatalf("read response: %v", err)
	}
}

func TestCredentialDisclosureControls(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "credentials-api.db"))
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	node := database.Node{Name: "worker", Address: "worker.example.com", Port: 443, Secret: "initial"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	if err := database.SetNodeSecret(db, &node, "worker-secret"); err != nil {
		t.Fatalf("encrypt node secret: %v", err)
	}
	if err := db.Create(&database.Config{Key: "database_dsn", Value: "mysql:root:secret"}).Error; err != nil {
		t.Fatalf("save DSN: %v", err)
	}
	srv := New(db, "admin", "password", "/admin", 0, false, "", false, false, "", "/sub-test", "vpn.example.com")

	loginReq := httptest.NewRequest(http.MethodPost, "/admin/api/login", strings.NewReader(`{"username":"admin","password":"password"}`))
	loginResp := httptest.NewRecorder()
	srv.handler.ServeHTTP(loginResp, loginReq)
	if loginResp.Code != http.StatusOK {
		t.Fatalf("login returned %d: %s", loginResp.Code, loginResp.Body.String())
	}
	var login struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(loginResp.Body.Bytes(), &login); err != nil || login.Token == "" {
		t.Fatalf("decode login token: %v", err)
	}
	authorized := func(method, path string, body io.Reader) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+login.Token)
		resp := httptest.NewRecorder()
		srv.handler.ServeHTTP(resp, req)
		return resp
	}

	nodesResp := authorized(http.MethodGet, "/admin/api/nodes", nil)
	if nodesResp.Code != http.StatusOK || strings.Contains(nodesResp.Body.String(), "worker-secret") || strings.Contains(nodesResp.Body.String(), "secret_ciphertext") {
		t.Fatalf("node list disclosed credential: code=%d body=%s", nodesResp.Code, nodesResp.Body.String())
	}
	settingsResp := authorized(http.MethodGet, "/admin/api/settings", nil)
	if settingsResp.Code != http.StatusOK || strings.Contains(settingsResp.Body.String(), "database_dsn") || strings.Contains(settingsResp.Body.String(), "jwt_secret") || strings.Contains(settingsResp.Body.String(), "admin_password") {
		t.Fatalf("settings disclosed sensitive config: code=%d body=%s", settingsResp.Code, settingsResp.Body.String())
	}
	blockedResp := authorized(http.MethodPost, "/admin/api/settings", strings.NewReader(`{"admin_password":"plaintext"}`))
	if blockedResp.Code != http.StatusBadRequest {
		t.Fatalf("protected setting write returned %d, want 400", blockedResp.Code)
	}
	rotateResp := authorized(http.MethodPost, fmt.Sprintf("/admin/api/nodes/%d/secret/rotate", node.ID), nil)
	if rotateResp.Code != http.StatusOK || !strings.Contains(rotateResp.Body.String(), `"secret"`) {
		t.Fatalf("node secret rotation failed: code=%d body=%s", rotateResp.Code, rotateResp.Body.String())
	}
	var rotate struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(rotateResp.Body.Bytes(), &rotate); err != nil || rotate.Secret == "" {
		t.Fatalf("decode rotated secret: %v", err)
	}
	if _, err := database.NodeBySecret(db, "worker-secret"); err == nil {
		t.Fatal("old node secret must fail after rotation")
	}
	if _, err := database.NodeBySecret(db, rotate.Secret); err != nil {
		t.Fatalf("rotated node secret rejected: %v", err)
	}
}

func TestSubscriptionETagConditionalRequest(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "subscription.db"))
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	if err := db.Create(&database.User{Username: "subscriber", Password: "password", Hash: "subscription-token"}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	srv := New(db, "admin", "password", "/admin", 0, false, "", false, false, "", "/sub-test", "vpn.example.com")

	firstReq := httptest.NewRequest(http.MethodGet, "/sub-test?token=subscription-token", nil)
	firstReq.Host = "vpn.example.com"
	firstResp := httptest.NewRecorder()
	srv.handler.ServeHTTP(firstResp, firstReq)
	if firstResp.Code != http.StatusOK {
		t.Fatalf("subscription returned %d, want %d", firstResp.Code, http.StatusOK)
	}
	etag := firstResp.Header().Get("ETag")
	if etag == "" {
		t.Fatal("subscription response must include ETag")
	}

	conditionalReq := httptest.NewRequest(http.MethodGet, "/sub-test?token=subscription-token", nil)
	conditionalReq.Host = "vpn.example.com"
	conditionalReq.Header.Set("If-None-Match", etag)
	conditionalResp := httptest.NewRecorder()
	srv.handler.ServeHTTP(conditionalResp, conditionalReq)
	if conditionalResp.Code != http.StatusNotModified {
		t.Fatalf("conditional subscription returned %d, want %d", conditionalResp.Code, http.StatusNotModified)
	}
}

func TestGenerateClashConfigDualProtocolAndAIGrouping(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:clash-subscription?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &database.Config{}, &database.Node{}); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	configs := []database.Config{
		{Key: "hysteria_enabled", Value: "true"},
		{Key: "hysteria_port", Value: "443"},
		{Key: "hysteria_up_mbps", Value: "100"},
		{Key: "hysteria_down_mbps", Value: "300"},
		{Key: "node_location", Value: "香港"},
		{Key: "clash_test_url", Value: "https://example.com/generate_204"},
		{Key: "reality_enabled", Value: "true"},
		{Key: "reality_public_key", Value: "unused-public-key"},
		{Key: "tuic_enabled", Value: "true"},
	}
	if err := db.Create(&configs).Error; err != nil {
		t.Fatalf("seed test config: %v", err)
	}

	user := database.User{Username: "test", Password: "test-password"}
	nodes := []database.Node{
		{Name: "美国", Address: "us.example.com", Port: 443, SNI: "us.example.com"},
		{Name: "美国(港转)", Address: "relay.example.com", Port: 9443, SNI: "xjp.example.com"},
	}
	config := generateClashConfigMultiNode(db, user, nodes, "hk.example.com", 443, false, "")

	for _, want := range []string{
		"type: trojan",
		"type: hysteria2",
		"name: \"🌐 节点选择\"",
		"name: \"♻️ 自动选择\"",
		"name: \"TROJAN\"",
		"name: \"HYSTERIA\"",
		"name: \"🤖 AI 服务\"",
		"name: \"💻 AI 编程\"",
		"name: \"Ⓜ️ 微软服务\"",
		"name: \"🎯 全球直连\"",
		"name: \"🐟 漏网之鱼\"",
		"tcp-香港",
		"h-香港",
		"tcp-美国(港转)",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("generated config missing %q\n%s", want, config)
		}
	}
	for _, forbidden := range []string{"type: vless", "type: tuic", "name: \"REALITY\"", "name: \"TUIC\"", "vl-", "tu-"} {
		if strings.Contains(config, forbidden) {
			t.Errorf("generated config unexpectedly contains %q\n%s", forbidden, config)
		}
	}
	if strings.Contains(config, "h-美国(港转)") {
		t.Errorf("relay node must not generate a Hysteria2 variant\n%s", config)
	}
	for _, want := range []string{
		"skip-cert-verify: false",
		"server: relay.example.com\n    port: 9443\n    password: test-password\n    udp: true\n    sni: xjp.example.com\n    skip-cert-verify: false",
	} {
		if !strings.Contains(config, want) {
			t.Errorf("generated config must verify TLS certificates and preserve relay SNI %q\n%s", want, config)
		}
	}
	if strings.Contains(config, "skip-cert-verify: true") {
		t.Errorf("generated config must not disable TLS certificate verification\n%s", config)
	}
	for _, groupName := range []string{"🤖 AI 服务", "💻 AI 编程", "Ⓜ️ 微软服务", "🎯 全球直连"} {
		groupPrefix := fmt.Sprintf("  - name: \"%s\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"", groupName)
		if !strings.Contains(config, groupPrefix) {
			t.Errorf("service group %q must offer the follow-node-selection option\n%s", groupName, config)
		}
	}
}

func TestGenerateClashConfigUsesValidFallbackRulesWithoutDatabaseRules(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:clash-fallback-rules?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &database.Config{}, &database.Node{}); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}

	config := generateClashConfigMultiNode(db, database.User{Username: "test", Password: "test-password"}, nil, "hk.example.com", 443, false, "")
	for _, want := range []string{"GEOIP,CN,🎯 全球直连", "MATCH,🐟 漏网之鱼"} {
		if !strings.Contains(config, want) {
			t.Errorf("fallback config missing %q\n%s", want, config)
		}
	}
	if strings.Contains(config, "MATCH,PROXY") {
		t.Errorf("fallback config still references removed PROXY group\n%s", config)
	}
}

func TestGenerateClashConfigPreservesCustomRules(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:clash-custom-rules?mode=memory&cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	if err := db.AutoMigrate(&database.User{}, &database.Config{}, &database.Node{}); err != nil {
		t.Fatalf("migrate test database: %v", err)
	}
	customRules := "  - DOMAIN-SUFFIX,example.test,🤖 AI 服务\n  - MATCH,🐟 漏网之鱼"
	if err := db.Create(&database.Config{Key: "clash_rules", Value: customRules}).Error; err != nil {
		t.Fatalf("seed custom rules: %v", err)
	}

	config := generateClashConfigMultiNode(db, database.User{Username: "test", Password: "test-password"}, nil, "hk.example.com", 443, false, "")
	if !strings.Contains(config, customRules) {
		t.Errorf("generated config did not preserve custom rules\n%s", config)
	}
	if strings.Contains(config, "GEOIP,CN,DIRECT") {
		t.Errorf("generated config unexpectedly appended fallback rules despite custom rules\n%s", config)
	}
}

func TestInitDbMigratesLegacySubscriptionRules(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy-rules.db")
	db, err := database.InitDb(dbPath)
	if err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	legacyRules := "  - DOMAIN-SUFFIX,google.com,PROXY\n  - MATCH,PROXY"
	if err := db.Model(&database.Config{}).Where("key = ?", "clash_rules").Update("value", legacyRules).Error; err != nil {
		t.Fatalf("seed legacy rules: %v", err)
	}
	// Simulate a pre-4.4 database: it has legacy data but no applied version records.
	if err := db.Where("version BETWEEN ? AND ?", 1, 4).Delete(&database.SchemaMigration{}).Error; err != nil {
		t.Fatalf("remove migration history for legacy simulation: %v", err)
	}

	if _, err := database.InitDb(dbPath); err != nil {
		t.Fatalf("reinitialize database: %v", err)
	}
	var config database.Config
	if err := db.Where("key = ?", "clash_rules").First(&config).Error; err != nil {
		t.Fatalf("read migrated rules: %v", err)
	}
	for _, want := range []string{
		"DOMAIN-SUFFIX,google.com,🌐 节点选择",
		"DOMAIN-SUFFIX,openai.com,🤖 AI 服务",
		"DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程",
		"MATCH,🐟 漏网之鱼",
	} {
		if !strings.Contains(config.Value, want) {
			t.Errorf("migrated rules missing %q\n%s", want, config.Value)
		}
	}
	if strings.Contains(config.Value, ",PROXY") {
		t.Errorf("migrated rules still reference removed PROXY group\n%s", config.Value)
	}
}

func TestInitDbPrioritizesExistingAIRulesBeforeBroadRuleSets(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "ai-rule-order.db")
	db, err := database.InitDb(dbPath)
	if err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	legacyRules := "  - RULE-SET,proxy,🌐 节点选择\n  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务\n  - DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程\n  - MATCH,🐟 漏网之鱼"
	if err := db.Model(&database.Config{}).Where("key = ?", "clash_rules").Update("value", legacyRules).Error; err != nil {
		t.Fatalf("seed legacy AI rule order: %v", err)
	}
	// Simulate a pre-4.4 database: it has legacy data but no applied version records.
	if err := db.Where("version BETWEEN ? AND ?", 1, 4).Delete(&database.SchemaMigration{}).Error; err != nil {
		t.Fatalf("remove migration history for legacy simulation: %v", err)
	}
	if _, err := database.InitDb(dbPath); err != nil {
		t.Fatalf("reinitialize database: %v", err)
	}

	var config database.Config
	if err := db.Where("key = ?", "clash_rules").First(&config).Error; err != nil {
		t.Fatalf("read migrated rules: %v", err)
	}
	for _, aiRule := range []string{
		"DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务",
		"DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程",
	} {
		if strings.Index(config.Value, aiRule) > strings.Index(config.Value, "RULE-SET,proxy,🌐 节点选择") {
			t.Errorf("AI rule %q must precede the broad proxy rule set\n%s", aiRule, config.Value)
		}
	}
}

func TestStandalonePortMaskHtml(t *testing.T) {
	// 创建一个临时测试伪装 HTML 文件
	tmpHtml := "test_mask.html"
	content := "<html><body>Hello, this is a fake blog.</body></html>"
	err := os.WriteFile(tmpHtml, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create tmp html: %v", err)
	}
	defer os.Remove(tmpHtml)

	db, _ := gorm.Open(sqlite.Open("file::memory:?cache=shared"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	db.AutoMigrate(&database.User{}, &database.Config{}, &database.Node{})

	// 创建带 maskHtmlPath 的 AdminServer
	srv := New(db, "admin", "trojan@123", "/admin", 0, false, "", false, false, tmpHtml, "", "vpn.example.com")

	if srv.serverDomain != "vpn.example.com" {
		t.Errorf("Expected serverDomain vpn.example.com, got %s", srv.serverDomain)
	}

	// 1. 模拟请求根目录 /
	req, _ := http.NewRequest("GET", "/", nil)
	resp := httptest.NewRecorder()
	srv.handler.ServeHTTP(resp, req)

	if resp.Code != http.StatusOK {
		t.Errorf("Expected status OK, got %d", resp.Code)
	}
	if resp.Body.String() != content {
		t.Errorf("Expected mask html content, got %s", resp.Body.String())
	}

	// 2. 模拟请求未知探测路由 /some-random-route-to-probe
	req2, _ := http.NewRequest("GET", "/some-random-route-to-probe", nil)
	resp2 := httptest.NewRecorder()
	srv.handler.ServeHTTP(resp2, req2)

	if resp2.Code != http.StatusOK {
		t.Errorf("Expected status OK for NoRoute mask, got %d", resp2.Code)
	}
	if resp2.Body.String() != content {
		t.Errorf("Expected mask html content for NoRoute, got %s", resp2.Body.String())
	}
}
