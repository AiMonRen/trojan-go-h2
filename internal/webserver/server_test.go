package webserver

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"github.com/voidluo/trojan-go/internal/database"
)

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
