package actions

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/voidluo/trojan-go/internal/database"
)

func setupTestDB(t *testing.T) func() {
	t.Helper()
	originalDBPath := dbPath
	t.Setenv("TROJAN_CREDENTIAL_KEY_FILE", filepath.Join(t.TempDir(), "credentials.key"))
	if err := database.EnsureCredentialKey(); err != nil {
		t.Fatalf("ensure credential key: %v", err)
	}
	t.Setenv("TROJAN_DB", "test-managed")
	dbPath = filepath.Join(t.TempDir(), "nodes.db")
	return func() {
		dbPath = originalDBPath
	}
}

func withStdin(t *testing.T, input string, action func()) {
	t.Helper()
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdin pipe: %v", err)
	}
	os.Stdin = r
	if _, err := w.Write([]byte(input)); err != nil {
		t.Fatalf("write stdin: %v", err)
	}
	_ = w.Close()
	action()
	os.Stdin = oldStdin
	_ = r.Close()
}

func TestNodeAddRejectsInvalidTrafficRate(t *testing.T) {
	teardownTestDB := setupTestDB(t)
	defer teardownTestDB()

	db, err := database.InitDb(dbPath)
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	withStdin(t, "invalid-rate\ninvalid.example.com\n443\n-1\n", NodeAdd)

	var count int64
	if err := db.Model(&database.Node{}).Count(&count).Error; err != nil {
		t.Fatalf("count nodes: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid traffic rate created %d nodes", count)
	}
}

func TestNodeModifyRejectsInvalidTrafficRate(t *testing.T) {
	teardownTestDB := setupTestDB(t)
	defer teardownTestDB()

	db, err := database.InitDb(dbPath)
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	node := database.Node{Name: "worker", Address: "worker.example.com", Port: 443, TrafficRate: 1}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	withStdin(t, fmt.Sprintf("%d\n\n\n\n0\n", node.ID), NodeModify)

	if err := db.First(&node, node.ID).Error; err != nil {
		t.Fatalf("reload node: %v", err)
	}
	if node.TrafficRate != 1 {
		t.Fatalf("invalid traffic rate was persisted: %v", node.TrafficRate)
	}
}

func TestNodeCRUD(t *testing.T) {
	teardownTestDB := setupTestDB(t)
	defer teardownTestDB()

	db, err := database.InitDb(dbPath)
	if err != nil {
		t.Fatalf("Failed to init database: %v", err)
	}

	// ----------------- 1. 测试添加节点 (NodeAdd) -----------------
	// 模拟交互输入: 名称\n地址\n端口\n倍率\nws(y)\nws路径\n
	input := "HK-01\nhk.example.com\n443\n1.2\ny\n/ws-path\n"

	oldStdin := os.Stdin
	r, w, _ := os.Pipe()
	os.Stdin = r

	// 写入模拟输入
	w.Write([]byte(input))
	w.Close()

	// 执行添加
	NodeAdd()

	// 恢复标准输入
	os.Stdin = oldStdin
	r.Close()

	// 验证数据库中是否已有该记录
	var node database.Node
	if err := db.Where("name = ?", "HK-01").First(&node).Error; err != nil {
		t.Fatalf("Failed to find inserted node: %v", err)
	}

	if node.Address != "hk.example.com" || node.Port != 443 || node.TrafficRate != 1.2 || !node.WSEnabled || node.WSPath != "/ws-path" {
		t.Errorf("Node fields mismatched: %+v", node)
	}

	// Secret is encrypted at rest and no longer stored as a reusable UUID.
	if node.SecretCiphertext == "" || node.SecretHash == "" || strings.Contains(node.Secret, "-") {
		t.Errorf("Node Secret storage is not encrypted: %+v", node)
	}

	// ----------------- 2. 测试列出节点 (NodeList) -----------------
	// 捕获控制台输出
	oldStdout := os.Stdout
	rOut, wOut, _ := os.Pipe()
	os.Stdout = wOut

	NodeList()

	wOut.Close()
	var buf bytes.Buffer
	io.Copy(&buf, rOut)
	os.Stdout = oldStdout
	rOut.Close()

	outputStr := buf.String()
	if !strings.Contains(outputStr, "HK-01") || !strings.Contains(outputStr, "hk.example.com") {
		t.Errorf("NodeList output mismatched:\n%s", outputStr)
	}

	modifyInput := "1\nHK-01-Mod\n\n8443\n\nn\n"
	rMod, wMod, _ := os.Pipe()
	os.Stdin = rMod

	wMod.Write([]byte(modifyInput))
	wMod.Close()

	NodeModify()

	os.Stdin = oldStdin
	rMod.Close()

	var modNode database.Node
	db.First(&modNode, node.ID)
	if modNode.Name != "HK-01-Mod" || modNode.Port != 8443 || modNode.Address != "hk.example.com" {
		t.Errorf("NodeModify failed: %+v", modNode)
	}

	// ----------------- 4. 测试删除节点 (NodeDelete) -----------------
	// 模拟交互输入: 节点ID(1)\n确认(y)\n
	deleteInput := "1\ny\n"
	rDel, wDel, _ := os.Pipe()
	os.Stdin = rDel

	wDel.Write([]byte(deleteInput))
	wDel.Close()

	NodeDelete()

	os.Stdin = oldStdin
	rDel.Close()

	var delNode database.Node
	err = db.First(&delNode, node.ID).Error
	if err == nil {
		t.Errorf("Node was not deleted from database")
	}
}
