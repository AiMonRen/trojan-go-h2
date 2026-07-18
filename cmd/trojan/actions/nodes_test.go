package actions

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/voidluo/trojan-go/internal/database"
)

func setupTestDB(t *testing.T) {
	// 强制指向测试本地数据库
	dbPath = "test_nodes.db"
	os.Remove(dbPath) // 确保初始为空
}

func teardownTestDB() {
	os.Remove(dbPath)
}

func TestNodeCRUD(t *testing.T) {
	setupTestDB(t)
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

	// 验证 Secret 是否为合法的 UUID 格式
	if _, err := uuid.Parse(node.Secret); err != nil {
		t.Errorf("Secret is not a valid UUID: %s, error: %v", node.Secret, err)
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
