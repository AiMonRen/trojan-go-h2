package actions

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/voidluo/trojan-go/internal/database"
	"gopkg.in/yaml.v3"
)

// NodeList 列出所有节点
func NodeList() {
	loadDBPathFromConfig()
	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}
	var nodes []database.Node
	db.Find(&nodes)
	if len(nodes) == 0 {
		fmt.Println("暂无节点。")
		return
	}
	fmt.Printf("\033[1m%-5s %-15s %-20s %-6s %-10s %-8s %-10s\033[0m\n", "ID", "节点名称", "对外地址", "端口", "状态", "结算倍率", "WS状态")
	fmt.Println(strings.Repeat("─", 78))
	for _, n := range nodes {
		status := "\033[31m离线\033[0m"
		if n.Status == 1 {
			status = "\033[32m在线\033[0m"
		}
		wsStatus := "关闭"
		if n.WSEnabled {
			wsStatus = fmt.Sprintf("开启(%s)", n.WSPath)
		}
		fmt.Printf("%-5d %-15s %-20s %-6d %s %-8.2f %-10s\n", n.ID, n.Name, n.Address, n.Port, status, n.TrafficRate, wsStatus)
	}
}

// NodeAdd 添加节点（交互输入）
func NodeAdd() {
	loadDBPathFromConfig()
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("请输入节点名称 (必填，如 香港01): ")
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name == "" {
		fmt.Println("\033[31m节点名称不能为空！\033[0m")
		return
	}

	fmt.Print("请输入节点地址/域名 (必填，如 hk.example.com): ")
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr == "" {
		fmt.Println("\033[31m节点地址不能为空！\033[0m")
		return
	}

	fmt.Print("请输入对外端口 (默认 443): ")
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	port := 443
	if portStr != "" {
		fmt.Sscanf(portStr, "%d", &port)
	}

	fmt.Print("请输入流量结算倍率 (默认 1.0): ")
	rateStr, _ := reader.ReadString('\n')
	rateStr = strings.TrimSpace(rateStr)
	rate := 1.0
	if rateStr != "" {
		if _, err := fmt.Sscanf(rateStr, "%f", &rate); err != nil {
			fmt.Println("\033[31m流量结算倍率格式无效！\033[0m")
			return
		}
	}
	if err := database.ValidateTrafficRate(rate); err != nil {
		fmt.Printf("\033[31m流量结算倍率必须大于 0 且不超过 %d！\033[0m\n", database.MaxTrafficRate)
		return
	}

	fmt.Print("是否启用 WebSocket 伪装 (y/n, 默认 n): ")
	wsStr, _ := reader.ReadString('\n')
	wsStr = strings.ToLower(strings.TrimSpace(wsStr))
	wsEnabled := false
	wsPath := "/trojan-go"
	if wsStr == "y" || wsStr == "yes" {
		wsEnabled = true
		fmt.Print("请输入 WebSocket 路径 (默认 /trojan-go): ")
		wsPathStr, _ := reader.ReadString('\n')
		wsPathStr = strings.TrimSpace(wsPathStr)
		if wsPathStr != "" {
			wsPath = wsPathStr
		}
	}

	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}

	// 自动生成高强度随机 UUID 作为节点通信密钥
	nodeSecret := uuid.New().String()

	pendingSecret, err := database.PendingNodeSecretMarker()
	if err != nil {
		fmt.Printf("\033[31m添加节点失败: 无法准备凭据: %v\033[0m\n", err)
		return
	}
	node := database.Node{
		Name:        name,
		Address:     addr,
		Port:        port,
		Secret:      pendingSecret,
		TrafficRate: rate,
		WSEnabled:   wsEnabled,
		WSPath:      wsPath,
		Status:      0, // 初始离线状态
	}

	if err := db.Create(&node).Error; err != nil {
		fmt.Printf("\033[31m添加节点失败: %v\033[0m\n", err)
		return
	}
	if err := database.SetNodeSecret(db, &node, nodeSecret); err != nil {
		_ = db.Delete(&node).Error
		fmt.Printf("\033[31m添加节点失败: 凭据加密失败: %v\033[0m\n", err)
		return
	}
	fmt.Printf("\033[32m✓ 节点添加成功！\033[0m [名称: %s] [密钥: %s]\n", name, nodeSecret)
}

// NodeModify 修改节点（根据 ID）
func NodeModify() {
	loadDBPathFromConfig()
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("请输入要修改的节点 ID: ")
	idStr, _ := reader.ReadString('\n')
	idStr = strings.TrimSpace(idStr)
	var id uint
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		fmt.Println("\033[31m输入无效！\033[0m")
		return
	}

	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}

	var node database.Node
	if err := db.First(&node, id).Error; err != nil {
		fmt.Printf("\033[31m找不到指定的节点 ID=%d: %v\033[0m\n", id, err)
		return
	}
	fmt.Printf("请输入新的节点名称 (当前为 %s, 直接回车保持不变): ", node.Name)
	name, _ := reader.ReadString('\n')
	name = strings.TrimSpace(name)
	if name != "" {
		node.Name = name
	}

	fmt.Printf("请输入新的节点地址 (当前为 %s, 直接回车保持不变): ", node.Address)
	addr, _ := reader.ReadString('\n')
	addr = strings.TrimSpace(addr)
	if addr != "" {
		node.Address = addr
	}

	fmt.Printf("请输入新的对外端口 (当前为 %d, 直接回车保持不变): ", node.Port)
	portStr, _ := reader.ReadString('\n')
	portStr = strings.TrimSpace(portStr)
	if portStr != "" {
		var port int
		if _, err := fmt.Sscanf(portStr, "%d", &port); err == nil {
			node.Port = port
		}
	}

	fmt.Printf("请输入新的流量结算倍率 (当前为 %.2f, 直接回车保持不变): ", node.TrafficRate)
	rateStr, _ := reader.ReadString('\n')
	rateStr = strings.TrimSpace(rateStr)
	if rateStr != "" {
		var rate float64
		if _, err := fmt.Sscanf(rateStr, "%f", &rate); err != nil {
			fmt.Println("\033[31m流量结算倍率格式无效！\033[0m")
			return
		}
		if err := database.ValidateTrafficRate(rate); err != nil {
			fmt.Printf("\033[31m流量结算倍率必须大于 0 且不超过 %d！\033[0m\n", database.MaxTrafficRate)
			return
		}
		node.TrafficRate = rate
	}

	fmt.Print("是否修改 WebSocket 伪装设置？(y/n, 默认 n): ")
	chgWS, _ := reader.ReadString('\n')
	chgWS = strings.ToLower(strings.TrimSpace(chgWS))
	if chgWS == "y" || chgWS == "yes" {
		fmt.Printf("是否启用 WebSocket 伪装？(y/n, 当前为 %t): ", node.WSEnabled)
		wsStr, _ := reader.ReadString('\n')
		wsStr = strings.ToLower(strings.TrimSpace(wsStr))
		if wsStr == "y" || wsStr == "yes" {
			node.WSEnabled = true
			fmt.Printf("请输入 WebSocket 路径 (当前为 %s, 直接回车保持不变): ", node.WSPath)
			wsPathStr, _ := reader.ReadString('\n')
			wsPathStr = strings.TrimSpace(wsPathStr)
			if wsPathStr != "" {
				node.WSPath = wsPathStr
			}
		} else if wsStr == "n" || wsStr == "no" {
			node.WSEnabled = false
		}
	}

	if err := db.Save(&node).Error; err != nil {
		fmt.Printf("\033[31m保存修改失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ 节点修改成功！\033[0m")
}

// NodeDelete 删除节点（根据 ID）
func NodeDelete() {
	loadDBPathFromConfig()
	reader := bufio.NewReader(os.Stdin)

	fmt.Print("请输入要删除的节点 ID: ")
	idStr, _ := reader.ReadString('\n')
	idStr = strings.TrimSpace(idStr)
	var id uint
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		fmt.Println("\033[31m输入无效！\033[0m")
		return
	}

	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}

	var node database.Node
	if err := db.First(&node, id).Error; err != nil {
		fmt.Printf("\033[31m找不到指定的节点 ID=%d: %v\033[0m\n", id, err)
		return
	}

	fmt.Printf("警告：确定要删除节点 [%s] (%s) 吗？(y/n): ", node.Name, node.Address)
	ans, _ := reader.ReadString('\n')
	ans = strings.ToLower(strings.TrimSpace(ans))
	if ans != "y" && ans != "yes" {
		fmt.Println("操作已取消。")
		return
	}

	if err := db.Delete(&node).Error; err != nil {
		fmt.Printf("\033[31m删除失败: %v\033[0m\n", err)
		return
	}
	fmt.Printf("\033[32m✓ 节点 ID=%d 已删除。\033[0m\n", id)
}

// ShowNodeSyncURL 显示从节点同步接口 URL
func ShowNodeSyncURL() {
	var domain string

	// Gateway 配置持有公网 TLS 证书路径；域名通常仍由部署时输入。
	data, err := os.ReadFile("/etc/trojan-go/gateway.yaml")
	if err == nil {
		var cfg map[string]any
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			// 尝试从 TLS 证书目录名提取域名。
			if sslVal, ok := cfg["ssl"]; ok {
				var ssl map[string]any
				if sslMap, ok1 := sslVal.(map[string]any); ok1 {
					ssl = sslMap
				} else if sslAny, ok2 := sslVal.(map[any]any); ok2 {
					ssl = make(map[string]any)
					for k, v := range sslAny {
						if ks, ok3 := k.(string); ok3 {
							ssl[ks] = v
						}
					}
				}
				if ssl != nil {
					if certPath, ok4 := ssl["cert"].(string); ok4 && certPath != "" {
						domain = filepath.Base(filepath.Dir(certPath))
					}
				}
			}
		}
	}

	if domain == "" {
		domain = "[您的域名]"
	}

	fmt.Println("\033[36m========== 从节点同步接口信息 ==========\033[0m")
	fmt.Printf("主节点同步 URL: \033[32mhttps://%s/control/v1/nodes/sync\033[0m\n", domain)
	fmt.Println("请在从节点一键部署或从节点配置文件中的 node_sync.node.master_url 中填入上述 URL")
	fmt.Println("\033[36m========================================\033[0m")
}
