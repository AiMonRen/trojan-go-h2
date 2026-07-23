package main

import (
	"fmt"
	"os"

	"github.com/voidluo/trojan-go/cmd/trojan/actions"
	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

func main() {
	if len(os.Args) == 4 && os.Args[1] == "cert-renew" && os.Args[2] == "--config" {
		if err := actions.RenewCertificateFromConfig(os.Args[3]); err != nil {
			fmt.Fprintf(os.Stderr, "certificate renewal failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// 允许通过环境变量指定数据库路径
	if dbPath := os.Getenv("TROJAN_DB"); dbPath != "" {
		actions.SetDBPath(dbPath)
	}

	// ─── 二级菜单：服务运维与部署 ────────────────────────────
	opsMenu := &menu.Menu{
		Title: menu.L{"服务运维与部署", "Service Ops & Deployment"},
		Items: []menu.Item{
			{Label: menu.L{"启动服务", "Start Service"}, Action: actions.TrojanStart},
			{Label: menu.L{"停止服务", "Stop Service"}, Action: actions.TrojanStop},
			{Label: menu.L{"重启服务", "Restart Service"}, Action: actions.TrojanRestart},
			{Label: menu.L{"查看状态", "Check Status"}, Action: actions.TrojanStatus},
			{Label: menu.L{"申请 SSL 证书", "Apply SSL Certificate"}, Action: actions.ApplyCert},
			{Label: menu.L{"初始化一键部署（主节点）", "Initial Deployment (Master Node)"}, Action: actions.InitDeployMaster},
			{Label: menu.L{"初始化一键部署（从节点）", "Initial Deployment (Worker Node)"}, Action: actions.InitDeployWorker},
		},
	}

	// ─── 二级子菜单：用户管理与节点管理 ──────────────────────
	userSubMenu := &menu.Menu{
		Title: menu.L{"用户管理", "User Management"},
		Items: []menu.Item{
			{Label: menu.L{"查看用户列表", "List Users"}, Action: actions.UserList},
			{Label: menu.L{"添加用户", "Add User"}, Action: actions.UserAdd},
			{Label: menu.L{"删除用户", "Delete User"}, Action: actions.UserDelete},
		},
	}

	nodeSubMenu := &menu.Menu{
		Title: menu.L{"节点管理", "Node Management"},
		Items: []menu.Item{
			{Label: menu.L{"查看节点列表", "List Nodes"}, Action: actions.NodeList},
			{Label: menu.L{"添加节点", "Add Node"}, Action: actions.NodeAdd},
			{Label: menu.L{"修改节点", "Modify Node"}, Action: actions.NodeModify},
			{Label: menu.L{"删除节点", "Delete Node"}, Action: actions.NodeDelete},
			{Label: menu.L{"查看从节点同步 URL", "Show Node Sync URL"}, Action: actions.ShowNodeSyncURL},
		},
	}

	// ─── 二级菜单：代理数据管理 ────────────────────────────
	dataMenu := &menu.Menu{
		Title: menu.L{"代理数据管理", "Proxy Data Admin"},
		Items: []menu.Item{
			{Label: menu.L{"用户管理", "User Management"}, Sub: userSubMenu},
			{Label: menu.L{"节点管理", "Node Management"}, Sub: nodeSubMenu},
		},
	}

	// ─── 二级菜单：配置与安全管理 ──────────────────────────
	configMenu := &menu.Menu{
		Title: menu.L{"配置与安全管理", "Config & Security"},
		Items: []menu.Item{
			{Label: menu.L{"显示当前配置", "Show Current Config"}, Action: actions.ShowConfig},
			{Label: menu.L{"切换 WebSocket 伪装", "Toggle WS Camouflage"}, Action: actions.ToggleWebSocket},
			{Label: menu.L{"修改管理员密码", "Change Admin Password"}, Action: actions.ChangeAdminPassword},
		},
	}

	// ─── 根菜单 ───────────────────────────────────────────
	root := &menu.Menu{
		Title: menu.L{"主菜单", "Main Menu"},
		Items: []menu.Item{
			{Label: menu.L{"服务运维与部署", "Service Ops & Deployment"}, Sub: opsMenu},
			{Label: menu.L{"代理数据管理", "Proxy Data Admin"}, Sub: dataMenu},
			{Label: menu.L{"配置与安全管理", "Config & Security"}, Sub: configMenu},
			{Label: menu.L{"切换语言 / Toggle Language", "Toggle Language / 切换语言"}, Action: func() {
				if menu.CurrentLang == menu.CN {
					menu.CurrentLang = menu.EN
				} else {
					menu.CurrentLang = menu.CN
				}
			}},
		},
	}

	if root.Run() {
		if menu.CurrentLang == menu.CN {
			fmt.Println("\n再见！")
		} else {
			fmt.Println("\nGoodbye!")
		}
	}
}
