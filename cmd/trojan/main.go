package main

import (
	"fmt"
	"os"

	"github.com/voidluo/trojan-go/cmd/trojan/actions"
	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

func main() {
	// 允许通过环境变量指定数据库路径
	if dbPath := os.Getenv("TROJAN_DB"); dbPath != "" {
		actions.SetDBPath(dbPath)
	}

	// ─── 二级菜单：trojan 管理 ────────────────────────────
	trojanMenu := &menu.Menu{
		Title: menu.L{"trojan管理", "Trojan Management"},
		Items: []menu.Item{
			{Label: menu.L{"启动服务", "Start Service"}, Action: actions.TrojanStart},
			{Label: menu.L{"停止服务", "Stop Service"}, Action: actions.TrojanStop},
			{Label: menu.L{"重启服务", "Restart Service"}, Action: actions.TrojanRestart},
			{Label: menu.L{"查看状态", "Check Status"}, Action: actions.TrojanStatus},
		},
	}

	// ─── 二级菜单：用户管理 ────────────────────────────────
	userMenu := &menu.Menu{
		Title: menu.L{"用户管理", "User Management"},
		Items: []menu.Item{
			{Label: menu.L{"查看用户列表", "List Users"}, Action: actions.UserList},
			{Label: menu.L{"添加用户", "Add User"}, Action: actions.UserAdd},
			{Label: menu.L{"删除用户", "Delete User"}, Action: actions.UserDelete},
		},
	}

	// ─── 二级菜单：安装管理 ────────────────────────────────
	installMenu := &menu.Menu{
		Title: menu.L{"安装管理", "Installation Management"},
		Items: []menu.Item{
			{Label: menu.L{"申请SSL证书", "Apply SSL Certificate"}, Action: actions.ApplyCert},
			{Label: menu.L{"初始化部署（主节点）", "Initial Deployment (Master Node)"}, Action: actions.InitDeployMaster},
			{Label: menu.L{"初始化部署（从节点）", "Initial Deployment (Worker Node)"}, Action: actions.InitDeployWorker},
		},
	}

	// ─── 二级菜单：web 管理 ────────────────────────────────
	webMenu := &menu.Menu{
		Title: menu.L{"web管理", "Web Management"},
		Items: []menu.Item{
			{Label: menu.L{"修改管理员密码", "Change Admin Password"}, Action: actions.ChangeAdminPassword},
		},
	}

	// ─── 二级菜单：查看配置 ────────────────────────────────
	configMenu := &menu.Menu{
		Title: menu.L{"查看配置", "View Configuration"},
		Items: []menu.Item{
			{Label: menu.L{"显示当前配置", "Show Current Config"}, Action: actions.ShowConfig},
			{Label: menu.L{"切换 WebSocket 伪装", "Toggle WS Camouflage"}, Action: actions.ToggleWebSocket},
		},
	}

	// ─── 根菜单 ───────────────────────────────────────────
	root := &menu.Menu{
		Title: menu.L{"主菜单", "Main Menu"},
		Items: []menu.Item{
			{Label: menu.L{"trojan管理", "Trojan Management"}, Sub: trojanMenu},
			{Label: menu.L{"用户管理", "User Management"}, Sub: userMenu},
			{Label: menu.L{"安装管理", "Installation"}, Sub: installMenu},
			{Label: menu.L{"web管理", "Web Admin"}, Sub: webMenu},
			{Label: menu.L{"查看配置", "Config Info"}, Sub: configMenu},
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
