package actions

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

var dbPath = "/etc/trojan-go/trojan-go.db"

// SetDBPath 设置数据库路径。
func SetDBPath(path string) { dbPath = path }

// loadDBPathFromConfig 尝试从系统配置加载数据库路径。
func loadDBPathFromConfig() {
	if os.Getenv("TROJAN_DB") != "" {
		return
	}
	data, err := os.ReadFile("/etc/trojan-go/web_config.yaml")
	if err != nil {
		data, err = os.ReadFile("/etc/trojan-go/config.yaml")
		if err != nil {
			return
		}
	}
	var cfg map[string]any
	if yaml.Unmarshal(data, &cfg) != nil {
		return
	}
	adminVal, ok := cfg["admin"]
	if !ok {
		return
	}
	var admin map[string]any
	if value, ok := adminVal.(map[string]any); ok {
		admin = value
	} else if value, ok := adminVal.(map[any]any); ok {
		admin = make(map[string]any)
		for k, v := range value {
			if key, ok := k.(string); ok {
				admin[key] = v
			}
		}
	} else {
		return
	}
	if value, ok := admin["db"].(string); ok && value != "" {
		dbPath = value
	}
}

// UserList 列出所有用户，不显示可复用密码。
func UserList() {
	loadDBPathFromConfig()
	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}
	var users []database.User
	if err := db.Find(&users).Error; err != nil {
		fmt.Printf("\033[31m读取用户失败: %v\033[0m\n", err)
		return
	}
	if len(users) == 0 {
		fmt.Println("暂无用户。")
		return
	}
	fmt.Printf("\033[1m%-5s %-20s %-15s %-12s\033[0m\n", "ID", "用户名/备注", "已用流量(MB)", "状态")
	fmt.Println(strings.Repeat("─", 65))
	for _, u := range users {
		status := "\033[32m正常\033[0m"
		if u.Status == 1 {
			status = "\033[31m禁用\033[0m"
		} else if u.ExpiryTime != nil && !u.ExpiryTime.IsZero() && u.ExpiryTime.Before(time.Now()) {
			status = "\033[33m已过期\033[0m"
		}
		name := u.Username
		if name == "" {
			name = "-"
		}
		fmt.Printf("%-5d %-20s %-15.2f %s\n", u.ID, name, float64(u.Used)/1024/1024, status)
	}
}

func readSecret(prompt string) (string, error) {
	fmt.Print(prompt)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		return strings.TrimSpace(string(value)), err
	}
	reader := bufio.NewReader(os.Stdin)
	value, err := reader.ReadString('\n')
	return strings.TrimSpace(value), err
}

// UserAdd 添加用户（交互输入）。
func UserAdd() {
	loadDBPathFromConfig()
	password, err := readSecret("请输入新密码: ")
	if err != nil {
		fmt.Printf("读取密码失败: %v\n", err)
		return
	}
	if password == "" {
		fmt.Println("密码不能为空！")
		return
	}
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("请输入备注/用户名 (必填): ")
	username, _ := reader.ReadString('\n')
	username = strings.TrimSpace(username)
	if username == "" {
		fmt.Println("\033[31m用户名/备注不能为空！\033[0m")
		return
	}
	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}
	user := database.User{Username: username, Hash: common.SHA224String(password)}
	var existing database.User
	if err := db.Where("hash = ?", user.Hash).First(&existing).Error; err == nil {
		fmt.Printf("\033[31m创建用户失败: 此密码已被用户 [%s] 使用！\033[0m\n", existing.Username)
		return
	}
	if err := db.Create(&user).Error; err != nil {
		fmt.Printf("\033[31m创建用户失败: %v\033[0m\n", err)
		return
	}
	if err := database.SetUserPassword(db, &user, password); err != nil {
		_ = db.Delete(&user).Error
		fmt.Printf("\033[31m创建用户失败: 凭据加密失败: %v\033[0m\n", err)
		return
	}
	fmt.Printf("\033[32m✓ 用户添加成功！\033[0m [备注: %s]\n", username)
}

// UserDelete 删除用户（交互输入 ID）。
func UserDelete() {
	loadDBPathFromConfig()
	fmt.Print("请输入要删除的用户 ID: ")
	var id uint
	fmt.Scan(&id)
	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}
	if err := db.Delete(&database.User{}, id).Error; err != nil {
		fmt.Printf("\033[31m删除失败: %v\033[0m\n", err)
		return
	}
	fmt.Printf("\033[32m✓ 用户 ID=%d 已删除。\033[0m\n", id)
}

// ChangeAdminPassword 修改 Web 控制台管理员密码。
func ChangeAdminPassword() {
	loadDBPathFromConfig()
	password, err := readSecret("请输入新的 Web 控制台 admin 密码 (留空取消): ")
	if err != nil {
		fmt.Printf("读取密码失败: %v\n", err)
		return
	}
	if password == "" {
		fmt.Println("操作已取消。")
		return
	}
	db, err := database.InitDb(dbPath)
	if err != nil {
		fmt.Printf("\033[31m数据库连接失败: %v\033[0m\n", err)
		return
	}
	if err := database.SetAdminPassword(db, password); err != nil {
		fmt.Printf("\033[31m更新密码失败: %v\033[0m\n", err)
		return
	}
	if _, err := database.RotateJWTSecret(db); err != nil {
		fmt.Printf("\033[31m轮换管理会话密钥失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ Web 控制台 admin 密码已成功修改；请重启管理服务以立即使旧会话失效。\033[0m")
}
