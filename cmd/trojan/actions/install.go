package actions

import (
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

// InitDeployMaster 初始化部署（主节点）一键化流程
func InitDeployMaster() {
	// 动态生成 6 位随机字符组成 websocket 路径
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	randChars := make([]byte, 6)
	for i := range randChars {
		randChars[i] = letters[r.Intn(len(letters))]
	}
	wsPath := "/stream-v2-" + string(randChars)

	if os.Geteuid() != 0 {
		msg := "错误：安装操作需要 sudo 权限！"
		if menu.CurrentLang == menu.EN {
			msg = "Error: Installation requires sudo privileges!"
		}
		fmt.Printf("\033[31m%s\033[0m\n", msg)
		return
	}

	// 自定义部署路径
	deployPath := getStdin("请输入部署路径 (直接回车为默认 /etc/trojan-go): ", "Enter deployment path (default /etc/trojan-go): ")
	if deployPath == "" {
		deployPath = "/etc/trojan-go"
	}
	deployPath = strings.TrimSuffix(deployPath, "/")

	// 自定义代理服务端口
	localPortStr := getStdin("请输入代理服务端口 (默认 443): ", "Enter proxy service port (default 443): ")
	localPort := 443
	if localPortStr != "" {
		fmt.Sscanf(localPortStr, "%d", &localPort)
	}

	configPath := filepath.Join(deployPath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("\033[33m检测到配置文件已存在，继续操作将覆盖它。\033[0m")
		ans := getStdin("是否继续？(y/n): ", "Continue? (y/n): ")
		if ans != "y" && ans != "Y" {
			return
		}
	}

	title := "=== 初始化部署（主节点） ==="
	infoMsg := "请依次输入所有配置信息，随后程序将自动完成证书申请和部署："
	if menu.CurrentLang == menu.EN {
		title = "=== Initial Deployment (Master Node) ==="
		infoMsg = "Please enter all configuration information, then the program will automatically complete certificate application and deployment:"
	}
	fmt.Printf("\n\033[36m%s\033[0m\n%s\n\n", title, infoMsg)

	// 1. 域名
	domain := getStdin("1. 请输入您的域名 (如 proxy.example.com): ", "1. Enter your domain (e.g. proxy.example.com): ")
	if domain == "" {
		fmt.Println("域名不能为空")
		return
	}

	// 2. 邮箱
	email := getStdin("2. 请输入邮箱 (用于注册 ACME 账户): ", "2. Enter your email (for ACME registration): ")
	if email == "" {
		fmt.Println("邮箱不能为空")
		return
	}

	// 3. 选择 CA
	fmt.Println("3. 请选择证书颁发机构 (CA):")
	fmt.Println("   1. Let's Encrypt (默认)")
	fmt.Println("   2. BuyPass (Go SSL)")
	caChoice := getStdin("   请选择 [1-2]: ", "   Select [1-2]: ")
	caURL := "https://acme-v02.api.letsencrypt.org/directory"
	caName := "Let's Encrypt"
	if caChoice == "2" {
		caURL = "https://api.buypass.com/acme/directory"
		caName = "BuyPass"
	}

	// 4. 管理面板用户名
	adminUser := getStdin("4. 设置管理面板用户名 (默认 admin): ", "4. Set admin username (default admin): ")
	if adminUser == "" {
		adminUser = "admin"
	}

	// 5. 管理面板密码
	adminPwd := getStdin("5. 设置管理面板密码 (默认 trojan@123): ", "5. Set admin password (default trojan@123): ")
	if adminPwd == "" {
		adminPwd = "trojan@123"
	}

	// 6. 管理面板监听端口
	adminPortStr := getStdin("6. 设置管理面板监听端口 (推荐 80): ", "6. Set admin port (recommended 80): ")
	adminPort := 80
	if adminPortStr != "" {
		fmt.Sscanf(adminPortStr, "%d", &adminPort)
	}

	// 7. 请选择数据库类型
	fmt.Println("7. 请选择数据库类型:")
	fmt.Println("   1. SQLite (默认)")
	fmt.Println("   2. 部署 Docker 版 MySQL")
	fmt.Println("   3. 使用外部/已有 MySQL 服务")
	dbChoice := getStdin("   请选择 [1-3]: ", "   Select [1-3]: ")

	var dbPath string
	var deployDockerMySQL bool
	var mysqlPort int = 3306
	var mysqlPass string
	var mysqlDB string = "trojan_go"

	if dbChoice == "2" {
		deployDockerMySQL = true
		mysqlPortStr := getStdin("   输入 Docker MySQL 映射端口 (默认 3306): ", "   Enter Docker MySQL host port (default 3306): ")
		if mysqlPortStr != "" {
			fmt.Sscanf(mysqlPortStr, "%d", &mysqlPort)
		}
		// 动态生成 10 位强随机密码
		const pwLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		defaultMySQLPass := make([]byte, 10)
		for i := range defaultMySQLPass {
			defaultMySQLPass[i] = pwLetters[r.Intn(len(pwLetters))]
		}
		defaultMySQLPassStr := string(defaultMySQLPass)

		promptCN := fmt.Sprintf("   输入 Docker MySQL root 密码 (默认随机: %s): ", defaultMySQLPassStr)
		promptEN := fmt.Sprintf("   Enter Docker MySQL root password (default random: %s): ", defaultMySQLPassStr)
		mysqlPass = getStdin(promptCN, promptEN)
		if mysqlPass == "" {
			mysqlPass = defaultMySQLPassStr
		}
		mysqlDBInput := getStdin("   输入 Docker MySQL 自动创建的数据库名 (默认 trojan_go): ", "   Enter Docker MySQL database name (default trojan_go): ")
		if mysqlDBInput != "" {
			mysqlDB = mysqlDBInput
		}
		dbPath = fmt.Sprintf("mysql:root:%s@tcp(127.0.0.1:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local", mysqlPass, mysqlPort, mysqlDB)

	} else if dbChoice == "3" {
		mysqlHost := getStdin("   输入 MySQL 服务端地址 (默认 127.0.0.1): ", "   Enter MySQL host (default 127.0.0.1): ")
		if mysqlHost == "" {
			mysqlHost = "127.0.0.1"
		}
		mysqlPortStr := getStdin("   输入 MySQL 服务端端口 (默认 3306): ", "   Enter MySQL port (default 3306): ")
		if mysqlPortStr != "" {
			fmt.Sscanf(mysqlPortStr, "%d", &mysqlPort)
		}
		mysqlUser := getStdin("   输入 MySQL 用户名 (默认 root): ", "   Enter MySQL username (default root): ")
		if mysqlUser == "" {
			mysqlUser = "root"
		}
		mysqlPass = getStdin("   输入 MySQL 密码 (必填): ", "   Enter MySQL password (required): ")
		if mysqlPass == "" {
			fmt.Println("❌ 密码不能为空")
			return
		}
		mysqlDBInput := getStdin("   输入 MySQL 数据库名称 (默认 trojan_go): ", "   Enter MySQL database name (default trojan_go): ")
		if mysqlDBInput != "" {
			mysqlDB = mysqlDBInput
		}
		dbPath = fmt.Sprintf("mysql:%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local", mysqlUser, mysqlPass, mysqlHost, mysqlPort, mysqlDB)

	} else {
		dbPath = filepath.Join(deployPath, "trojan-go.db")
	}

	// 开始执行操作
	fmt.Println("\n\033[36m=== 开始执行初始化部署 ===\033[0m")

	// ─── 步骤 1: 申请 SSL 证书 ────────────────────────────
	fmt.Printf("\n[1/5] 正在为 %s 申请 SSL 证书 (%s)...\n", domain, caName)
	certs, err := obtainCert(domain, email, caURL)
	if err != nil {
		fmt.Printf("\033[31m❌ 证书申请失败: %v\033[0m\n", err)
		return
	}

	tlsDir := filepath.Join(deployPath, "tls", domain)
	os.MkdirAll(tlsDir, 0755)

	crtPath := filepath.Join(tlsDir, domain+".crt")
	keyPath := filepath.Join(tlsDir, domain+".key")

	if err := os.WriteFile(crtPath, certs.Certificate, 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入证书失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(keyPath, certs.PrivateKey, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入私钥失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ 证书已保存至:", tlsDir, "\033[0m")

	// ─── Docker MySQL 部署 (如果适用) ────────────────────────────
	if deployDockerMySQL {
		// 检测并自动安装 Docker
		if err := exec.Command("docker", "--version").Run(); err != nil {
			fmt.Println("\033[33m未检测到 Docker，正在为您自动安装 Docker...\033[0m")
			installCmd := exec.Command("sh", "-c", "curl -fsSL https://get.docker.com | sh")
			installCmd.Stdout = os.Stdout
			installCmd.Stderr = os.Stderr
			if err := installCmd.Run(); err != nil {
				fmt.Printf("\033[31m❌ 自动安装 Docker 失败: %v，请手动安装后重试！\033[0m\n", err)
				return
			}
			// 启动并使能 Docker
			_ = runCmd("systemctl", "start", "docker")
			_ = runCmd("systemctl", "enable", "docker")
			fmt.Println("\033[32m✓ Docker 安装并启动成功！\033[0m")
		}

		fmt.Printf("\n正在部署 Docker MySQL 容器 (端口 %d, 库名 %s)...\n", mysqlPort, mysqlDB)
		_ = runCmd("docker", "rm", "-f", "trojan-mysql")
		err := runCmd("docker", "run", "-d",
			"--name", "trojan-mysql",
			"--restart", "always",
			"-p", fmt.Sprintf("%d:3306", mysqlPort),
			"-e", "MYSQL_ROOT_PASSWORD="+mysqlPass,
			"-e", "MYSQL_DATABASE="+mysqlDB,
			"mysql:8.0",
		)
		if err != nil {
			fmt.Printf("\033[31m❌ 启动 Docker MySQL 失败: %v\033[0m\n", err)
			return
		}
		fmt.Println("\033[32m✓ Docker MySQL 容器启动成功，正在等待数据库初始化 (5 秒)...\033[0m")
		time.Sleep(5 * time.Second)
	}

	// ─── 步骤 2: 生成配置文件 ────────────────────────────
	fmt.Println("\n[2/5] 正在生成配置文件...")
	
	// 代理专用配置模板 (config.yaml)
	proxyTmpl := `run_type: server
local_addr: 0.0.0.0
local_port: {{.LocalPort}}
remote_addr: 127.0.0.1
remote_port: {{.AdminPort}}

ssl:
  cert: {{.CertPath}}
  key: {{.KeyPath}}
  sni: {{.Domain}}         # 预设 of SNI 域名
  verify: false             # 设置为 false 提高浏览器直接访问的兼容性
  verify_hostname: false    # 设置为 false 解决 SNI 不匹配导致的协议错误

  # 回落机制：将普通网页请求转发至本地 80 端口的管理后台
  fallback_addr: 127.0.0.1
  fallback_port: {{.AdminPort}}
  # 备选首页：当回落目标不可用时展示的备选页面
  plain_http_response: {{.DeployPath}}/index.html

mux:                # 开启多路复用，提高小文件传输效率
  enabled: true
websocket:
  enabled: true
  # 【警告】千万不要用 /ws、/trojan 等常见词汇。用随机生成的字符串最安全。
  path: "{{.WSPath}}"
  host: "{{.Domain}}"
admin:
  enabled: true
  username: "{{.User}}"
  password: "{{.Pass}}"
  port: 0
  db: "{{.DbPath}}"
  path: /admin

log:
  level: 1  # 设为 1 或 0 (TRACE)
  access: {{.DeployPath}}/log/trojan-go/access.log
  error: {{.DeployPath}}/log/trojan-go/error.log
`

	// Web 专用配置模板 (web_config.yaml)
	webTmpl := `# =================================================================
# Trojan-Go Web 管理后台配置文件 (Web / 80)
# =================================================================
# 此进程独立运行于 80 端口，专门处理管理面板逻辑。

run_type: server

admin:
  enabled: true
  username: "{{.User}}"    # 面板登录用户名
  password: "{{.Pass}}"    # 面板登录密码
  port: {{.AdminPort}}     # 服务真正在 80 端口监听
  db: "{{.DbPath}}"        # 数据库路径或 DSN
  path: "/"                # 面板挂载根路径
`

	os.MkdirAll(deployPath, 0755)
	
	// 填充替换逻辑
	proxyContent := proxyTmpl
	proxyContent = strings.ReplaceAll(proxyContent, "{{.CertPath}}", crtPath)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.KeyPath}}", keyPath)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.Domain}}", domain)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.LocalPort}}", fmt.Sprintf("%d", localPort))
	proxyContent = strings.ReplaceAll(proxyContent, "{{.DeployPath}}", deployPath)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.AdminPort}}", fmt.Sprintf("%d", adminPort))
	proxyContent = strings.ReplaceAll(proxyContent, "{{.WSPath}}", wsPath)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.DbPath}}", dbPath)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.User}}", adminUser)
	proxyContent = strings.ReplaceAll(proxyContent, "{{.Pass}}", adminPwd)

	webContent := webTmpl
	webContent = strings.ReplaceAll(webContent, "{{.User}}", adminUser)
	webContent = strings.ReplaceAll(webContent, "{{.Pass}}", adminPwd)
	webContent = strings.ReplaceAll(webContent, "{{.AdminPort}}", fmt.Sprintf("%d", adminPort))
	webContent = strings.ReplaceAll(webContent, "{{.DbPath}}", dbPath)

	if err := os.WriteFile(configPath, []byte(proxyContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), []byte(webContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	// 创建内置首页
	os.WriteFile(filepath.Join(deployPath, "index.html"), []byte("<h1>Welcome to Trojan-Go Modern Suite</h1>"), 0644)
	fmt.Println("\033[32m✓ 配置文件已生成\033[0m")

	// ─── 步骤 3: 自动安装二进制文件 ────────────────────────────
	fmt.Println("\n[3/5] 正在安装二进制文件到系统路径...")
	// 安装 trojan-go
	installedProxy := false
	if _, err := os.Stat("./trojan-go"); err == nil {
		runCmd("cp", "-f", "./trojan-go", "/usr/bin/trojan-go")
		runCmd("chmod", "+x", "/usr/bin/trojan-go")
		installedProxy = true
	} else if _, err := os.Stat("./trojan-go-linux-amd64"); err == nil {
		runCmd("cp", "-f", "./trojan-go-linux-amd64", "/usr/bin/trojan-go")
		runCmd("chmod", "+x", "/usr/bin/trojan-go")
		installedProxy = true
	}
	if installedProxy {
		fmt.Println("✓ 已安装 trojan-go 至 /usr/bin/trojan-go")
	}

	// 安装 trojan 管理工具自身
	installedCli := false
	if _, err := os.Stat("./trojan"); err == nil {
		runCmd("cp", "-f", "./trojan", "/usr/bin/trojan")
		runCmd("chmod", "+x", "/usr/bin/trojan")
		installedCli = true
	} else if _, err := os.Stat("./trojan-linux-amd64"); err == nil {
		runCmd("cp", "-f", "./trojan-linux-amd64", "/usr/bin/trojan")
		runCmd("chmod", "+x", "/usr/bin/trojan")
		installedCli = true
	}
	if installedCli {
		fmt.Println("✓ 已安装 trojan 至 /usr/bin/trojan")
	}

	// 修正配置目录权限，确保证书可读
	runCmd("chmod", "-R", "0755", deployPath)

	// ─── 步骤 4: 创建 Systemd 服务文件 ────────────────────────────
	fmt.Println("\n[4/5] 正在配置 Systemd 服务...")
	// 1. 代理核心服务 (依赖于 Web 服务提供的回落支持)
	proxySvc := `[Unit]
Description=Trojan-Go Proxy Service
After=network.target trojan-web.service

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go -config ` + filepath.Join(deployPath, "config.yaml") + `
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`
	// 2. Web 管理服务
	webSvc := `[Unit]
Description=Trojan-Go Web Management Service
After=network.target

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go web -config ` + filepath.Join(deployPath, "web_config.yaml") + `
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`
	
	os.WriteFile("/etc/systemd/system/trojan-go.service", []byte(proxySvc), 0644)
	os.WriteFile("/etc/systemd/system/trojan-web.service", []byte(webSvc), 0644)
	fmt.Println("✓ Systemd 服务配置完成")

	// ─── 步骤 5: 启动双服务 ────────────────────────────
	fmt.Println("\n[5/5] 正在启动并激活服务...")
	if err := runCmd("systemctl", "daemon-reload"); err == nil {
		// 先启动 Web 服务 (80) 以便 Proxy (443) 验证回落地址
		svcs := []string{"trojan-web", "trojan-go"}
		for _, s := range svcs {
			fmt.Printf(" [!] 正在激活 %s...\n", s)
			runCmd("systemctl", "enable", s)
			if err := runCmd("systemctl", "start", s); err != nil {
				fmt.Printf("\033[31m(!) 警告: %s 启动可能失败，请检查日志。\033[0m\n", s)
			}
		}
		
		fmt.Println("\n正在验证服务存活状态...")
		time.Sleep(2 * time.Second) // 等待服务就绪
		for _, s := range svcs {
			active, _ := exec.Command("systemctl", "is-active", s).Output()
			if string(active) != "active\n" {
				fmt.Printf("\033[31m❌ %s 启动失败! 错误日志如下:\033[0m\n", s)
				out, _ := exec.Command("journalctl", "-u", s, "-n", "10", "--no-pager").CombinedOutput()
				fmt.Println(string(out))
			} else {
				fmt.Printf("\033[32m✅ %s 运行正常\033[0m\n", s)
			}
		}
	}

	fmt.Println("\n\033[32m=== 初始化部署成功 ! ===\033[0m")
	fmt.Printf("1. 双服务已就绪: trojan-go (443) 和 trojan-web (80)\n")
	fmt.Printf("2. 访问方式:\n")
	fmt.Printf("   - https://%s/ (通过 443 回落至后台)\n", domain)
	fmt.Printf("   - http://%s/  (直连 80 端口后台)\n", domain)
	fmt.Printf("3. 检查状态: trojan status\n")
}

// 简单的命令执行工具
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// InitDeployWorker 初始化部署（从节点）一键化流程
func InitDeployWorker() {
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	if os.Geteuid() != 0 {
		msg := "错误：安装操作需要 sudo 权限！"
		if menu.CurrentLang == menu.EN {
			msg = "Error: Installation requires sudo privileges!"
		}
		fmt.Printf("\033[31m%s\033[0m\n", msg)
		return
	}

	// 自定义部署路径
	deployPath := getStdin("请输入部署路径 (直接回车为默认 /etc/trojan-go): ", "Enter deployment path (default /etc/trojan-go): ")
	if deployPath == "" {
		deployPath = "/etc/trojan-go"
	}
	deployPath = strings.TrimSuffix(deployPath, "/")

	configPath := filepath.Join(deployPath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("\033[33m检测到从节点配置文件已存在，继续操作将覆盖它。\033[0m")
		ans := getStdin("是否继续？(y/n): ", "Continue? (y/n): ")
		if ans != "y" && ans != "Y" {
			return
		}
	}

	title := "=== 初始化部署（从节点） ==="
	infoMsg := "请依次输入所有配置信息，随后程序将自动完成证书申请和部署："
	if menu.CurrentLang == menu.EN {
		title = "=== Initial Deployment (Worker Node) ==="
		infoMsg = "Please enter all configuration information, then the program will automatically complete certificate application and deployment:"
	}
	fmt.Printf("\n\033[36m%s\033[0m\n%s\n\n", title, infoMsg)

	// 1. 域名
	domain := getStdin("1. 请输入从节点域名 (如 hk01.example.com): ", "1. Enter worker domain (e.g. hk01.example.com): ")
	if domain == "" {
		fmt.Println("从节点域名不能为空")
		return
	}

	// 2. 邮箱
	email := getStdin("2. 请输入邮箱 (用于注册 ACME 账户): ", "2. Enter your email (for ACME registration): ")
	if email == "" {
		fmt.Println("邮箱不能为空")
		return
	}

	// 3. 代理端口
	localPortStr := getStdin("3. 设置从节点代理服务端口 (默认 443): ", "3. Set proxy port (default 443): ")
	localPort := 443
	if localPortStr != "" {
		fmt.Sscanf(localPortStr, "%d", &localPort)
	}

	// 4. 主节点同步接口 URL (必填)
	masterURL := ""
	for {
		masterURL = getStdin("4. 请输入主节点同步接口 URL (必填，如 https://master.com/api/node/sync): ", "4. Enter master sync URL (required): ")
		if masterURL != "" {
			break
		}
		fmt.Println("❌ 必须输入主节点同步接口 URL！")
	}

	// 5. 从节点通信密钥 Secret (必填)
	nodeSecret := ""
	for {
		nodeSecret = getStdin("5. 请输入从节点通信密钥 Secret (必填): ", "5. Enter worker node communication Secret (required): ")
		if nodeSecret != "" {
			break
		}
		fmt.Println("❌ 必须输入节点通信密钥！")
	}

	// 6. 是否启用 WebSocket 伪装
	wsEnabled := false
	wsPath := ""
	wsAns := getStdin("6. 是否启用 WebSocket 伪装？(y/n, 默认 n): ", "6. Enable WebSocket masquerade? (y/n, default n): ")
	if wsAns == "y" || wsAns == "Y" {
		wsEnabled = true
		for {
			wsPath = getStdin("   请输入 WebSocket 伪装路径 (回车自动随机生成): ", "   Enter WebSocket path (enter for random): ")
			if wsPath == "" {
				const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
				randChars := make([]byte, 6)
				for i := range randChars {
					randChars[i] = letters[r.Intn(len(letters))]
				}
				wsPath = "/stream-v2-" + string(randChars)
				break
			}
			if !strings.HasPrefix(wsPath, "/") {
				wsPath = "/" + wsPath
			}
			break
		}
	}

	// 7. 管理面板用户名
	adminUser := getStdin("7. 设置管理面板用户名 (默认 admin): ", "7. Set admin username (default admin): ")
	if adminUser == "" {
		adminUser = "admin"
	}

	// 8. 管理面板密码
	adminPwd := getStdin("8. 设置管理面板密码 (默认 trojan@123): ", "8. Set admin password (default trojan@123): ")
	if adminPwd == "" {
		adminPwd = "trojan@123"
	}

	// 9. 管理面板监听端口
	adminPortStr := getStdin("9. 设置管理面板监听端口 (推荐 80): ", "9. Set admin port (recommended 80): ")
	adminPort := 80
	if adminPortStr != "" {
		fmt.Sscanf(adminPortStr, "%d", &adminPort)
	}

	// SQLite 作为本地缓存库，路径定为 deployPath/trojan-go.db
	dbPath := filepath.Join(deployPath, "trojan-go.db")

	// 开始执行操作
	fmt.Println("\n\033[36m=== 开始执行从节点初始化部署 ===\033[0m")

	// ─── 步骤 1: 申请 SSL 证书 ────────────────────────────
	fmt.Printf("\n[1/5] 正在为从节点 %s 申请 SSL 证书...\n", domain)
	certs, err := obtainCert(domain, email, "https://acme-v02.api.letsencrypt.org/directory")
	if err != nil {
		fmt.Printf("\033[31m❌ 证书申请失败: %v\033[0m\n", err)
		return
	}

	tlsDir := filepath.Join(deployPath, "tls", domain)
	os.MkdirAll(tlsDir, 0755)

	crtPath := filepath.Join(tlsDir, domain+".crt")
	keyPath := filepath.Join(tlsDir, domain+".key")

	err1 := os.WriteFile(crtPath, certs.Certificate, 0600)
	err2 := os.WriteFile(keyPath, certs.PrivateKey, 0600)
	if err1 != nil || err2 != nil {
		fmt.Printf("\033[31m❌ 证书写入失败: %v %v\033[0m\n", err1, err2)
		return
	}
	fmt.Println("\033[32m✓ SSL 证书已成功下载并写入配置目录\033[0m")

	// ─── 步骤 2: 生成配置文件 ────────────────────────────
	fmt.Println("\n[2/5] 正在生成配置文件...")

	// 从节点核心配置
	wsEnabledStr := "false"
	if wsEnabled {
		wsEnabledStr = "true"
	}
	proxyContent := fmt.Sprintf(`run_type: server
local_addr: 0.0.0.0
local_port: %d
remote_addr: 127.0.0.1
remote_port: %d

ssl:
  cert: %s
  key: %s
  sni: %s
  verify: false
  verify_hostname: false

  fallback_addr: 127.0.0.1
  fallback_port: %d
  plain_http_response: %s/index.html

mux:
  enabled: true
websocket:
  enabled: %s
  path: "%s"
  host: "%s"
admin:
  enabled: true
  username: "%s"
  password: "%s"
  port: 0
  db: "%s"
  path: /admin

node:
  enabled: true
  master_url: "%s"
  secret: "%s"
  sync_interval: 60

log:
  level: 1
  access: %s/log/trojan-go/access.log
  error: %s/log/trojan-go/error.log
`, localPort, adminPort, crtPath, keyPath, domain, adminPort, deployPath, wsEnabledStr, wsPath, domain, adminUser, adminPwd, dbPath, masterURL, nodeSecret, deployPath, deployPath)

	// 从节点网页配置
	webContent := fmt.Sprintf(`# =================================================================
# Trojan-Go Web 管理后台配置文件 (Web / 80)
# =================================================================
run_type: server

admin:
  enabled: true
  username: "%s"
  password: "%s"
  port: %d
  db: "%s"
  path: "/"
node:
  enabled: true
`, adminUser, adminPwd, adminPort, dbPath)

	os.MkdirAll(deployPath, 0755)
	if err := os.WriteFile(configPath, []byte(proxyContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), []byte(webContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	// 创建内置首页
	os.WriteFile(filepath.Join(deployPath, "index.html"), []byte("<h1>Welcome to Trojan-Go Worker Node</h1>"), 0644)
	fmt.Println("\033[32m✓ 配置文件已生成\033[0m")

	// ─── 步骤 3: 自动安装二进制文件 ────────────────────────────
	fmt.Println("\n[3/5] 正在安装二进制文件到系统路径...")
	installedProxy := false
	if _, err := os.Stat("./trojan-go"); err == nil {
		runCmd("cp", "-f", "./trojan-go", "/usr/bin/trojan-go")
		runCmd("chmod", "+x", "/usr/bin/trojan-go")
		installedProxy = true
	} else if _, err := os.Stat("./trojan-go-linux-amd64"); err == nil {
		runCmd("cp", "-f", "./trojan-go-linux-amd64", "/usr/bin/trojan-go")
		runCmd("chmod", "+x", "/usr/bin/trojan-go")
		installedProxy = true
	}
	if installedProxy {
		fmt.Println("✓ 已安装 trojan-go 至 /usr/bin/trojan-go")
	}

	installedCli := false
	if _, err := os.Stat("./trojan"); err == nil {
		runCmd("cp", "-f", "./trojan", "/usr/bin/trojan")
		runCmd("chmod", "+x", "/usr/bin/trojan")
		installedCli = true
	} else if _, err := os.Stat("./trojan-linux-amd64"); err == nil {
		runCmd("cp", "-f", "./trojan-linux-amd64", "/usr/bin/trojan")
		runCmd("chmod", "+x", "/usr/bin/trojan")
		installedCli = true
	}
	if installedCli {
		fmt.Println("✓ 已安装 trojan 至 /usr/bin/trojan")
	}

	runCmd("chmod", "-R", "0755", deployPath)

	// ─── 步骤 4: 创建 Systemd 服务文件 ────────────────────────────
	fmt.Println("\n[4/5] 正在配置 Systemd 服务...")
	proxySvc := `[Unit]
Description=Trojan-Go Worker Proxy Service
After=network.target trojan-web.service

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go -config ` + filepath.Join(deployPath, "config.yaml") + `
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`
	webSvc := `[Unit]
Description=Trojan-Go Worker Web Management Service
After=network.target

[Service]
Type=simple
LimitNOFILE=65536
ExecStart=/usr/bin/trojan-go web -config ` + filepath.Join(deployPath, "web_config.yaml") + `
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`
	os.WriteFile("/etc/systemd/system/trojan-go.service", []byte(proxySvc), 0644)
	os.WriteFile("/etc/systemd/system/trojan-web.service", []byte(webSvc), 0644)
	fmt.Println("✓ Systemd 服务配置完成")

	// ─── 步骤 5: 启动双服务 ────────────────────────────
	fmt.Println("\n[5/5] 正在启动并激活服务...")
	if err := runCmd("systemctl", "daemon-reload"); err == nil {
		svcs := []string{"trojan-web", "trojan-go"}
		for _, s := range svcs {
			fmt.Printf(" [!] 正在激活 %s...\n", s)
			runCmd("systemctl", "enable", s)
			if err := runCmd("systemctl", "start", s); err != nil {
				fmt.Printf("\033[31m(!) 警告: %s 启动可能失败，请检查日志。\033[0m\n", s)
			}
		}

		fmt.Println("\n正在验证服务存活状态...")
		time.Sleep(2 * time.Second)
		for _, s := range svcs {
			active, _ := exec.Command("systemctl", "is-active", s).Output()
			if string(active) != "active\n" {
				fmt.Printf("\033[31m❌ %s 启动失败! 错误日志如下:\033[0m\n", s)
				out, _ := exec.Command("journalctl", "-u", s, "-n", "10", "--no-pager").CombinedOutput()
				fmt.Println(string(out))
			} else {
				fmt.Printf("\033[32m✅ %s 运行正常\033[0m\n", s)
			}
		}
	}

	fmt.Println("\n\033[32m=== 从节点部署成功 ! ===\033[0m")
	fmt.Printf("1. 双服务已就绪: 从节点代理 (%d) 和 管理面板 (%d)\n", localPort, adminPort)
	fmt.Printf("2. 访问方式:\n")
	fmt.Printf("   - https://%s:%d/ (回落至面板)\n", domain, localPort)
	fmt.Printf("   - http://%s:%d/  (直连面板)\n", domain, adminPort)
}
