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

const nginxWelcome = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`

// InitDeployMaster 初始化部署（主节点）一键化流程
func InitDeployMaster() {
	// 动态生成 6 位随机字符组成 websocket 路径
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	randChars := make([]byte, 6)
	for i := range randChars {
		randChars[i] = letters[r.Intn(len(letters))]
	}
	wsPath := "/stream-" + string(randChars)

	// 动态生成 8 位随机字符组成订阅混淆路径
	subChars := make([]byte, 8)
	for i := range subChars {
		subChars[i] = letters[r.Intn(len(letters))]
	}
	subPath := "/sub-" + string(subChars)

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
	adminPortStr := getStdin("6. 设置管理面板监听端口 (推荐 8080): ", "6. Set admin port (recommended 8080): ")
	adminPort := 8080
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

	// 8. 是否启用 Hysteria2 (QUIC/UDP 主力协议)
	h2Enabled := false
	h2Port := 8443
	h2Up := 100
	h2Down := 500
	h2Ans := getStdin("8. 是否启用 Hysteria2 (QUIC/UDP) 主力协议？(y/n, 默认 n): ", "8. Enable Hysteria2 (QUIC/UDP) protocol? (y/n, default n): ")
	if h2Ans == "y" || h2Ans == "Y" {
		h2Enabled = true
		h2PortStr := getStdin("   Hysteria2 监听端口 (默认 8443): ", "   Hysteria2 listen port (default 8443): ")
		if h2PortStr != "" {
			fmt.Sscanf(h2PortStr, "%d", &h2Port)
		}
		h2UpStr := getStdin("   上行带宽 Mbps (默认 100): ", "   Upstream bandwidth Mbps (default 100): ")
		if h2UpStr != "" {
			fmt.Sscanf(h2UpStr, "%d", &h2Up)
		}
		h2DownStr := getStdin("   下行带宽 Mbps (默认 500): ", "   Downstream bandwidth Mbps (default 500): ")
		if h2DownStr != "" {
			fmt.Sscanf(h2DownStr, "%d", &h2Down)
		}
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
	proxyTmpl := `# =================================================================
# Trojan-Go Core Proxy Configuration File (config.yaml)
# Trojan-Go 核心代理配置文件 (config.yaml)
# =================================================================

# [Core Configuration] The run type of the service (server or client)
# [核心配置] 服务运行类型 (server 或 client)
run_type: server

# [Core Configuration] The local IP address to listen on
# [核心配置] 本地监听 IP 地址
local_addr: 0.0.0.0

# [Core Configuration] The local port to listen on
# [核心配置] 本地监听端口
local_port: {{.LocalPort}}

# [Core Configuration] The destination server address to route connection (optional)
# [核心配置] 目标代理转发目标地址（备用）
remote_addr: 127.0.0.1

# [Core Configuration] The destination server port to route connection (optional)
# [核心配置] 目标代理转发目标端口（备用）
remote_port: {{.AdminPort}}

# [TLS Configuration] SSL settings
# [TLS配置] SSL 证书与安全设定
ssl:
# [TLS Configuration] The certificate file path
# [TLS配置] SSL 证书文件路径
  cert: {{.CertPath}}

# [TLS Configuration] The private key file path
# [TLS配置] SSL 私钥文件路径
  key: {{.KeyPath}}

# [TLS Configuration] The server SNI (Server Name Indication)
# [TLS配置] 预设的 SNI 证书匹配域名
  sni: {{.Domain}}

# [TLS Configuration] Whether to verify the client cert (false to improve compatibility)
# [TLS配置] 是否验证客户端证书（设为 false 可提高兼容性）
  verify: false

# [TLS Configuration] Whether to verify host name in certificate
# [TLS配置] 是否验证证书中的域名匹配（防 SNI 阻断）
  verify_hostname: false

# [TLS Configuration] The fallback address of plaintext http server (uncomment to use Nginx fallback)
# [TLS配置] 原生 Fallback 本地反代地址（如果结合 Nginx 伪装则取消下面两行注释）
#   fallback_addr: 127.0.0.1
# [TLS Configuration] The fallback port of plaintext http server
# [TLS配置] 原生 Fallback 本地反代端口
#   fallback_port: 80

# [TLS Configuration] The static HTML fallback webpage when no fallback port is configured
# [TLS配置] 无 Nginx 情况下，未认证流量直接回送的本地静态网页（字节流形式）
  plain_http_response: {{.DeployPath}}/index.html

# [Multiplexing] Mux configuration
# [多路复用] Mux 配置段，提高多小文件并发下的传输效率
mux:
# [Multiplexing] Whether to enable multiplexing
# [多路复用] 是否开启多路复用
  enabled: true

# [WebSocket] WebSocket transport settings
# [WebSocket] WebSocket 传输层协议伪装设置
websocket:
# [WebSocket] Whether to enable WebSocket camouflage
# [WebSocket] 是否启用 WebSocket 伪装
  enabled: true

# [WebSocket] The path to listen on (Random path is recommended to bypass firewall)
# [WebSocket] WebSocket 挂载路径（千万不要用 /ws 等常见词，模板使用随机路径）
  path: "{{.WSPath}}"

# [WebSocket] The SNI host to match
# [WebSocket] WebSocket 域名头匹配
  host: "{{.Domain}}"

# [Hysteria2] Hysteria2 (QUIC/UDP) 协议配置 — 主力协议
# [Hysteria2] 启用后 Clash 订阅会优先包含 Hysteria2 节点，Trojan 退居备用
# hysteria2:
#   enabled: true
#   port: 8443
#   up_mbps: 100
#   down_mbps: 500
#   masquerade_url: "https://www.bilibili.com"
#   auth_api: "http://127.0.0.1:{{.AdminPort}}/admin/api/hysteria/auth"

# [Control Plane] Web admin server settings
# [管理控制面] Web 管理后台与订阅接口配置
admin:
# [Control Plane] Whether to enable admin panel server
# [管理控制面] 是否启用 Web 管理服务
  enabled: true

# [Control Plane] The login username of admin panel
# [管理控制面] 管理面板的登录用户名
  username: "{{.User}}"

# [Control Plane] The login password of admin panel
# [管理控制面] 管理面板的登录密码
  password: "{{.Pass}}"

# [Control Plane] The standalone port to listen on (default 8080 to avoid nginx conflicts)
# [管理控制面] 管理面板监听的本地独立端口（默认为 127.0.0.1 独立监听）
  port: {{.AdminPort}}

# [Control Plane] The SQLite database file path or MySQL DSN
# [管理控制面] 存储用户与节点数据的数据库路径或 DSN 链接
  db: "{{.DbPath}}"

# [Control Plane] The routing mount path of web UI
# [管理控制面] 管理主界面的网页挂载路径，系统将强制清洗为 "/admin/"
  path: /admin

# [Control Plane] The dynamic obfuscated subscription path to download clash config
# [管理控制面] 自定义加密订阅混淆路径（主节点），系统运行后将随机自动生成
  sub_path: "{{.SubPath}}"

# [Advanced Config] The redirect URL of unauthenticated http request
# [高级配置] 未认证的 302 外部重定向跳转地址
#   unauth_redirect: "https://your-redirect-domain.com"

# [Advanced Config] The custom mask HTML file path for standalone admin port
# [高级配置] 独立端口收到非 admin 访问时的本地伪装网页路径
#   mask_html_path: "{{.DeployPath}}/index.html"

# [Routing Policy] Custom router settings
# [路由策略] 自定义路由策略（如果您需要绕过局域网和国内流量可取消下面注释）
# router:
# [Routing Policy] Whether to enable custom router
# [路由策略] 是否启用自定义路由分流
#   enabled: true
# [Routing Policy] The bypass rules list
# [路由策略] 默认直连的域名和 IP 段
#   bypass:
#     - geosite:cn
#     - geoip:private

# [Logging] System logs settings
# [系统日志] 访问和错误日志配置文件路径
log:
# [Logging] Log level (0: TRACE, 1: INFO, 2: WARN, 3: ERROR)
# [系统日志] 日志级别记录
  level: 1

# [Logging] Access log output path
# [系统日志] 访问日志输出文件路径
  access: {{.DeployPath}}/log/trojan-go/access.log

# [Logging] Error log output path
# [系统日志] 错误日志输出文件路径
  error: {{.DeployPath}}/log/trojan-go/error.log
`

	// Web 专用配置模板 (web_config.yaml)
	webTmpl := `# =================================================================
# Trojan-Go Web Management Backend Configuration (web_config.yaml)
# Trojan-Go Web 管理后台配置文件 (web_config.yaml)
# =================================================================

run_type: server

admin:
  enabled: true
  username: "{{.User}}"    # 面板登录用户名
  password: "{{.Pass}}"    # 面板登录密码
  port: {{.AdminPort}}     # 服务真正在独立端口监听
  db: "{{.DbPath}}"        # 数据库路径或 DSN
  path: "/admin/"          # 面板挂载根路径
  sub_path: "{{.SubPath}}" # 安全订阅下载路径
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
	proxyContent = strings.ReplaceAll(proxyContent, "{{.SubPath}}", subPath)

	webContent := webTmpl
	webContent = strings.ReplaceAll(webContent, "{{.User}}", adminUser)
	webContent = strings.ReplaceAll(webContent, "{{.Pass}}", adminPwd)
	webContent = strings.ReplaceAll(webContent, "{{.AdminPort}}", fmt.Sprintf("%d", adminPort))
	webContent = strings.ReplaceAll(webContent, "{{.DbPath}}", dbPath)
	webContent = strings.ReplaceAll(webContent, "{{.SubPath}}", subPath)

	// Hysteria2 配置处理
	if h2Enabled {
		proxyContent = strings.ReplaceAll(proxyContent, "# hysteria2:", "hysteria2:")
		proxyContent = strings.ReplaceAll(proxyContent, "#   enabled: true", "  enabled: true")
		proxyContent = strings.ReplaceAll(proxyContent, "#   port: 8443", fmt.Sprintf("  port: %d", h2Port))
		proxyContent = strings.ReplaceAll(proxyContent, "#   up_mbps: 100", fmt.Sprintf("  up_mbps: %d", h2Up))
		proxyContent = strings.ReplaceAll(proxyContent, "#   down_mbps: 500", fmt.Sprintf("  down_mbps: %d", h2Down))
		proxyContent = strings.ReplaceAll(proxyContent, "#   masquerade_url: \"https://www.bilibili.com\"", "  masquerade_url: \"https://www.bilibili.com\"")
		proxyContent = strings.ReplaceAll(proxyContent, "#   auth_api: \"http://127.0.0.1:{{.AdminPort}}/admin/api/hysteria/auth\"",
			fmt.Sprintf("  auth_api: \"http://127.0.0.1:%d/admin/api/hysteria/auth\"", adminPort))
	}

	if err := os.WriteFile(configPath, []byte(proxyContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), []byte(webContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	// 创建内置首页 (防探测，使用逼真的标准 Nginx 测试页面)
	nginxWelcome := `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>`
	os.WriteFile(filepath.Join(deployPath, "index.html"), []byte(nginxWelcome), 0644)
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

	// ─── Hysteria2 部署（如用户选择启用） ──────
	if h2Enabled {
		fmt.Println("\n--- 开始 Hysteria2 (QUIC/UDP) 部署 ---")
		// 1. 下载 Hysteria2 二进制
		h2URL := "https://github.com/apernet/hysteria/releases/download/app%2Fv2.10.0/hysteria-linux-amd64"
		fmt.Printf(" [!] 正在下载 Hysteria2...\n")
		if err := runCmd("wget", "-qO", "/usr/local/bin/hysteria", h2URL); err != nil {
			fmt.Printf("\033[31m❌ 下载 Hysteria2 失败: %v\033[0m\n", err)
		} else {
			runCmd("chmod", "+x", "/usr/local/bin/hysteria")
			fmt.Println("✓ Hysteria2 已安装至 /usr/local/bin/hysteria")
		}

		// 2. 生成 Hysteria2 配置文件
		hysteriaConfig := fmt.Sprintf(`listen: :%d
tls:
  cert: %s
  key: %s
auth:
  type: password
  password: {{需要套用 Trojan 密码，在 Web 面板管理用户}}
masquerade:
  type: proxy
  proxy:
    url: https://www.bilibili.com
    rewriteHost: true
quic:
  initStreamReceiveWindow: 8388608
  maxStreamReceiveWindow: 8388608
  initConnReceiveWindow: 20971520
  maxConnReceiveWindow: 20971520
  maxIdleTimeout: 60s
  keepAliveInterval: 10s
bandwidth:
  up: %d mbps
  down: %d mbps
`, h2Port, crtPath, keyPath, h2Up, h2Down)
		hysteriaConfigPath := filepath.Join(deployPath, "hysteria.yaml")
		os.WriteFile(hysteriaConfigPath, []byte(hysteriaConfig), 0644)
		fmt.Printf("✓ Hysteria2 配置已生成 (%s)\n", hysteriaConfigPath)
		fmt.Println("  [!] 请登录 Web 面板创建用户，并将 hysteria.yaml 中的 password 替换为实际密码")
	}

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

	if h2Enabled {
		hysteriaSvc := `[Unit]
Description=Hysteria2 QUIC/UDP Server
After=network.target trojan-web.service

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c ` + filepath.Join(deployPath, "hysteria.yaml") + `
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
`
		os.WriteFile("/etc/systemd/system/hysteria.service", []byte(hysteriaSvc), 0644)
	}

	fmt.Println("✓ Systemd 服务配置完成")

	// ─── 步骤 5: 启动双服务 ────────────────────────────
	fmt.Println("\n[5/5] 正在启动并激活服务...")
	if err := runCmd("systemctl", "daemon-reload"); err == nil {
		// 先启动 Web 服务 (80) 以便 Proxy (443) 验证回落地址
		svcs := []string{"trojan-web", "trojan-go"}
		if h2Enabled {
			svcs = append(svcs, "hysteria")
		}
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
	fmt.Printf("1. 双服务已就绪: trojan-go (主端口: %d) 和 trojan-web (管理端口: %d)\n", localPort, adminPort)
	fmt.Printf("2. 安全订阅链接 (443 TLS 加密保护):\n")
	fmt.Printf("   - https://%s%s?token=[用户UUID]\n", domain, subPath)
	fmt.Printf("3. 管理后台访问方式 (独立端口):\n")
	fmt.Printf("   - 本地端口转发：在客户端建立 SSH 隧道：\n")
	fmt.Printf("     ssh -L %d:127.0.0.1:%d ubuntu@%s\n", adminPort, adminPort, domain)
	fmt.Printf("     然后访问：http://127.0.0.1:%d/admin/\n", adminPort)
	fmt.Printf("4. 检查状态: trojan status\n")
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
		masterURL = getStdin("4. 节点同步接口 URL (必填，如 https://master.com/admin/api/node/sync): ", "4. Enter master sync URL (required): ")
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
	// 默认先生成一个随机的 wsPath
	const wsLetters = "abcdefghijklmnopqrstuvwxyz0123456789"
	wsRandChars := make([]byte, 6)
	for i := range wsRandChars {
		wsRandChars[i] = wsLetters[r.Intn(len(wsLetters))]
	}
	wsPath := "/stream-" + string(wsRandChars)

	wsEnabled := false
	wsAns := getStdin("6. 是否启用 WebSocket 伪装？(y/n, 默认 n): ", "6. Enable WebSocket masquerade? (y/n, default n): ")
	if wsAns == "y" || wsAns == "Y" {
		wsEnabled = true
		inputPath := getStdin("   请输入 WebSocket 伪装路径 (直接回车使用随机路径): ", "   Enter WebSocket path (enter for random): ")
		inputPath = strings.TrimSpace(inputPath)
		if inputPath != "" {
			if !strings.HasPrefix(inputPath, "/") {
				inputPath = "/" + inputPath
			}
			wsPath = inputPath
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
	adminPortStr := getStdin("9. 设置管理面板监听端口 (推荐 8080): ", "9. Set admin port (recommended 8080): ")
	adminPort := 8080
	if adminPortStr != "" {
		fmt.Sscanf(adminPortStr, "%d", &adminPort)
	}

	// SQLite 作为本地缓存库，路径定为 deployPath/trojan-go.db
	dbPath := filepath.Join(deployPath, "trojan-go.db")

	// 10. 动态生成 8 位随机字符组成订阅混淆路径
	subChars := make([]byte, 8)
	for i := range subChars {
		subChars[i] = wsLetters[r.Intn(len(wsLetters))]
	}
	subPath := "/sub-" + string(subChars)

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
  sub_path: "%s"

node:
  enabled: true
  master_url: "%s"
  secret: "%s"
  sync_interval: 60

log:
  level: 1
  access: %s/log/trojan-go/access.log
  error: %s/log/trojan-go/error.log
`, localPort, adminPort, crtPath, keyPath, domain, adminPort, deployPath, wsEnabledStr, wsPath, domain, adminUser, adminPwd, dbPath, subPath, masterURL, nodeSecret, deployPath, deployPath)

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
  path: "/admin/"
  sub_path: "%s"
node:
  enabled: true
`, adminUser, adminPwd, adminPort, dbPath, subPath)

	os.MkdirAll(deployPath, 0755)
	if err := os.WriteFile(configPath, []byte(proxyContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), []byte(webContent), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	// 创建内置首页 (防探测，使用逼真标准 Nginx 测试页面)
	os.WriteFile(filepath.Join(deployPath, "index.html"), []byte(nginxWelcome), 0644)
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
