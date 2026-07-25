package actions

import (
	cryptorand "crypto/rand"
	"errors"
	"fmt"
	"math/big"
	mathrand "math/rand"
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

func generateSecurePassword(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789-_"
	buf := make([]byte, length)
	for i := range buf {
		n, err := cryptorand.Int(cryptorand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		buf[i] = alphabet[n.Int64()]
	}
	return string(buf), nil
}

// promptAdminPassword refuses the historical weak default. A blank value creates
// a high-entropy password and prints it once to the local deployment terminal.
func promptAdminPassword(promptCN, promptEN string) string {
	password := getStdin(promptCN, promptEN)
	if password != "" {
		return password
	}
	password, err := generateSecurePassword(24)
	if err != nil {
		fmt.Println("❌ 无法生成安全的管理面板密码，请手动输入密码后重试：", err)
		return ""
	}
	fmt.Printf("\n\033[33m⚠ 已生成随机管理面板密码（仅显示本次，请立即安全保存）：%s\033[0m\n", password)
	return password
}

// InitDeployMaster 初始化部署（主节点）一键化流程
func InitDeployMaster() {
	// === Phase 0: privilege check and path selection ===
	// Gateway 独占公网 TCP 443；Trojan data-plane 固定使用 loopback 14443。
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
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

	// 公网 TCP 入口固定由 Gateway 使用 443；data-plane 不再暴露公网端口。
	gatewayPort := defaultGatewayPort
	dataPlanePort := defaultDataPlanePort
	controlPort := defaultControlServicePort

	configPath := filepath.Join(deployPath, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Println("\033[31m检测到现有部署。为避免二进制、配置和服务进入新旧混合状态，初始化部署拒绝直接覆盖。\033[0m")
		fmt.Println("请准备带 SHA-256 校验的升级清单，并使用：trojan upgrade --manifest /path/to/upgrade.json")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("\033[31m检查现有部署失败: %v\033[0m\n", err)
		return
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

	// 5. 管理面板密码：不再使用历史弱默认密码。
	adminPwd := promptAdminPassword("5. 设置管理面板密码（直接回车生成随机强密码）: ", "5. Set admin password (press Enter to generate a strong random password): ")
	if adminPwd == "" {
		return
	}

	// 6. admin-service 仅监听 loopback 8081。
	adminPort := defaultAdminServicePort

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
	h2Port := 443
	h2Up := 100
	h2Down := 300
	h2Ans := getStdin("8. 是否启用 Hysteria2 (QUIC/UDP) 主力协议？(y/n, 默认 n): ", "8. Enable Hysteria2 (QUIC/UDP) protocol? (y/n, default n): ")
	if h2Ans == "y" || h2Ans == "Y" {
		h2Enabled = true
		h2PortStr := getStdin("   Hysteria2 监听端口 (默认 443): ", "   Hysteria2 listen port (default 443): ")
		if h2PortStr != "" {
			fmt.Sscanf(h2PortStr, "%d", &h2Port)
		}
		h2UpStr := getStdin("   上行带宽 Mbps（请填写 VPS 实际上行带宽，默认 100）: ", "   Upstream bandwidth Mbps (enter VPS actual uplink, default 100): ")
		if h2UpStr != "" {
			fmt.Sscanf(h2UpStr, "%d", &h2Up)
		}
		h2DownStr := getStdin("   下行带宽 Mbps（请填写 VPS 实际下行带宽，默认 300）: ", "   Downstream bandwidth Mbps (enter VPS actual downlink, default 300): ")
		if h2DownStr != "" {
			fmt.Sscanf(h2DownStr, "%d", &h2Down)
		}
	}

	// === Phase 1: SSL certificate provisioning ===
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
	crtPath := filepath.Join(tlsDir, domain+".crt")
	keyPath := filepath.Join(tlsDir, domain+".key")
	if err := writeCertificateFiles(crtPath, keyPath, certs.Certificate, certs.PrivateKey); err != nil {
		fmt.Printf("\033[31m❌ 写入证书或私钥失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ 证书已保存至:", tlsDir, "\033[0m")

	// ─── Docker MySQL 部署 (如果适用) ────────────────────────────
	// === Phase 2: optional MySQL setup ===
	if deployDockerMySQL {
		// 检测 Docker，如果不存在则打印分发行安装指引而非远程执行脚本
		if err := exec.Command("docker", "--version").Run(); err != nil {
			fmt.Println("\033[33m未检测到 Docker。请通过发行版官方仓库安装 Docker 后重试：\033[0m")
			fmt.Println("")
			fmt.Println("  Ubuntu / Debian:")
			fmt.Println("    sudo apt-get update && sudo apt-get install -y docker.io")
			fmt.Println("    sudo systemctl enable --now docker")
			fmt.Println("")
			fmt.Println("  CentOS / RHEL / Fedora:")
			fmt.Println("    sudo dnf install -y docker-ce  # 或 docker")
			fmt.Println("    sudo systemctl enable --now docker")
			fmt.Println("")
			fmt.Println("  或参考官方文档: https://docs.docker.com/engine/install/")
			fmt.Println("")
			fmt.Println("\033[31m❌ Docker 不可用，已跳过 MySQL 容器部署。\033[0m")
			return
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

	// === Phase 3: config generation, binary install and service bring-up ===
	// ─── 步骤 2: 生成配置文件 ────────────────────────────
	fmt.Println("\n[2/5] 正在生成配置文件...")

	proxyContent, err := buildMasterProxyConfig(deploymentCoreConfigInput{
		DeployPath: deployPath, Domain: domain, CertPath: crtPath, KeyPath: keyPath,
		GatewayPort: gatewayPort, DataPlanePort: dataPlanePort, AdminPort: adminPort, ControlPort: controlPort,
		AdminUser: adminUser, AdminPass: adminPwd, DBPath: dbPath, SubPath: subPath,
	})
	if err != nil {
		fmt.Printf("\033[31m❌ 生成 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	gatewayContent, err := buildGatewayConfig(deploymentCoreConfigInput{
		DeployPath: deployPath, CertPath: crtPath, KeyPath: keyPath,
		GatewayPort: gatewayPort, DataPlanePort: dataPlanePort, AdminPort: adminPort, ControlPort: controlPort, SubPath: subPath,
	}, false)
	if err != nil {
		fmt.Printf("\033[31m❌ 生成 gateway.yaml 失败: %v\033[0m\n", err)
		return
	}
	webContent, err := buildMasterWebConfig(adminUser, adminPwd, adminPort, dbPath, subPath)
	if err != nil {
		fmt.Printf("\033[31m❌ 生成 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	if err := os.MkdirAll(deployPath, 0755); err != nil {
		fmt.Printf("\033[31m❌ 创建部署目录失败: %v\033[0m\n", err)
		return
	}

	// Hysteria2 由独立 hysteria.service 读取 hysteria.yaml；核心 Trojan-Go 并不消费
	// config.yaml 中的 hysteria2 元数据。订阅端的 HY2 开关由数据库配置持久化管理。

	if err := os.WriteFile(configPath, proxyContent, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "gateway.yaml"), gatewayContent, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入 gateway.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), webContent, 0600); err != nil {
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
	if err := installDeploymentBinaries(deployPath, tlsDir, crtPath, keyPath); err != nil {
		fmt.Printf("\033[31m❌ 安装二进制或设置权限失败: %v\033[0m\n", err)
		return
	}

	// ─── Hysteria2 部署（如用户选择启用） ──────
	if h2Enabled {
		fmt.Println("\n--- 开始 Hysteria2 (QUIC/UDP) 部署 ---")
		// 1. 下载、校验并原子安装 Hysteria2 二进制。失败后不继续创建配置或服务。
		fmt.Printf(" [!] 正在下载并验证 Hysteria2 %s...\n", hysteriaVersion)
		if err := installHysteriaBinary(); err != nil {
			fmt.Printf("\033[31m❌ Hysteria2 安装失败，已停止部署: %v\033[0m\n", err)
			return
		}
		fmt.Println("✓ Hysteria2 已通过 SHA-256 校验并安装至 /usr/local/bin/hysteria")

		// 2. 生成 Hysteria2 配置文件
		hysteriaConfig, err := buildHysteriaConfig(deploymentHysteriaConfigInput{
			ListenPort: h2Port, CertPath: crtPath, KeyPath: keyPath, ControlPort: controlPort, UpMbps: h2Up, DownMbps: h2Down,
		})
		if err != nil {
			fmt.Printf("\033[31m❌ 生成 Hysteria2 配置失败: %v\033[0m\n", err)
			return
		}
		hysteriaConfigPath := filepath.Join(deployPath, "hysteria.yaml")
		if err := os.WriteFile(hysteriaConfigPath, hysteriaConfig, 0600); err != nil {
			fmt.Printf("\033[31m❌ 写入 Hysteria2 配置失败: %v\033[0m\n", err)
			return
		}
		fmt.Printf("✓ Hysteria2 配置已生成 (%s)\n", hysteriaConfigPath)
	}

	// ─── 步骤 4-5: 写入服务、续期与启动验证 ──────────────────
	fmt.Println("\n[4/5] 正在配置 Systemd 服务与证书自动续期...")
	if err := configureAndStartDeployment(deploymentMaster, deployPath, h2Enabled, certificateRenewalConfig{
		Domain: domain, Email: email, CAURL: caURL, CertificatePath: crtPath, PrivateKeyPath: keyPath, ReloadHysteria: h2Enabled,
	}); err != nil {
		fmt.Printf("\033[31m❌ 配置或启动服务失败: %v\033[0m\n", err)
		return
	}

	fmt.Println("\n\033[32m=== 初始化部署成功 ! ===\033[0m")
	fmt.Printf("1. Gateway 统一入口: TCP/%d；Trojan data-plane: 127.0.0.1:%d\n", gatewayPort, dataPlanePort)
	fmt.Printf("2. admin-service: 127.0.0.1:%d；control-service: 127.0.0.1:%d\n", adminPort, controlPort)
	fmt.Printf("3. 安全订阅链接 (Gateway TLS 加密保护):\n")
	fmt.Printf("   - https://%s%s?token=[用户UUID]\n", domain, subPath)
	fmt.Printf("4. 管理后台入口：\n")
	fmt.Printf("   - https://%s/admin/\n", domain)
	fmt.Printf("   - 8081/8082/14443 均仅监听 loopback，不开放公网。\n")
	fmt.Printf("5. 证书自动续期已启用: systemctl status trojan-cert-renew.timer\n")
	fmt.Printf("6. 检查状态: trojan status\n")
}

// 简单的命令执行工具
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// InitDeployWorker 初始化部署（从节点）一键化流程
func InitDeployWorker() {
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))
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
		fmt.Println("\033[31m检测到现有 Worker 部署。初始化部署拒绝直接覆盖，以免留下新旧混合状态。\033[0m")
		fmt.Println("请准备带 SHA-256 校验的升级清单，并使用：trojan upgrade --manifest /path/to/upgrade.json")
		return
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Printf("\033[31m检查现有 Worker 部署失败: %v\033[0m\n", err)
		return
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

	// 3. Worker 同样由 Gateway 独占 TCP 443，data-plane 仅监听本机 14443。
	gatewayPort := defaultGatewayPort
	dataPlanePort := defaultDataPlanePort
	controlPort := defaultControlServicePort

	// 4. 主节点同步接口 URL (必填)
	masterURL := ""
	for {
		masterURL = getStdin("4. 节点同步接口 URL (必填，如 https://master.com/control/v1/nodes/sync): ", "4. Enter master sync URL (required): ")
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

	// 新 Gateway 架构当前仅支持原生 Trojan TLS 字节流；不生成 Trojan-over-WebSocket 路由。

	// 7. 管理面板用户名
	adminUser := getStdin("7. 设置管理面板用户名 (默认 admin): ", "7. Set admin username (default admin): ")
	if adminUser == "" {
		adminUser = "admin"
	}

	// 8. 管理面板密码：不再使用历史弱默认密码。
	adminPwd := promptAdminPassword("8. 设置管理面板密码（直接回车生成随机强密码）: ", "8. Set admin password (press Enter to generate a strong random password): ")
	if adminPwd == "" {
		return
	}

	// Worker 不部署 admin-service；control-service 固定监听 loopback 8082。
	adminPort := defaultAdminServicePort // 仅用于结构兼容，不创建 Worker admin-service。

	// 10. 是否启用 Hysteria2 (QUIC/UDP)
	wh2Enabled := false
	wh2Port := 443
	wh2Up := 100
	wh2Down := 300
	wh2Ans := getStdin("10. 是否启用 Hysteria2 (QUIC/UDP) 协议？(y/n, 默认 n): ", "10. Enable Hysteria2 (QUIC/UDP) protocol? (y/n, default n): ")
	if wh2Ans == "y" || wh2Ans == "Y" {
		wh2Enabled = true
		wh2PortStr := getStdin("    Hysteria2 监听端口 (默认 443): ", "    Hysteria2 listen port (default 443): ")
		if wh2PortStr != "" {
			fmt.Sscanf(wh2PortStr, "%d", &wh2Port)
		}
		wh2UpStr := getStdin("    上行带宽 Mbps（请填写 VPS 实际上行带宽，默认 100）: ", "    Upstream bandwidth Mbps (enter VPS actual uplink, default 100): ")
		if wh2UpStr != "" {
			fmt.Sscanf(wh2UpStr, "%d", &wh2Up)
		}
		wh2DownStr := getStdin("    下行带宽 Mbps（请填写 VPS 实际下行带宽，默认 300）: ", "    Downstream bandwidth Mbps (enter VPS actual downlink, default 300): ")
		if wh2DownStr != "" {
			fmt.Sscanf(wh2DownStr, "%d", &wh2Down)
		}
	}

	// SQLite 作为本地缓存库，路径定为 deployPath/trojan-go.db
	dbPath := filepath.Join(deployPath, "trojan-go.db")

	const workerPathLetters = "abcdefghijklmnopqrstuvwxyz0123456789"
	// 动态生成 8 位随机字符组成订阅路径；Worker Gateway 不暴露该路径，字段仅供缓存配置兼容。
	subChars := make([]byte, 8)
	for i := range subChars {
		subChars[i] = workerPathLetters[r.Intn(len(workerPathLetters))]
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
	crtPath := filepath.Join(tlsDir, domain+".crt")
	keyPath := filepath.Join(tlsDir, domain+".key")
	if err := writeCertificateFiles(crtPath, keyPath, certs.Certificate, certs.PrivateKey); err != nil {
		fmt.Printf("\033[31m❌ 证书写入失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ SSL 证书已成功下载并写入配置目录\033[0m")

	// ─── 步骤 2: 生成配置文件 ────────────────────────────
	fmt.Println("\n[2/5] 正在生成配置文件...")

	proxyContent, err := buildWorkerProxyConfig(deploymentCoreConfigInput{
		DeployPath: deployPath, Domain: domain, CertPath: crtPath, KeyPath: keyPath,
		GatewayPort: gatewayPort, DataPlanePort: dataPlanePort, AdminPort: adminPort, ControlPort: controlPort,
		AdminUser: adminUser, AdminPass: adminPwd, DBPath: dbPath, SubPath: subPath,
		Node: &deploymentNodeConfig{Enabled: true, MasterURL: masterURL, Secret: nodeSecret, SyncInterval: 60},
	})
	if err != nil {
		fmt.Printf("\033[31m❌ 生成从节点 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	gatewayContent, err := buildGatewayConfig(deploymentCoreConfigInput{
		DeployPath: deployPath, CertPath: crtPath, KeyPath: keyPath,
		GatewayPort: gatewayPort, DataPlanePort: dataPlanePort, AdminPort: adminPort, ControlPort: controlPort, SubPath: subPath,
	}, true)
	if err != nil {
		fmt.Printf("\033[31m❌ 生成从节点 gateway.yaml 失败: %v\033[0m\n", err)
		return
	}
	webContent, err := buildWorkerWebConfig(adminUser, adminPwd, controlPort, dbPath, subPath)
	if err != nil {
		fmt.Printf("\033[31m❌ 生成从节点 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	if err := os.MkdirAll(deployPath, 0755); err != nil {
		fmt.Printf("\033[31m❌ 创建部署目录失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(configPath, proxyContent, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入 config.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "gateway.yaml"), gatewayContent, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入 gateway.yaml 失败: %v\033[0m\n", err)
		return
	}
	if err := os.WriteFile(filepath.Join(deployPath, "web_config.yaml"), webContent, 0600); err != nil {
		fmt.Printf("\033[31m❌ 写入 web_config.yaml 失败: %v\033[0m\n", err)
		return
	}

	// 创建内置首页 (防探测，使用逼真标准 Nginx 测试页面)
	if err := os.WriteFile(filepath.Join(deployPath, "index.html"), []byte(nginxWelcome), 0644); err != nil {
		fmt.Printf("\033[31m❌ 写入伪装首页失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ 配置文件已生成\033[0m")

	// ─── 步骤 3: 自动安装二进制文件 ────────────────────────────
	fmt.Println("\n[3/5] 正在安装二进制文件到系统路径...")
	if err := installDeploymentBinaries(deployPath, tlsDir, crtPath, keyPath); err != nil {
		fmt.Printf("\033[31m❌ 安装二进制或设置权限失败: %v\033[0m\n", err)
		return
	}

	// ─── Hysteria2 部署（从节点，如用户选择启用） ──────
	if wh2Enabled {
		fmt.Println("\n--- 开始 Hysteria2 (QUIC/UDP) 从节点部署 ---")
		fmt.Printf(" [!] 正在下载并验证 Hysteria2 %s...\n", hysteriaVersion)
		if err := installHysteriaBinary(); err != nil {
			fmt.Printf("\033[31m❌ Hysteria2 安装失败，已停止部署: %v\033[0m\n", err)
			return
		}
		fmt.Println("✓ Hysteria2 已通过 SHA-256 校验并安装")
		hysteriaConfig, err := buildHysteriaConfig(deploymentHysteriaConfigInput{
			ListenPort: wh2Port, CertPath: crtPath, KeyPath: keyPath, ControlPort: controlPort, UpMbps: wh2Up, DownMbps: wh2Down,
		})
		if err != nil {
			fmt.Printf("\033[31m❌ 生成 Hysteria2 从节点配置失败: %v\033[0m\n", err)
			return
		}
		hysteriaConfigPath := filepath.Join(deployPath, "hysteria.yaml")
		if err := os.WriteFile(hysteriaConfigPath, hysteriaConfig, 0600); err != nil {
			fmt.Printf("\033[31m❌ 写入 Hysteria2 从节点配置失败: %v\033[0m\n", err)
			return
		}
		fmt.Printf("✓ Hysteria2 从节点配置已生成 (%s)\n", hysteriaConfigPath)
	}

	// ─── 步骤 4-5: 写入服务、续期与启动验证 ──────────────────
	fmt.Println("\n[4/5] 正在配置 Systemd 服务与证书自动续期...")
	if err := configureAndStartDeployment(deploymentWorker, deployPath, wh2Enabled, certificateRenewalConfig{
		Domain: domain, Email: email, CAURL: "https://acme-v02.api.letsencrypt.org/directory", CertificatePath: crtPath, PrivateKeyPath: keyPath, ReloadHysteria: wh2Enabled,
	}); err != nil {
		fmt.Printf("\033[31m❌ 配置或启动服务失败: %v\033[0m\n", err)
		return
	}

	fmt.Println("\n\033[32m=== 从节点部署成功 ! ===\033[0m")
	fmt.Printf("1. Worker Gateway: TCP/%d；Trojan data-plane: 127.0.0.1:%d\n", gatewayPort, dataPlanePort)
	fmt.Printf("2. Worker control-service: 127.0.0.1:%d；不部署 admin-service。\n", controlPort)
	fmt.Println("3. Worker 不提供 /admin 与订阅；管理和订阅由 Master Gateway 统一输出。")
	fmt.Println("4. 节点同步使用 /control/v1/nodes/sync，Hysteria2 Auth 使用本机 control-service。")
	fmt.Println("5. 证书自动续期已启用: systemctl status trojan-cert-renew.timer")
}
