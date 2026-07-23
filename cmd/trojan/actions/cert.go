package actions

import (
	"fmt"
	"os"

	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

// ApplyCert 交互式申请 SSL 证书
func ApplyCert() {
	// 基础权限检查 (针对 Linux)
	if os.Geteuid() != 0 {
		msg := "错误：申请证书需要写入 /etc/ 目录，请使用 sudo 运行此程序！"
		if menu.CurrentLang == menu.EN {
			msg = "Error: ACME requires sudo privileges!"
		}
		fmt.Printf("\033[31m%s\033[0m\n", msg)
		return
	}

	title := "=== SSL 证书一键申请 (ACME) ==="
	if menu.CurrentLang == menu.EN {
		title = "=== ACME Certificate Request ==="
	}
	fmt.Printf("\033[36m%s\033[0m\n", title)

	fmt.Println("\n请选择证书颁发机构 (CA):")
	fmt.Println("1. Let's Encrypt (默认)")
	fmt.Println("2. BuyPass (Go SSL)")
	caChoice := getStdin("请选择 [1-2]: ", "Select [1-2]: ")

	caURL := "https://acme-v02.api.letsencrypt.org/directory"
	caName := "Let's Encrypt"
	if caChoice == "2" {
		caURL = "https://api.buypass.com/acme/directory"
		caName = "BuyPass"
	}

	fmt.Printf("\n--- 正在通过 %s 进行申请 ---\n", caName)
	domain := getStdin("请输入域名 (如: example.com): ", "Enter your domain (e.g. example.com): ")
	email := getStdin("请输入邮箱 (用于注册账户): ", "Enter your email (for ACME registration): ")

	if domain == "" || email == "" {
		fmt.Println("域名或邮箱不能为空")
		return
	}

	progress := fmt.Sprintf("\n正在向 %s 发起申请 (HTTP-01 验证)... ", caName)
	note := "[注意] 此操作将临时启动 80 端口验证，请确保 80 端口未被占用。"
	if menu.CurrentLang == menu.EN {
		progress = fmt.Sprintf("\nRequesting certificate for %s (HTTP-01)... ", domain)
		note = "[Note] Port 80 must be available for verification."
	}
	fmt.Println(progress)
	fmt.Printf("\033[33m%s\033[0m\n\n", note)

	certs, err := obtainCert(domain, email, caURL)
	if err != nil {
		fmt.Printf("\033[31m申请失败: %v\033[0m\n", err)
		return
	}

	// 保存证书；任何目录或文件写入失败都必须显式返回，避免误报申请成功。
	if err := writeCertificateFiles("/etc/trojan-go/cert.pem", "/etc/trojan-go/key.pem", certs.Certificate, certs.PrivateKey); err != nil {
		fmt.Printf("\033[31m保存证书失败: %v\033[0m\n", err)
		return
	}

	successMsg := "✓ 证书申请成功！"
	if menu.CurrentLang == menu.EN {
		successMsg = "✓ Certificate obtained successfully!"
	}
	fmt.Printf("\033[32m%s\033[0m\n  证书: /etc/trojan-go/cert.pem\n  私钥: /etc/trojan-go/key.pem\n", successMsg)
}
