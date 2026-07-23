package actions

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/voidluo/trojan-go/cmd/trojan/menu"
)

type legoUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *legoUser) GetEmail() string                       { return u.Email }
func (u legoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey       { return u.key }

// getStdin 获取用户输入
func getStdin(promptCN, promptEN string) string {
	prompt := promptCN
	if menu.CurrentLang == menu.EN {
		prompt = promptEN
	}
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	s, _ := reader.ReadString('\n')
	return strings.TrimSpace(s)
}

// obtainCert 内部函数：执行证书申请，返回证书内容和私钥内容
func obtainCert(domain, email, caURL string) (*certificate.Resource, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	user := &legoUser{Email: email, key: privateKey}
	config := lego.NewConfig(user)
	if caURL != "" {
		config.CADirURL = caURL
	} else {
		config.CADirURL = lego.LEDirectoryProduction
	}

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	provider := http01.NewProviderServer("", "80")
	if err = client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, err
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return nil, err
	}
	user.Registration = reg

	// 增加重试逻辑，应对 Let's Encrypt 的 404 同步延迟 bug
	var res *certificate.Resource
	for i := 1; i <= 3; i++ {
		res, err = client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		})
		if err == nil {
			return res, nil
		}
		// 如果是 404 错误，则等待后重试
		if strings.Contains(err.Error(), "404") {
			fmt.Printf(" [警告] ACME 服务器返回 404 (同步延迟)，正在进行第 %d 次重试...\n", i)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	return nil, err
}
