package certmonitor

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// acmeAccountDir is where persisted ACME account material lives.
const acmeAccountDir = "/var/lib/trojan-go/acme"

// persistedACMEAccount is the on-disk form of a registered ACME account.
type persistedACMEAccount struct {
	Email        string                 `json:"email"`
	Registration *registration.Resource `json:"registration"`
	PrivateKey   string                 `json:"private_key"` // PEM-encoded EC key
}

type legoUser struct {
	Email        string
	Registration *registration.Resource
	key          *ecdsa.PrivateKey
}

func (u *legoUser) GetEmail() string                       { return u.Email }
func (u legoUser) GetRegistration() *registration.Resource { return u.Registration }
func (u *legoUser) GetPrivateKey() crypto.PrivateKey       { return u.key }

func acmeAccountPath(email, caURL string) string {
	sum := sha256.Sum256([]byte(email + "|" + caURL))
	return filepath.Join(acmeAccountDir, "account-"+hex.EncodeToString(sum[:8])+".json")
}

// loadACMEAccount returns a previously persisted account for (email, caURL),
// or (nil, nil) if none exists yet.
func loadACMEAccount(email, caURL string) (*legoUser, error) {
	data, err := os.ReadFile(acmeAccountPath(email, caURL))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var acct persistedACMEAccount
	if err := json.Unmarshal(data, &acct); err != nil {
		return nil, fmt.Errorf("parse persisted ACME account: %w", err)
	}
	block, _ := pem.Decode([]byte(acct.PrivateKey))
	if block == nil {
		return nil, fmt.Errorf("persisted ACME account key is not PEM")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse persisted ACME account key: %w", err)
	}
	return &legoUser{Email: acct.Email, Registration: acct.Registration, key: key}, nil
}

// saveACMEAccount persists a registered account so future renewals reuse it.
func saveACMEAccount(user *legoUser, caURL string) error {
	if err := os.MkdirAll(acmeAccountDir, 0o700); err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(user.key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	data, err := json.Marshal(persistedACMEAccount{
		Email:        user.Email,
		Registration: user.Registration,
		PrivateKey:   string(keyPEM),
	})
	if err != nil {
		return err
	}
	path := acmeAccountPath(user.Email, caURL)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ObtainCert performs ACME certificate issuance using the HTTP-01 challenge
// on port 80. It reuses a previously persisted ACME account to avoid rate
// limits on repeated renewals.
func ObtainCert(domain, email, caURL string) (*certificate.Resource, error) {
	resolvedCA := caURL
	if resolvedCA == "" {
		resolvedCA = lego.LEDirectoryProduction
	}

	user, err := loadACMEAccount(email, resolvedCA)
	if err != nil {
		return nil, fmt.Errorf("load persisted ACME account: %w", err)
	}
	newAccount := user == nil
	if newAccount {
		privateKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if keyErr != nil {
			return nil, keyErr
		}
		user = &legoUser{Email: email, key: privateKey}
	}

	config := lego.NewConfig(user)
	config.CADirURL = resolvedCA

	client, err := lego.NewClient(config)
	if err != nil {
		return nil, err
	}

	provider := http01.NewProviderServer("", "80")
	if err = client.Challenge.SetHTTP01Provider(provider); err != nil {
		return nil, err
	}

	if newAccount {
		reg, regErr := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if regErr != nil {
			return nil, regErr
		}
		user.Registration = reg
		if saveErr := saveACMEAccount(user, resolvedCA); saveErr != nil {
			fmt.Printf(" [警告] ACME 账户未能持久化，下次续期将重新注册: %v\n", saveErr)
		}
	}

	// Retry up to 3 times to handle Let's Encrypt 404 sync delay.
	var res *certificate.Resource
	for i := 1; i <= 3; i++ {
		res, err = client.Certificate.Obtain(certificate.ObtainRequest{
			Domains: []string{domain},
			Bundle:  true,
		})
		if err == nil {
			return res, nil
		}
		if strings.Contains(err.Error(), "404") {
			fmt.Printf(" [警告] ACME 服务器返回 404 (同步延迟)，正在进行第 %d 次重试...\n", i)
			time.Sleep(3 * time.Second)
			continue
		}
		break
	}
	return nil, err
}
