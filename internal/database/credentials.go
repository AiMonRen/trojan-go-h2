package database

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

const (
	credentialKeyEnvironment = "TROJAN_CREDENTIAL_KEY_FILE"
	defaultCredentialKeyPath = "/etc/trojan-go/credentials.key"
	credentialCipherVersion  = "enc:v1:default:"
)

// CredentialKeyPath returns the deployment-external encryption key location.
// Deployments may override it with TROJAN_CREDENTIAL_KEY_FILE for managed secret
// stores or test isolation. The key itself is never persisted in the database.
func CredentialKeyPath() string {
	if path := strings.TrimSpace(os.Getenv(credentialKeyEnvironment)); path != "" {
		return path
	}
	return defaultCredentialKeyPath
}

// EnsureCredentialKey creates a new AES-256 key only when the configured key
// file is absent. It must be called by an installer or an explicit provisioning
// workflow, never implicitly during normal database initialization.
func EnsureCredentialKey() error {
	path := CredentialKeyPath()
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != 32 {
			return fmt.Errorf("credential key %s must contain exactly 32 bytes", path)
		}
		return checkCredentialKeyPermissions(path)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read credential key %s: %w", path, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create credential key directory: %w", err)
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(cryptorand.Reader, key); err != nil {
		return fmt.Errorf("generate credential key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if errors.Is(err, os.ErrExist) {
		return EnsureCredentialKey()
	}
	if err != nil {
		return fmt.Errorf("create credential key %s: %w", path, err)
	}
	defer file.Close()
	if _, err := file.Write(key); err != nil {
		return fmt.Errorf("write credential key: %w", err)
	}
	return nil
}

func loadCredentialKey() ([]byte, error) {
	path := CredentialKeyPath()
	key, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if err := EnsureCredentialKey(); err != nil {
			return nil, fmt.Errorf("provision credential key at %s: %w", path, err)
		}
		key, err = os.ReadFile(path)
	}
	if err != nil {
		return nil, fmt.Errorf("read credential key %s: %w", path, err)
	}
	if err := checkCredentialKeyPermissions(path); err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("credential key %s must contain exactly 32 bytes", path)
	}
	return key, nil
}

func checkCredentialKeyPermissions(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect credential key %s: %w", path, err)
	}
	if info.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("credential key %s must be readable only by its owner (mode 0600)", path)
	}
	return nil
}

// EncryptCredential uses AES-256-GCM with a unique nonce and binds the value to
// its storage purpose through associated authenticated data.
func EncryptCredential(purpose, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	key, err := loadCredentialKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("initialize credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize credential AEAD: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(cryptorand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate credential nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(value), []byte(purpose))
	payload := append(nonce, ciphertext...)
	return credentialCipherVersion + base64.RawURLEncoding.EncodeToString(payload), nil
}

// DecryptCredential rejects malformed, unknown, or tampered values instead of
// silently falling back to a potentially unsafe interpretation.
func DecryptCredential(purpose, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, credentialCipherVersion) {
		return "", errors.New("credential ciphertext has an unsupported format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(value, credentialCipherVersion))
	if err != nil {
		return "", fmt.Errorf("decode credential ciphertext: %w", err)
	}
	key, err := loadCredentialKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("initialize credential cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("initialize credential AEAD: %w", err)
	}
	if len(payload) < gcm.NonceSize() {
		return "", errors.New("credential ciphertext is too short")
	}
	plaintext, err := gcm.Open(nil, payload[:gcm.NonceSize()], payload[gcm.NonceSize():], []byte(purpose))
	if err != nil {
		return "", errors.New("credential ciphertext authentication failed")
	}
	return string(plaintext), nil
}

// CredentialFingerprint is a keyed, non-reversible lookup value. It is used
// for node Secret authentication so the database never needs plaintext lookup.
func CredentialFingerprint(purpose, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	key, err := loadCredentialKey()
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(purpose))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(value))
	return fmt.Sprintf("%x", mac.Sum(nil)), nil
}

func userPasswordPurpose(id uint) string { return fmt.Sprintf("user-password:%d", id) }
func nodeSecretPurpose(id uint) string   { return fmt.Sprintf("node-secret:%d", id) }

// PendingNodeSecretMarker reserves the legacy unique column without ever
// writing the usable Worker credential before encryption completes.
func PendingNodeSecretMarker() (string, error) {
	buf := make([]byte, 16)
	if _, err := io.ReadFull(cryptorand.Reader, buf); err != nil {
		return "", fmt.Errorf("generate pending node credential marker: %w", err)
	}
	return "pending:" + base64.RawURLEncoding.EncodeToString(buf), nil
}

// SetUserPassword stores a recoverable Trojan password encrypted at rest while
// retaining Hash for protocol authentication and duplicate checks.
func SetUserPassword(db *gorm.DB, user *User, password string) error {
	if db == nil || user == nil {
		return errors.New("database and user are required")
	}
	if user.ID == 0 {
		return errors.New("user must be persisted before encrypting a password")
	}
	ciphertext, err := EncryptCredential(userPasswordPurpose(user.ID), password)
	if err != nil {
		return err
	}
	user.Password = ""
	user.PasswordCiphertext = ciphertext
	user.PasswordKeyID = "default"
	user.Hash = sha224Password(password)
	return db.Model(user).Updates(map[string]any{
		"password":            "",
		"password_ciphertext": ciphertext,
		"password_key_id":     "default",
		"hash":                user.Hash,
	}).Error
}

// UserPassword decrypts new-format rows and uses legacy plaintext only while a
// forward migration has not yet converted that individual record.
func UserPassword(user User) (string, error) {
	if user.PasswordCiphertext != "" {
		return DecryptCredential(userPasswordPurpose(user.ID), user.PasswordCiphertext)
	}
	return user.Password, nil
}

// SetNodeSecret persists an encrypted node credential and keyed lookup hash.
func SetNodeSecret(db *gorm.DB, node *Node, secret string) error {
	if db == nil || node == nil || node.ID == 0 {
		return errors.New("persisted node and database are required")
	}
	ciphertext, err := EncryptCredential(nodeSecretPurpose(node.ID), secret)
	if err != nil {
		return err
	}
	fingerprint, err := CredentialFingerprint("node-secret-lookup", secret)
	if err != nil {
		return err
	}
	now := timeNowUTC()
	// Keep a unique non-secret marker in the legacy column until a separately
	// confirmed contract migration can remove its historical unique index.
	node.Secret = fmt.Sprintf("retired:%d", node.ID)
	node.SecretCiphertext = ciphertext
	node.SecretHash = fingerprint
	node.SecretKeyID = "default"
	node.SecretRotatedAt = &now
	return db.Model(node).Updates(map[string]any{
		"secret":            node.Secret,
		"secret_ciphertext": ciphertext,
		"secret_hash":       fingerprint,
		"secret_key_id":     "default",
		"secret_rotated_at": now,
	}).Error
}

// NodeBySecret uses the keyed lookup hash for migrated rows and retains a
// legacy fallback only until the database migration has completed.
func NodeBySecret(db *gorm.DB, secret string) (Node, error) {
	if db == nil {
		return Node{}, errors.New("database is required")
	}
	fingerprint, err := CredentialFingerprint("node-secret-lookup", secret)
	if err != nil {
		return Node{}, err
	}
	var node Node
	if err := db.Where("secret_hash = ?", fingerprint).First(&node).Error; err == nil {
		return node, nil
	} else if !errors.Is(err, gorm.ErrRecordNotFound) {
		return Node{}, err
	}
	// Legacy fallback is intentionally limited to rows not yet migrated. Once a
	// node has a ciphertext, authentication must never fall back to plaintext.
	if err := db.Where("secret = ? AND (secret_ciphertext = '' OR secret_ciphertext IS NULL)", secret).First(&node).Error; err != nil {
		return Node{}, err
	}
	return node, nil
}

// SetAdminPassword is the single password writer for CLI and Web callers.
func SetAdminPassword(db *gorm.DB, password string) error {
	if db == nil || password == "" {
		return errors.New("database and non-empty administrator password are required")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("hash administrator password: %w", err)
	}
	return db.Save(&Config{Key: "admin_password", Value: string(hash)}).Error
}

// RotateJWTSecret replaces the signing key with an encrypted Config value.
func RotateJWTSecret(db *gorm.DB) ([]byte, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	secret := make([]byte, 32)
	if _, err := io.ReadFull(cryptorand.Reader, secret); err != nil {
		return nil, fmt.Errorf("generate JWT secret: %w", err)
	}
	ciphertext, err := EncryptCredential("jwt-secret:global", base64.RawURLEncoding.EncodeToString(secret))
	if err != nil {
		return nil, err
	}
	if err := db.Save(&Config{Key: "jwt_secret", Value: ciphertext}).Error; err != nil {
		return nil, err
	}
	return secret, nil
}

// LoadJWTSecret supports the one-way migration from legacy plaintext storage.
func LoadJWTSecret(db *gorm.DB) ([]byte, error) {
	if db == nil {
		return nil, errors.New("database is required")
	}
	var config Config
	if err := db.Where("`key` = ?", "jwt_secret").First(&config).Error; err == nil && config.Value != "" {
		if strings.HasPrefix(config.Value, credentialCipherVersion) {
			encoded, err := DecryptCredential("jwt-secret:global", config.Value)
			if err != nil {
				return nil, err
			}
			secret, err := base64.RawURLEncoding.DecodeString(encoded)
			if err != nil || len(secret) != 32 {
				return nil, errors.New("stored JWT secret is invalid")
			}
			return secret, nil
		}
		legacy := []byte(config.Value)
		if len(legacy) == 32 {
			ciphertext, err := EncryptCredential("jwt-secret:global", base64.RawURLEncoding.EncodeToString(legacy))
			if err != nil {
				return nil, err
			}
			if err := db.Model(&Config{}).Where("`key` = ?", "jwt_secret").Update("value", ciphertext).Error; err != nil {
				return nil, err
			}
			return legacy, nil
		}
	}
	return RotateJWTSecret(db)
}

// timeNowUTC is a variable only to make lifecycle timestamps deterministic in tests.
var timeNowUTC = func() time.Time { return time.Now().UTC() }

func sha224Password(password string) string {
	sum := sha256.Sum224([]byte(password))
	return fmt.Sprintf("%x", sum[:])
}
