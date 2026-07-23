package database

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func credentialTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "credentials.key")
	t.Setenv(credentialKeyEnvironment, keyPath)
	if err := EnsureCredentialKey(); err != nil {
		t.Fatalf("provision credential key: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "credentials.db")), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &Node{}, &Config{}); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	return db
}

func TestCredentialEncryptionBindsPurposeAndRejectsTampering(t *testing.T) {
	credentialTestDB(t)
	ciphertext, err := EncryptCredential("user-password:1", "secret-value")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(ciphertext, credentialCipherVersion) || strings.Contains(ciphertext, "secret-value") {
		t.Fatalf("unexpected ciphertext representation: %q", ciphertext)
	}
	value, err := DecryptCredential("user-password:1", ciphertext)
	if err != nil || value != "secret-value" {
		t.Fatalf("decrypt got value=%q err=%v", value, err)
	}
	if _, err := DecryptCredential("node-secret:1", ciphertext); err == nil {
		t.Fatal("ciphertext must not decrypt for another credential purpose")
	}
	encoded := strings.TrimPrefix(ciphertext, credentialCipherVersion)
	replacement := "A"
	if encoded[0] == 'A' {
		replacement = "B"
	}
	tampered := credentialCipherVersion + replacement + encoded[1:]
	if _, err := DecryptCredential("user-password:1", tampered); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
}

func TestSetUserPasswordEncryptsAtRest(t *testing.T) {
	db := credentialTestDB(t)
	user := User{Username: "alice", Hash: "initial"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := SetUserPassword(db, &user, "trojan-password"); err != nil {
		t.Fatalf("set user password: %v", err)
	}
	var stored User
	if err := db.First(&stored, user.ID).Error; err != nil {
		t.Fatalf("read user: %v", err)
	}
	if stored.Password != "" || stored.PasswordCiphertext == "" || stored.PasswordKeyID != "default" {
		t.Fatalf("plaintext user password was retained: %#v", stored)
	}
	password, err := UserPassword(stored)
	if err != nil || password != "trojan-password" {
		t.Fatalf("recover user password got=%q err=%v", password, err)
	}
}

func TestSetNodeSecretUsesFingerprintLookup(t *testing.T) {
	db := credentialTestDB(t)
	node := Node{Name: "worker", Address: "worker.example.com", Port: 443, Secret: "initial"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	if err := SetNodeSecret(db, &node, "worker-secret"); err != nil {
		t.Fatalf("set node secret: %v", err)
	}
	var stored Node
	if err := db.First(&stored, node.ID).Error; err != nil {
		t.Fatalf("read node: %v", err)
	}
	if stored.Secret == "worker-secret" || stored.SecretCiphertext == "" || stored.SecretHash == "" {
		t.Fatalf("node secret storage is unsafe: %#v", stored)
	}
	matched, err := NodeBySecret(db, "worker-secret")
	if err != nil || matched.ID != node.ID {
		t.Fatalf("lookup new node secret: node=%#v err=%v", matched, err)
	}
	if _, err := NodeBySecret(db, "wrong-secret"); err == nil {
		t.Fatal("wrong node secret must be rejected")
	}
}

func TestSetAdminPasswordHashesValue(t *testing.T) {
	db := credentialTestDB(t)
	if err := SetAdminPassword(db, "panel-password"); err != nil {
		t.Fatalf("set admin password: %v", err)
	}
	var config Config
	if err := db.Where("`key` = ?", "admin_password").First(&config).Error; err != nil {
		t.Fatalf("read admin password: %v", err)
	}
	if !strings.HasPrefix(config.Value, "$2") || strings.Contains(config.Value, "panel-password") {
		t.Fatalf("admin password is not bcrypt encoded: %q", config.Value)
	}
}

func TestCredentialKeyRequiresOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.key")
	t.Setenv(credentialKeyEnvironment, path)
	if err := os.WriteFile(path, make([]byte, 32), 0644); err != nil {
		t.Fatalf("write permissive key: %v", err)
	}
	if _, err := EncryptCredential("test", "value"); err == nil {
		t.Fatal("permissive credential key must be rejected")
	}
}
