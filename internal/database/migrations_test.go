package database

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openMigrationTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/migrations.db"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	return db
}

func TestRunMigrationsAppliesInOrderAndIsIdempotent(t *testing.T) {
	db := openMigrationTestDB(t)
	var calls []uint64
	migrations := []Migration{
		{Version: 10, Name: "first", Revision: "v1", Up: func(tx *gorm.DB) error { calls = append(calls, 10); return nil }},
		{Version: 20, Name: "second", Revision: "v1", Up: func(tx *gorm.DB) error { calls = append(calls, 20); return nil }},
	}
	if err := runMigrations(db, migrations); err != nil {
		t.Fatalf("first migration run: %v", err)
	}
	if len(calls) != 2 || calls[0] != 10 || calls[1] != 20 {
		t.Fatalf("migration order = %v, want [10 20]", calls)
	}
	if err := runMigrations(db, migrations); err != nil {
		t.Fatalf("second migration run: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("completed migrations ran again: %v", calls)
	}

	var records []SchemaMigration
	if err := db.Order("version").Find(&records).Error; err != nil {
		t.Fatalf("read migration records: %v", err)
	}
	if len(records) != 2 || records[0].Version != 10 || records[1].Version != 20 {
		t.Fatalf("migration records = %+v", records)
	}
	var audits []MigrationAudit
	if err := db.Order("id").Find(&audits).Error; err != nil {
		t.Fatalf("read migration audits: %v", err)
	}
	if len(audits) != 2 || audits[0].Status != migrationStatusApplied || audits[1].Status != migrationStatusApplied {
		t.Fatalf("audits = %+v", audits)
	}
}

func TestRunMigrationsRejectsChangedPublishedMigration(t *testing.T) {
	db := openMigrationTestDB(t)
	original := []Migration{{Version: 1, Name: "published", Revision: "v1", Up: func(*gorm.DB) error { return nil }}}
	if err := runMigrations(db, original); err != nil {
		t.Fatalf("apply original migration: %v", err)
	}
	changed := []Migration{{Version: 1, Name: "published", Revision: "v2", Up: func(*gorm.DB) error { return nil }}}
	if err := runMigrations(db, changed); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("changed migration error = %v, want checksum mismatch", err)
	}
}

func TestRunMigrationsRollsBackFailureAndAuditsIt(t *testing.T) {
	db := openMigrationTestDB(t)
	if err := db.AutoMigrate(&Config{}); err != nil {
		t.Fatalf("create config table: %v", err)
	}
	migrations := []Migration{{
		Version: 1, Name: "failing_change", Revision: "v1",
		Up: func(tx *gorm.DB) error {
			if err := tx.Create(&Config{Key: "must_not_persist", Value: "value"}).Error; err != nil {
				return err
			}
			return errors.New("expected migration failure")
		},
	}}
	if err := runMigrations(db, migrations); err == nil || !strings.Contains(err.Error(), "expected migration failure") {
		t.Fatalf("migration error = %v", err)
	}
	var config Config
	if err := db.Where("key = ?", "must_not_persist").First(&config).Error; !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("failed migration data persisted: config=%+v err=%v", config, err)
	}
	var migrationCount int64
	if err := db.Model(&SchemaMigration{}).Count(&migrationCount).Error; err != nil {
		t.Fatalf("count migrations: %v", err)
	}
	if migrationCount != 0 {
		t.Fatalf("failed migration was recorded as applied: %d", migrationCount)
	}
	var audit MigrationAudit
	if err := db.Where("version = ?", 1).First(&audit).Error; err != nil {
		t.Fatalf("read failure audit: %v", err)
	}
	if audit.Status != migrationStatusFailed || !strings.Contains(audit.ErrorMessage, "expected migration failure") || audit.FinishedAt == nil {
		t.Fatalf("failure audit = %+v", audit)
	}
}

func TestRunMigrationsRejectsInvalidOrder(t *testing.T) {
	db := openMigrationTestDB(t)
	migrations := []Migration{
		{Version: 2, Name: "second", Revision: "v1", Up: func(*gorm.DB) error { return nil }},
		{Version: 1, Name: "first", Revision: "v1", Up: func(*gorm.DB) error { return nil }},
	}
	if err := runMigrations(db, migrations); err == nil || !strings.Contains(err.Error(), "strictly increasing") {
		t.Fatalf("invalid migration order error = %v", err)
	}
}

func TestCredentialMigrationEncryptsLegacyRows(t *testing.T) {
	keyPath := t.TempDir() + "/credentials.key"
	t.Setenv(credentialKeyEnvironment, keyPath)
	if err := EnsureCredentialKey(); err != nil {
		t.Fatalf("provision credential key: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/credentials-migration.db"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &Node{}, &Config{}); err != nil {
		t.Fatalf("migrate database: %v", err)
	}
	user := User{Username: "legacy-user", Password: "legacy-password", Hash: sha224Password("legacy-password")}
	node := Node{Name: "legacy-node", Address: "legacy.example.com", Port: 443, Secret: "legacy-node-secret"}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create legacy user: %v", err)
	}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create legacy node: %v", err)
	}
	if err := encryptRecoverableCredentials(db); err != nil {
		t.Fatalf("encrypt legacy credentials: %v", err)
	}
	var migratedUser User
	var migratedNode Node
	if err := db.First(&migratedUser, user.ID).Error; err != nil {
		t.Fatalf("read migrated user: %v", err)
	}
	if err := db.First(&migratedNode, node.ID).Error; err != nil {
		t.Fatalf("read migrated node: %v", err)
	}
	if migratedUser.Password != "" || migratedUser.PasswordCiphertext == "" {
		t.Fatalf("legacy user plaintext not cleared: %#v", migratedUser)
	}
	if migratedNode.Secret == "legacy-node-secret" || migratedNode.SecretCiphertext == "" || migratedNode.SecretHash == "" {
		t.Fatalf("legacy node secret not protected: %#v", migratedNode)
	}
	if password, err := UserPassword(migratedUser); err != nil || password != "legacy-password" {
		t.Fatalf("migrated password unavailable: %q, %v", password, err)
	}
	if found, err := NodeBySecret(db, "legacy-node-secret"); err != nil || found.ID != node.ID {
		t.Fatalf("migrated node authentication failed: %#v, %v", found, err)
	}
}

// TestPurgeSyncPlaceholderPasswords covers S-08: the placeholder credential a
// worker node used to cache must be cleared in both its plaintext and its
// already-encrypted form, while real credentials are left untouched.
func TestPurgeSyncPlaceholderPasswords(t *testing.T) {
	keyPath := t.TempDir() + "/credentials.key"
	t.Setenv(credentialKeyEnvironment, keyPath)
	if err := EnsureCredentialKey(); err != nil {
		t.Fatalf("provision credential key: %v", err)
	}
	db, err := gorm.Open(sqlite.Open(t.TempDir()+"/placeholder.db"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	if err := db.AutoMigrate(&User{}, &Node{}, &Config{}); err != nil {
		t.Fatalf("migrate database: %v", err)
	}

	plain := User{Username: "sync-user-aaaaaa", Password: legacySyncPlaceholderPassword, Hash: sha224Password("aaa")}
	encrypted := User{Username: "sync-user-bbbbbb", Password: legacySyncPlaceholderPassword, Hash: sha224Password("bbb")}
	real := User{Username: "real-user", Password: "a-real-password", Hash: sha224Password("ccc")}
	for _, u := range []*User{&plain, &encrypted, &real} {
		if err := db.Create(u).Error; err != nil {
			t.Fatalf("create %s: %v", u.Username, err)
		}
	}
	// Put one placeholder row through migration 5 so it only exists as
	// ciphertext, which is the state an already-upgraded worker node is in.
	if err := SetUserPassword(db, &encrypted, legacySyncPlaceholderPassword); err != nil {
		t.Fatalf("encrypt placeholder: %v", err)
	}
	if err := SetUserPassword(db, &real, "a-real-password"); err != nil {
		t.Fatalf("encrypt real password: %v", err)
	}

	if err := purgeSyncPlaceholderPasswords(db); err != nil {
		t.Fatalf("purgeSyncPlaceholderPasswords: %v", err)
	}

	for _, id := range []uint{plain.ID, encrypted.ID} {
		var got User
		if err := db.First(&got, id).Error; err != nil {
			t.Fatalf("read user %d: %v", id, err)
		}
		if got.Password != "" || got.PasswordCiphertext != "" {
			t.Errorf("user %d still holds a placeholder credential: %#v", id, got)
		}
		password, err := UserPassword(got)
		if err != nil || password != "" {
			t.Errorf("UserPassword(user %d) = %q, %v; want empty", id, password, err)
		}
	}

	var keptReal User
	if err := db.First(&keptReal, real.ID).Error; err != nil {
		t.Fatalf("read real user: %v", err)
	}
	if password, err := UserPassword(keptReal); err != nil || password != "a-real-password" {
		t.Errorf("real credential damaged: %q, %v", password, err)
	}
}

func TestRegisteredMigrationsNormalizeLegacyRules(t *testing.T) {
	db := openMigrationTestDB(t)
	if err := db.AutoMigrate(&Config{}); err != nil {
		t.Fatalf("create config table: %v", err)
	}
	if err := db.Create(&Config{Key: "clash_rules", Value: "  - DOMAIN-SUFFIX,google.com,PROXY\n  - MATCH,PROXY"}).Error; err != nil {
		t.Fatalf("seed legacy rules: %v", err)
	}
	if err := runMigrations(db, registeredMigrations()); err != nil {
		t.Fatalf("run registered migrations: %v", err)
	}
	var config Config
	if err := db.Where("key = ?", "clash_rules").First(&config).Error; err != nil {
		t.Fatalf("read migrated config: %v", err)
	}
	for _, want := range []string{"DOMAIN-SUFFIX,google.com,🌐 节点选择", "DOMAIN-SUFFIX,openai.com,🤖 AI 服务", "DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程", "MATCH,🐟 漏网之鱼"} {
		if !strings.Contains(config.Value, want) {
			t.Fatalf("migrated rules missing %q:\n%s", want, config.Value)
		}
	}
}

func TestVerifyLockOwnership(t *testing.T) {
	db := openMigrationTestDB(t)
	if err := db.AutoMigrate(&MigrationLock{}); err != nil {
		t.Fatalf("automigrate lock table: %v", err)
	}

	// Held lease with a valid token and future expiry passes.
	valid := MigrationLock{Name: migrationLockName, Token: "owner-token", ExpiresAt: time.Now().UTC().Add(migrationLockTTL)}
	if err := db.Create(&valid).Error; err != nil {
		t.Fatalf("seed valid lock: %v", err)
	}
	if err := verifyLockOwnership(db, "owner-token"); err != nil {
		t.Fatalf("valid lease should pass: %v", err)
	}

	// A different token means the lease was taken over.
	if err := verifyLockOwnership(db, "other-token"); err == nil || !strings.Contains(err.Error(), "taken over") {
		t.Fatalf("token mismatch should fail with takeover error, got: %v", err)
	}

	// An expired lease (even with the right token) must fail.
	if err := db.Model(&MigrationLock{}).Where("name = ?", migrationLockName).Update("expires_at", time.Now().UTC().Add(-time.Minute)).Error; err != nil {
		t.Fatalf("expire lock: %v", err)
	}
	if err := verifyLockOwnership(db, "owner-token"); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired lease should fail, got: %v", err)
	}

	// A missing lease row fails closed.
	if err := db.Delete(&MigrationLock{}, "name = ?", migrationLockName).Error; err != nil {
		t.Fatalf("delete lock: %v", err)
	}
	if err := verifyLockOwnership(db, "owner-token"); err == nil || !strings.Contains(err.Error(), "lease row missing") {
		t.Fatalf("missing lease should fail, got: %v", err)
	}
}
