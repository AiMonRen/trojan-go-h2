package database

import (
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"gorm.io/gorm"
)

const (
	migrationStatusStarted = "started"
	migrationStatusApplied = "applied"
	migrationStatusFailed  = "failed"
)

// SchemaMigration is the immutable record of a completed database change.
// A published migration's version, name, and checksum must never be modified.
type SchemaMigration struct {
	Version    uint64    `gorm:"primaryKey"`
	Name       string    `gorm:"not null;size:255"`
	Checksum   string    `gorm:"not null;size:64"`
	AppliedAt  time.Time `gorm:"not null"`
	DurationMS int64     `gorm:"not null"`
}

func (SchemaMigration) TableName() string {
	return "schema_migrations"
}

// MigrationAudit retains a successful or failed attempt. It is intentionally
// separate from SchemaMigration, which contains only committed migrations.
type MigrationAudit struct {
	ID           uint       `gorm:"primaryKey"`
	Version      uint64     `gorm:"index;not null"`
	Name         string     `gorm:"not null;size:255"`
	Checksum     string     `gorm:"not null;size:64"`
	Status       string     `gorm:"not null;size:16"`
	StartedAt    time.Time  `gorm:"not null"`
	FinishedAt   *time.Time `gorm:"index"`
	DurationMS   int64      `gorm:"not null"`
	ErrorMessage string     `gorm:"type:text"`
}

func (MigrationAudit) TableName() string {
	return "migration_audits"
}

// MigrationLock is a short-lived database lease. It serializes migration runs
// across compatibility runtimes while admin-service owns migrations in the
// standalone Gateway architecture.
type MigrationLock struct {
	Name      string    `gorm:"primaryKey;size:255"`
	Token     string    `gorm:"not null;size:64"`
	ExpiresAt time.Time `gorm:"index;not null"`
}

func (MigrationLock) TableName() string {
	return "migration_locks"
}

// Migration contains a forward-only, transactional data change. Destructive
// schema changes are deliberately excluded; they require Expand/Contract work
// and a separately tested backup and recovery procedure.
type Migration struct {
	Version  uint64
	Name     string
	Revision string
	Up       func(tx *gorm.DB) error
}

// checksum is based on an explicit immutable revision marker. When a published
// migration needs a correction, it must be replaced by a new version rather
// than changing this marker or its existing behavior.
func (m Migration) checksum() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", m.Version, m.Name, m.Revision)))
	return hex.EncodeToString(sum[:])
}

var migrationRunMu sync.Mutex

// RunMigrations applies the registered forward migrations in strict version
// order. The process-local mutex prevents duplicate execution by multiple
// callers in the same process; each migration is additionally protected by a
// database transaction and the unique migration version in every database.
func RunMigrations(db *gorm.DB) error {
	return runMigrations(db, registeredMigrations())
}

func runMigrations(db *gorm.DB, migrations []Migration) error {
	if db == nil {
		return errors.New("database is nil")
	}
	migrationRunMu.Lock()
	defer migrationRunMu.Unlock()

	if err := db.AutoMigrate(&SchemaMigration{}, &MigrationAudit{}, &MigrationLock{}); err != nil {
		return fmt.Errorf("create migration metadata tables: %w", err)
	}
	lockToken, err := acquireMigrationLock(db, time.Now().UTC())
	if err != nil {
		return err
	}
	defer releaseMigrationLock(db, lockToken)

	var previous uint64
	for _, migration := range migrations {
		if migration.Version == 0 || migration.Name == "" || migration.Revision == "" || migration.Up == nil {
			return fmt.Errorf("invalid migration definition: version=%d name=%q", migration.Version, migration.Name)
		}
		if previous >= migration.Version {
			return fmt.Errorf("migration versions must be strictly increasing: %d before %d", previous, migration.Version)
		}
		previous = migration.Version

		checksum := migration.checksum()
		var applied SchemaMigration
		err := db.First(&applied, "version = ?", migration.Version).Error
		if err == nil {
			if applied.Name != migration.Name || applied.Checksum != checksum {
				return fmt.Errorf("migration %03d checksum mismatch: published migrations must not change", migration.Version)
			}
			continue
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("read migration %03d: %w", migration.Version, err)
		}

		if err := runMigration(db, migration, checksum); err != nil {
			return err
		}
	}
	return nil
}

const migrationLockName = "schema_migrations"

func acquireMigrationLock(db *gorm.DB, now time.Time) (string, error) {
	var tokenBytes [16]byte
	if _, err := cryptorand.Read(tokenBytes[:]); err != nil {
		return "", fmt.Errorf("generate migration lock token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes[:])
	expiresAt := now.Add(30 * time.Second)
	lock := MigrationLock{Name: migrationLockName, Token: token, ExpiresAt: expiresAt}
	result := db.Model(&MigrationLock{}).Where("name = ? AND expires_at < ?", migrationLockName, now).Updates(map[string]any{"token": token, "expires_at": expiresAt})
	if result.Error != nil {
		return "", fmt.Errorf("refresh migration lock: %w", result.Error)
	}
	if result.RowsAffected == 1 {
		return token, nil
	}
	if err := db.Create(&lock).Error; err != nil {
		return "", fmt.Errorf("acquire migration lock: another process may be migrating: %w", err)
	}
	return token, nil
}

func releaseMigrationLock(db *gorm.DB, token string) {
	_ = db.Delete(&MigrationLock{}, "name = ? AND token = ?", migrationLockName, token).Error
}

func runMigration(db *gorm.DB, migration Migration, checksum string) error {
	startedAt := time.Now().UTC()
	audit := MigrationAudit{
		Version: migration.Version, Name: migration.Name, Checksum: checksum,
		Status: migrationStatusStarted, StartedAt: startedAt,
	}
	if err := db.Create(&audit).Error; err != nil {
		return fmt.Errorf("create audit for migration %03d: %w", migration.Version, err)
	}

	tx := db.Begin()
	if tx.Error != nil {
		return finishMigrationFailure(db, audit, startedAt, fmt.Errorf("begin transaction: %w", tx.Error))
	}
	if err := migration.Up(tx); err != nil {
		_ = tx.Rollback().Error
		return finishMigrationFailure(db, audit, startedAt, err)
	}

	completedAt := time.Now().UTC()
	if err := tx.Create(&SchemaMigration{
		Version: migration.Version, Name: migration.Name, Checksum: checksum,
		AppliedAt: completedAt, DurationMS: completedAt.Sub(startedAt).Milliseconds(),
	}).Error; err != nil {
		_ = tx.Rollback().Error
		return finishMigrationFailure(db, audit, startedAt, fmt.Errorf("record applied migration: %w", err))
	}
	if err := tx.Commit().Error; err != nil {
		return finishMigrationFailure(db, audit, startedAt, fmt.Errorf("commit migration: %w", err))
	}

	if err := db.Model(&MigrationAudit{}).Where("id = ?", audit.ID).Updates(map[string]any{
		"status": migrationStatusApplied, "finished_at": completedAt,
		"duration_ms": completedAt.Sub(startedAt).Milliseconds(),
	}).Error; err != nil {
		return fmt.Errorf("record successful migration %03d audit: %w", migration.Version, err)
	}
	return nil
}

func finishMigrationFailure(db *gorm.DB, audit MigrationAudit, startedAt time.Time, migrationErr error) error {
	finishedAt := time.Now().UTC()
	updateErr := db.Model(&MigrationAudit{}).Where("id = ?", audit.ID).Updates(map[string]any{
		"status": migrationStatusFailed, "finished_at": finishedAt,
		"duration_ms": finishedAt.Sub(startedAt).Milliseconds(), "error_message": migrationErr.Error(),
	}).Error
	if updateErr != nil {
		return fmt.Errorf("migration %03d failed: %v; record failure audit: %w", audit.Version, migrationErr, updateErr)
	}
	return fmt.Errorf("migration %03d %s failed: %w", audit.Version, audit.Name, migrationErr)
}

func registeredMigrations() []Migration {
	return []Migration{
		{Version: 1, Name: "normalize_legacy_clash_rule_groups", Revision: "2026-07-23", Up: normalizeLegacyClashRuleGroups},
		{Version: 2, Name: "add_ai_routing_rules", Revision: "2026-07-23", Up: addAIRoutingRules},
		{Version: 3, Name: "fix_legacy_lancidr_indentation", Revision: "2026-07-23", Up: fixLegacyLANCIDRIndentation},
		{Version: 4, Name: "remove_unused_rule_providers", Revision: "2026-07-23", Up: removeUnusedRuleProviders},
		{Version: 5, Name: "encrypt_recoverable_credentials", Revision: "2026-07-23", Up: encryptRecoverableCredentials},
	}
}

func readConfigValue(tx *gorm.DB, key string) (Config, bool, error) {
	var config Config
	err := tx.Where("key = ?", key).First(&config).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Config{}, false, nil
	}
	return config, err == nil, err
}

func updateConfigValue(tx *gorm.DB, config Config, value string) error {
	if value == config.Value {
		return nil
	}
	return tx.Model(&Config{}).Where("key = ?", config.Key).Update("value", value).Error
}

func normalizeLegacyClashRuleGroups(tx *gorm.DB) error {
	config, found, err := readConfigValue(tx, "clash_rules")
	if err != nil || !found {
		return err
	}
	return updateConfigValue(tx, config, normalizeLegacyClashRuleValue(config.Value))
}

func normalizeLegacyClashRuleValue(value string) string {
	value = strings.ReplaceAll(value, "MATCH,Trojan", "MATCH,🐟 漏网之鱼")
	value = strings.ReplaceAll(value, ",PROXY", ",🌐 节点选择")
	value = strings.ReplaceAll(value, "MATCH,🌐 节点选择", "MATCH,🐟 漏网之鱼")
	return strings.ReplaceAll(value, "RULE-SET,google,DIRECT", "RULE-SET,google,🌐 节点选择")
}

func addAIRoutingRules(tx *gorm.DB) error {
	config, found, err := readConfigValue(tx, "clash_rules")
	if err != nil || !found {
		return err
	}
	value := config.Value
	if !strings.Contains(value, "🤖 AI 服务") {
		const aiRules = `  - DOMAIN-SUFFIX,openai.com,🤖 AI 服务
  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 服务
  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 服务
  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 服务
  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务
  - DOMAIN-SUFFIX,claude.ai,🤖 AI 服务
  - DOMAIN,generativelanguage.googleapis.com,🤖 AI 服务
  - DOMAIN,aistudio.google.com,🤖 AI 服务
  - DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程
  - DOMAIN-SUFFIX,cursor.com,💻 AI 编程
  - DOMAIN-SUFFIX,windsurf.com,💻 AI 编程
`
		if strings.Contains(value, "  - MATCH,🐟 漏网之鱼") {
			value = strings.Replace(value, "  - MATCH,🐟 漏网之鱼", aiRules+"  - MATCH,🐟 漏网之鱼", 1)
		} else if strings.Contains(value, "- MATCH,🐟 漏网之鱼") {
			value = strings.Replace(value, "- MATCH,🐟 漏网之鱼", aiRules+"- MATCH,🐟 漏网之鱼", 1)
		} else {
			value = strings.TrimRight(value, "\n") + "\n" + aiRules + "  - MATCH,🐟 漏网之鱼"
		}
	}
	return updateConfigValue(tx, config, prioritizeAIRules(value))
}

func fixLegacyLANCIDRIndentation(tx *gorm.DB) error {
	config, found, err := readConfigValue(tx, "clash_rules")
	if err != nil || !found || !strings.Contains(config.Value, "    - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve") {
		return err
	}
	value := strings.ReplaceAll(config.Value, "    - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
	return updateConfigValue(tx, config, value)
}

func removeUnusedRuleProviders(tx *gorm.DB) error {
	config, found, err := readConfigValue(tx, "clash_rule_providers")
	if err != nil || !found {
		return err
	}
	value := config.Value
	for _, provider := range []string{"gfw", "greatfire", "tld-not-cn", "lancidr"} {
		value = removeRuleProvider(value, provider)
	}
	return updateConfigValue(tx, config, value)
}

// encryptRecoverableCredentials upgrades legacy plaintext fields while keeping
// their columns present for a separately confirmed future cleanup migration.
func encryptRecoverableCredentials(tx *gorm.DB) error {
	// Migration unit tests may exercise the Config-only historical rules without
	// creating all current application tables. A real InitDb path has already
	// AutoMigrated these schemas before this data migration runs.
	if tx.Migrator().HasTable(&User{}) {
		var users []User
		if err := tx.Where("password <> '' AND (password_ciphertext = '' OR password_ciphertext IS NULL)").Find(&users).Error; err != nil {
			return err
		}
		for i := range users {
			if err := SetUserPassword(tx, &users[i], users[i].Password); err != nil {
				return fmt.Errorf("encrypt user %d password: %w", users[i].ID, err)
			}
		}
	}

	if tx.Migrator().HasTable(&Node{}) {
		var nodes []Node
		if err := tx.Where("secret <> '' AND (secret_ciphertext = '' OR secret_ciphertext IS NULL)").Find(&nodes).Error; err != nil {
			return err
		}
		for i := range nodes {
			if err := SetNodeSecret(tx, &nodes[i], nodes[i].Secret); err != nil {
				return fmt.Errorf("encrypt node %d secret: %w", nodes[i].ID, err)
			}
		}
	}
	return nil
}

func removeRuleProvider(value, provider string) string {
	prefixes := []string{"\n\n  ", "  "}
	for _, prefix := range prefixes {
		block := prefix + provider + ":\n    type: http\n"
		start := strings.Index(value, block)
		if start == -1 {
			continue
		}
		end := strings.Index(value[start+len(block):], "\n\n  ")
		if end == -1 {
			return strings.TrimRight(value[:start], "\n")
		}
		end += start + len(block)
		return value[:start] + value[end:]
	}
	return value
}
