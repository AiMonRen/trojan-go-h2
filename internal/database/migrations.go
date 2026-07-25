package database

import (
	"context"
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

	// migrationLockTTL is how long a freshly acquired or renewed lease is valid.
	migrationLockTTL = 5 * time.Minute
	// migrationLockRenewInterval is how often the background loop renews the
	// lease; it must be comfortably shorter than migrationLockTTL.
	migrationLockRenewInterval = 2 * time.Minute
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

	// Start a background goroutine that periodically renews the lock.
	// This prevents lock expiry during migrations that take longer than
	// the fixed TTL (e.g. encrypting large credential tables).
	//
	// renewalCtx stops the renewal loop when we return. migCtx is bound to the
	// migration transactions themselves: if renewal fails, the loop cancels
	// migCtx so any in-flight migration aborts before committing under a lease
	// it no longer holds.
	renewalCtx, cancelRenewal := context.WithCancel(context.Background())
	defer cancelRenewal()
	migCtx, cancelMigration := context.WithCancel(context.Background())
	defer cancelMigration()
	renewalErrCh := make(chan error, 1)
	go renewLockLoop(db, lockToken, renewalCtx, renewalErrCh, cancelMigration)

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

		// Abort early if the lease was already lost before starting the next
		// migration, so we never open a transaction we cannot safely commit.
		select {
		case renewalErr := <-renewalErrCh:
			return fmt.Errorf("migration lock lost before migration %03d: %w", migration.Version, renewalErr)
		default:
		}

		if err := runMigration(migCtx, db, lockToken, migration, checksum); err != nil {
			return err
		}

		// Verify the lock is still held after each migration.
		select {
		case renewalErr := <-renewalErrCh:
			return fmt.Errorf("migration lock lost after migration %03d: %w", migration.Version, renewalErr)
		default:
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
	expiresAt := now.Add(5 * time.Minute)
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

// renewMigrationLock extends the expiration of an existing migration lock
// by the given duration. It returns an error if the token no longer holds
// the lock, indicating the migration must abort.
func renewMigrationLock(db *gorm.DB, token string, extension time.Duration) error {
	result := db.Model(&MigrationLock{}).Where("name = ? AND token = ?", migrationLockName, token).Update("expires_at", time.Now().Add(extension))
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return errors.New("migration lock was lost: another process may have taken over")
	}
	return nil
}

func releaseMigrationLock(db *gorm.DB, token string) {
	_ = db.Delete(&MigrationLock{}, "name = ? AND token = ?", migrationLockName, token).Error
}

// verifyLockOwnership confirms, inside the migration transaction, that the
// lease row still belongs to token and has not expired. Running it on tx means
// the check and the schema write are committed atomically, so we can never
// commit a migration under a lease that was lost or taken over.
func verifyLockOwnership(tx *gorm.DB, token string) error {
	var lock MigrationLock
	err := tx.First(&lock, "name = ?", migrationLockName).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return errors.New("migration lock was lost before commit: lease row missing")
	}
	if err != nil {
		return fmt.Errorf("verify migration lock ownership: %w", err)
	}
	if lock.Token != token {
		return errors.New("migration lock was taken over before commit: token mismatch")
	}
	if !lock.ExpiresAt.After(time.Now().UTC()) {
		return errors.New("migration lock expired before commit")
	}
	return nil
}

// renewLockLoop periodically extends the migration lock's expiration while
// migrations are running. It stops when the parent context is cancelled and
// sends any renewal error to errCh (exactly once) so the caller can abort
// the migration sequence. On renewal failure it also calls cancelMigration so
// that an in-flight migration transaction bound to that context is aborted
// immediately instead of continuing to write schema under a lost lease.
func renewLockLoop(db *gorm.DB, token string, ctx context.Context, errCh chan<- error, cancelMigration context.CancelFunc) {
	ticker := time.NewTicker(migrationLockRenewInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := renewMigrationLock(db, token, migrationLockTTL); err != nil {
				select {
				case errCh <- err:
				default:
				}
				// Abort any in-flight migration bound to migCtx so it stops
				// before committing under a lease we no longer hold.
				cancelMigration()
				return
			}
		}
	}
}

func runMigration(ctx context.Context, db *gorm.DB, lockToken string, migration Migration, checksum string) error {
	startedAt := time.Now().UTC()
	audit := MigrationAudit{
		Version: migration.Version, Name: migration.Name, Checksum: checksum,
		Status: migrationStatusStarted, StartedAt: startedAt,
	}
	if err := db.Create(&audit).Error; err != nil {
		return fmt.Errorf("create audit for migration %03d: %w", migration.Version, err)
	}

	// Bind the transaction to ctx so a lost lease (which cancels ctx via the
	// renewal loop) aborts the in-flight work instead of committing blindly.
	tx := db.WithContext(ctx).Begin()
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

	// Final ownership check inside the transaction, immediately before commit.
	// This closes the race where the lease expired and was taken over by another
	// process between the last renewal and this commit: if we no longer own the
	// lock we roll back rather than write schema under a stolen lease.
	if err := ctx.Err(); err != nil {
		_ = tx.Rollback().Error
		return finishMigrationFailure(db, audit, startedAt, fmt.Errorf("migration context cancelled before commit: %w", err))
	}
	if err := verifyLockOwnership(tx, lockToken); err != nil {
		_ = tx.Rollback().Error
		return finishMigrationFailure(db, audit, startedAt, err)
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
		{Version: 6, Name: "purge_sync_placeholder_passwords", Revision: "2026-07-25", Up: purgeSyncPlaceholderPasswords},
	}
}

// legacySyncPlaceholderPassword is the literal that worker nodes used to write
// into the local user cache before S-08 was fixed.
const legacySyncPlaceholderPassword = "placeholder-pwd"

// purgeSyncPlaceholderPasswords clears the placeholder credential that worker
// nodes previously cached for synced users.
//
// S-08: the worker only ever receives the authentication hash from the master,
// so its cached rows never held a usable password. Writing the fixed literal
// "placeholder-pwd" meant migration 5 then encrypted that literal into
// password_ciphertext, so UserPassword() would happily return it and any code
// path generating a client config could emit a config that cannot authenticate.
// Both the plaintext column and the ciphertext derived from it are cleared so
// UserPassword() returns an empty string, which every caller already treats as
// "credential unavailable".
func purgeSyncPlaceholderPasswords(tx *gorm.DB) error {
	if !tx.Migrator().HasTable(&User{}) {
		return nil
	}
	var users []User
	if err := tx.Where("password = ?", legacySyncPlaceholderPassword).Find(&users).Error; err != nil {
		return err
	}
	// Rows already migrated by version 5 have an empty plaintext column, so the
	// ciphertext has to be decrypted to recognise them.
	var encrypted []User
	if err := tx.Where("password = '' AND password_ciphertext <> '' AND password_ciphertext IS NOT NULL").Find(&encrypted).Error; err != nil {
		return err
	}
	for i := range encrypted {
		plaintext, err := UserPassword(encrypted[i])
		if err != nil {
			// An undecryptable row is not this migration's problem; leave it for
			// the credential-key tooling to report.
			continue
		}
		if plaintext == legacySyncPlaceholderPassword {
			users = append(users, encrypted[i])
		}
	}
	for i := range users {
		if err := tx.Model(&User{}).Where("id = ?", users[i].ID).Updates(map[string]any{
			"password":            "",
			"password_ciphertext": "",
		}).Error; err != nil {
			return fmt.Errorf("clear placeholder credential for user %d: %w", users[i].ID, err)
		}
	}
	return nil
}

func readConfigValue(tx *gorm.DB, key string) (Config, bool, error) {
	var config Config
	err := tx.Where("`key` = ?", key).First(&config).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return Config{}, false, nil
	}
	return config, err == nil, err
}

func updateConfigValue(tx *gorm.DB, config Config, value string) error {
	if value == config.Value {
		return nil
	}
	return tx.Model(&Config{}).Where("`key` = ?", config.Key).Update("value", value).Error
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
