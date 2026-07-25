package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

const (
	defaultUpgradeStateDir = "/var/lib/trojan-go/upgrades"
	defaultUpgradeAuditLog = "/var/log/trojan-go/upgrade-audit.jsonl"
)

var serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]+$`)

type upgradeManifest struct {
	Version       string               `json:"version"`
	Artifacts     []upgradeArtifact    `json:"artifacts"`
	Services      []string             `json:"services"`
	ConfigChecks  []upgradeConfigCheck `json:"config_checks,omitempty"`
	HealthChecks  []upgradeHealthCheck `json:"health_checks,omitempty"`
	StateDir      string               `json:"state_dir,omitempty"`
	AuditLog      string               `json:"audit_log,omitempty"`
	HealthTimeout int                  `json:"health_timeout_seconds,omitempty"`
}

type upgradeArtifact struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	SHA256     string   `json:"sha256"`
	Mode       string   `json:"mode"`
	VerifyArgs []string `json:"verify_args,omitempty"`
}

type upgradeConfigCheck struct {
	BinaryTarget string `json:"binary_target"`
	Service      string `json:"service"`
	ConfigTarget string `json:"config_target"`
}

type upgradeHealthCheck struct {
	Name           string `json:"name"`
	Type           string `json:"type"`
	Target         string `json:"target"`
	Path           string `json:"path,omitempty"`
	ExpectedStatus int    `json:"expected_status,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type upgradeBackup struct {
	Target     string `json:"target"`
	BackupPath string `json:"backup_path,omitempty"`
	Existed    bool   `json:"existed"`
	Mode       uint32 `json:"mode,omitempty"`
}

type upgradeJournal struct {
	ID             string               `json:"id"`
	Version        string               `json:"version"`
	Phase          string               `json:"phase"`
	StartedAt      time.Time            `json:"started_at"`
	Transaction    string               `json:"transaction_dir"`
	Artifacts      []upgradeArtifact    `json:"artifacts"`
	ArtifactHashes map[string]string    `json:"artifact_hashes,omitempty"`
	Backups        []upgradeBackup      `json:"backups"`
	Services       []string             `json:"services"`
	HealthChecks   []upgradeHealthCheck `json:"health_checks,omitempty"`
	HealthTimeout  int                  `json:"health_timeout_seconds,omitempty"`
	AuditLog       string               `json:"audit_log"`
}

type upgradeAuditRecord struct {
	ID        string            `json:"id"`
	Version   string            `json:"version"`
	Status    string            `json:"status"`
	StartedAt time.Time         `json:"started_at"`
	EndedAt   time.Time         `json:"ended_at"`
	Artifacts map[string]string `json:"artifacts"`
	Error     string            `json:"error,omitempty"`
}

type upgradeHost interface {
	RunBinary(context.Context, string, ...string) error
	DaemonReload(context.Context) error
	Restart(context.Context, string) error
	IsActive(context.Context, string) error
	Health(context.Context, upgradeHealthCheck) error
}

type systemUpgradeHost struct{}

func (systemUpgradeHost) RunBinary(ctx context.Context, path string, args ...string) error {
	output, err := exec.CommandContext(ctx, path, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("run %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (systemUpgradeHost) DaemonReload(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "systemctl", "daemon-reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl daemon-reload: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (systemUpgradeHost) Restart(ctx context.Context, service string) error {
	output, err := exec.CommandContext(ctx, "systemctl", "restart", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("restart %s: %w: %s", service, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (systemUpgradeHost) IsActive(ctx context.Context, service string) error {
	output, err := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("service %s is not active: %w: %s", service, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (systemUpgradeHost) Health(ctx context.Context, check upgradeHealthCheck) error {
	timeout := time.Duration(check.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	checkCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch check.Type {
	case "tcp":
		if err := validateLoopbackAddress(check.Target); err != nil {
			return err
		}
		dialer := net.Dialer{}
		connection, err := dialer.DialContext(checkCtx, "tcp", check.Target)
		if err != nil {
			return fmt.Errorf("TCP health check %s: %w", check.Name, err)
		}
		return connection.Close()
	case "http", "https":
		if err := validateLoopbackAddress(check.Target); err != nil {
			return err
		}
		path := check.Path
		if path == "" {
			path = "/"
		}
		endpoint := (&url.URL{Scheme: check.Type, Host: check.Target, Path: path}).String()
		request, err := http.NewRequestWithContext(checkCtx, http.MethodGet, endpoint, nil)
		if err != nil {
			return fmt.Errorf("build HTTP health check %s: %w", check.Name, err)
		}
		client := &http.Client{Timeout: timeout}
		response, err := client.Do(request)
		if err != nil {
			return fmt.Errorf("HTTP health check %s: %w", check.Name, err)
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		expected := check.ExpectedStatus
		if expected == 0 {
			expected = http.StatusOK
		}
		if response.StatusCode != expected {
			return fmt.Errorf("HTTP health check %s returned %d, expected %d", check.Name, response.StatusCode, expected)
		}
		return nil
	default:
		return fmt.Errorf("unsupported health check type %q", check.Type)
	}
}

func validateLoopbackAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid health check target %q: %w", address, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("health check target %q must use a loopback IP", address)
	}
	return nil
}

func AtomicUpgrade() {
	if os.Geteuid() != 0 {
		fmt.Println("错误：原子升级需要 sudo 权限！")
		return
	}
	manifestPath := getStdin("请输入升级清单 JSON 路径: ", "Enter upgrade manifest JSON path: ")
	if manifestPath == "" {
		fmt.Println("升级清单路径不能为空")
		return
	}
	if err := UpgradeFromManifest(manifestPath); err != nil {
		fmt.Printf("\033[31m❌ 原子升级失败: %v\033[0m\n", err)
		return
	}
	fmt.Println("\033[32m✓ 原子升级、健康检查及审计记录已完成\033[0m")
}

func UpgradeFromManifest(manifestPath string) error {
	return executeUpgrade(manifestPath, systemUpgradeHost{}, time.Now)
}

func executeUpgrade(manifestPath string, host upgradeHost, now func() time.Time) error {
	manifest, manifestDir, err := loadUpgradeManifest(manifestPath)
	if err != nil {
		return err
	}
	if manifest.StateDir == "" {
		manifest.StateDir = defaultUpgradeStateDir
	}
	if manifest.AuditLog == "" {
		manifest.AuditLog = defaultUpgradeAuditLog
	}
	if err := os.MkdirAll(manifest.StateDir, 0o700); err != nil {
		return fmt.Errorf("create upgrade state directory: %w", err)
	}
	lock, err := acquireUpgradeLock(filepath.Join(manifest.StateDir, "upgrade.lock"))
	if err != nil {
		return err
	}
	defer lock()

	activeJournal := filepath.Join(manifest.StateDir, "active.json")
	if err := recoverInterruptedUpgrade(activeJournal, host, now); err != nil {
		return fmt.Errorf("recover interrupted upgrade: %w", err)
	}

	startedAt := now().UTC()
	transactionID := fmt.Sprintf("%d-%d", startedAt.UnixNano(), os.Getpid())
	transactionDir := filepath.Join(manifest.StateDir, transactionID)
	if err := os.Mkdir(transactionDir, 0o700); err != nil {
		return fmt.Errorf("create upgrade transaction directory: %w", err)
	}
	journal := upgradeJournal{
		ID: transactionID, Version: manifest.Version, Phase: "preparing", StartedAt: startedAt,
		Transaction: transactionDir, Artifacts: manifest.Artifacts, Services: manifest.Services,
		HealthChecks: manifest.HealthChecks, HealthTimeout: manifest.HealthTimeout, AuditLog: manifest.AuditLog,
	}

	staged, hashes, err := stageUpgradeArtifacts(transactionDir, manifestDir, manifest.Artifacts, host)
	if err == nil {
		err = runUpgradeConfigChecks(manifest, staged, host)
	}
	if err != nil {
		_ = appendUpgradeAudit(manifest.AuditLog, upgradeAuditRecord{ID: transactionID, Version: manifest.Version, Status: "rejected", StartedAt: startedAt, EndedAt: now().UTC(), Error: err.Error()})
		return err
	}
	journal.ArtifactHashes = hashes
	journal.Backups, err = backupUpgradeTargets(transactionDir, manifest.Artifacts)
	if err != nil {
		_ = appendUpgradeAudit(manifest.AuditLog, upgradeAuditRecord{ID: transactionID, Version: manifest.Version, Status: "rejected", StartedAt: startedAt, EndedAt: now().UTC(), Artifacts: hashes, Error: err.Error()})
		return err
	}
	journal.Phase = "prepared"
	if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
		return fmt.Errorf("persist prepared upgrade journal: %w", err)
	}

	applyErr := applyUpgrade(staged, manifest.Artifacts)
	if applyErr == nil {
		journal.Phase = "switched"
		applyErr = writeJSONAtomic(activeJournal, journal, 0o600)
	}
	if applyErr == nil {
		applyErr = restartAndCheck(manifest, host)
	}
	if applyErr == nil {
		journal.Phase = "healthy"
		if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
			applyErr = fmt.Errorf("persist healthy upgrade journal: %w", err)
		}
	}
	if applyErr == nil {
		if err := appendUpgradeAudit(manifest.AuditLog, upgradeAuditRecord{ID: transactionID, Version: manifest.Version, Status: "committed", StartedAt: startedAt, EndedAt: now().UTC(), Artifacts: hashes}); err != nil {
			return fmt.Errorf("upgrade is healthy but audit commit failed; active journal retained: %w", err)
		}
		journal.Phase = "committed"
		if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
			return fmt.Errorf("persist committed upgrade journal: %w", err)
		}
		if err := removeAndSync(activeJournal); err != nil {
			return fmt.Errorf("clear committed upgrade journal: %w", err)
		}
		return nil
	}

	rollbackErr := rollbackUpgrade(journal, host)
	status := "rolled_back"
	if rollbackErr != nil {
		status = "rollback_failed"
	}
	auditErr := appendUpgradeAudit(manifest.AuditLog, upgradeAuditRecord{ID: transactionID, Version: manifest.Version, Status: status, StartedAt: startedAt, EndedAt: now().UTC(), Artifacts: hashes, Error: applyErr.Error()})
	if rollbackErr == nil {
		if err := removeAndSync(activeJournal); err != nil {
			rollbackErr = fmt.Errorf("clear rolled-back upgrade journal: %w", err)
		}
	}
	if rollbackErr != nil {
		return errors.Join(fmt.Errorf("upgrade failed: %w", applyErr), fmt.Errorf("rollback failed: %w", rollbackErr), auditErr)
	}
	return errors.Join(fmt.Errorf("upgrade failed and was rolled back: %w", applyErr), auditErr)
}

func loadUpgradeManifest(path string) (upgradeManifest, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return upgradeManifest{}, "", fmt.Errorf("resolve upgrade manifest path: %w", err)
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return upgradeManifest{}, "", fmt.Errorf("read upgrade manifest: %w", err)
	}
	var manifest upgradeManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return upgradeManifest{}, "", fmt.Errorf("decode upgrade manifest: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return upgradeManifest{}, "", errors.New("upgrade manifest must contain exactly one JSON object")
	}
	if err := validateUpgradeManifest(&manifest); err != nil {
		return upgradeManifest{}, "", err
	}
	return manifest, filepath.Dir(absolute), nil
}

func validateUpgradeManifest(manifest *upgradeManifest) error {
	manifest.Version = strings.TrimSpace(manifest.Version)
	if manifest.Version == "" {
		return errors.New("upgrade manifest version is required")
	}
	if len(manifest.Artifacts) == 0 {
		return errors.New("upgrade manifest must contain artifacts")
	}
	seenTargets := make(map[string]struct{}, len(manifest.Artifacts))
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		artifact.SHA256 = strings.ToLower(strings.TrimSpace(artifact.SHA256))
		if artifact.Source == "" || artifact.Target == "" {
			return fmt.Errorf("artifact %d requires source and target", i)
		}
		if !filepath.IsAbs(artifact.Target) || filepath.Clean(artifact.Target) == string(filepath.Separator) {
			return fmt.Errorf("artifact %d target must be an absolute non-root path", i)
		}
		artifact.Target = filepath.Clean(artifact.Target)
		if _, exists := seenTargets[artifact.Target]; exists {
			return fmt.Errorf("duplicate artifact target %s", artifact.Target)
		}
		seenTargets[artifact.Target] = struct{}{}
		decoded, err := hex.DecodeString(artifact.SHA256)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("artifact %d has invalid SHA-256", i)
		}
		if _, err := parseFileMode(artifact.Mode); err != nil {
			return fmt.Errorf("artifact %d: %w", i, err)
		}
	}
	for i := range manifest.ConfigChecks {
		check := &manifest.ConfigChecks[i]
		if check.BinaryTarget == "" || check.ConfigTarget == "" || check.Service == "" {
			return errors.New("each config check requires binary_target, service and config_target")
		}
		check.BinaryTarget = filepath.Clean(check.BinaryTarget)
		check.ConfigTarget = filepath.Clean(check.ConfigTarget)
		if _, exists := seenTargets[check.BinaryTarget]; !exists {
			return fmt.Errorf("config check binary_target %s is not an artifact target", check.BinaryTarget)
		}
		if _, exists := seenTargets[check.ConfigTarget]; !exists {
			return fmt.Errorf("config check config_target %s is not an artifact target", check.ConfigTarget)
		}
		switch check.Service {
		case "gateway", "admin", "worker-control", "data-plane":
		default:
			return fmt.Errorf("unsupported config check service %q", check.Service)
		}
	}
	if len(manifest.Services) == 0 {
		return errors.New("upgrade manifest must contain services")
	}
	seenServices := make(map[string]struct{}, len(manifest.Services))
	for _, service := range manifest.Services {
		if !serviceNamePattern.MatchString(service) {
			return fmt.Errorf("invalid systemd service name %q", service)
		}
		if _, exists := seenServices[service]; exists {
			return fmt.Errorf("duplicate systemd service %q", service)
		}
		seenServices[service] = struct{}{}
	}
	for _, check := range manifest.HealthChecks {
		if check.Name == "" {
			return errors.New("health check name is required")
		}
		if check.Type != "tcp" && check.Type != "http" && check.Type != "https" {
			return fmt.Errorf("unsupported health check type %q", check.Type)
		}
		if err := validateLoopbackAddress(check.Target); err != nil {
			return err
		}
	}
	if manifest.HealthTimeout <= 0 {
		manifest.HealthTimeout = 30
	}
	if manifest.HealthTimeout > 300 {
		return errors.New("health_timeout_seconds must not exceed 300")
	}
	return nil
}

func parseFileMode(value string) (os.FileMode, error) {
	if len(value) != 4 || value[0] != '0' {
		return 0, fmt.Errorf("mode %q must use four-digit octal form such as 0600", value)
	}
	parsed, err := strconv.ParseUint(value, 8, 32)
	if err != nil || parsed > 0o777 {
		return 0, fmt.Errorf("invalid file mode %q", value)
	}
	return os.FileMode(parsed), nil
}

func stageUpgradeArtifacts(transactionDir, manifestDir string, artifacts []upgradeArtifact, host upgradeHost) ([]string, map[string]string, error) {
	stagingDir := filepath.Join(transactionDir, "staging")
	if err := os.Mkdir(stagingDir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("create staging directory: %w", err)
	}
	staged := make([]string, len(artifacts))
	hashes := make(map[string]string, len(artifacts))
	for i, artifact := range artifacts {
		source := artifact.Source
		if !filepath.IsAbs(source) {
			source = filepath.Join(manifestDir, source)
		}
		info, err := os.Lstat(source)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect artifact source %s: %w", source, err)
		}
		if !info.Mode().IsRegular() {
			return nil, nil, fmt.Errorf("artifact source %s must be a regular file", source)
		}
		mode, _ := parseFileMode(artifact.Mode)
		staged[i] = filepath.Join(stagingDir, fmt.Sprintf("%03d", i))
		if err := copyFileSync(source, staged[i], mode); err != nil {
			return nil, nil, fmt.Errorf("stage artifact %s: %w", source, err)
		}
		digest, err := fileSHA256(staged[i])
		if err != nil {
			return nil, nil, err
		}
		if digest != artifact.SHA256 {
			return nil, nil, fmt.Errorf("artifact %s SHA-256 mismatch: got %s, expected %s", source, digest, artifact.SHA256)
		}
		hashes[artifact.Target] = digest
		if err := validateStagedConfig(staged[i], artifact.Target); err != nil {
			return nil, nil, err
		}
		verifyArgs := artifact.VerifyArgs
		if len(verifyArgs) == 0 && filepath.Base(artifact.Target) == "trojan-go" {
			verifyArgs = []string{"-version"}
		}
		if len(verifyArgs) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			err := host.RunBinary(ctx, staged[i], verifyArgs...)
			cancel()
			if err != nil {
				return nil, nil, fmt.Errorf("artifact self-check %s: %w", artifact.Target, err)
			}
		}
	}
	if err := syncDirectoryPath(stagingDir); err != nil {
		return nil, nil, fmt.Errorf("sync staging directory: %w", err)
	}
	return staged, hashes, nil
}

func runUpgradeConfigChecks(manifest upgradeManifest, staged []string, host upgradeHost) error {
	if len(manifest.ConfigChecks) == 0 {
		return nil
	}
	stagedByTarget := make(map[string]string, len(manifest.Artifacts))
	for i, artifact := range manifest.Artifacts {
		stagedByTarget[artifact.Target] = staged[i]
	}
	for _, check := range manifest.ConfigChecks {
		binaryPath := stagedByTarget[filepath.Clean(check.BinaryTarget)]
		configPath := stagedByTarget[filepath.Clean(check.ConfigTarget)]
		args := []string{"config-check", "--service", check.Service, "--config", configPath}
		if check.Service == "gateway" {
			for i, artifact := range manifest.Artifacts {
				if artifact.Target == check.BinaryTarget || artifact.Target == check.ConfigTarget {
					continue
				}
				args = append(args, "--path-override", artifact.Target, staged[i])
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		err := host.RunBinary(ctx, binaryPath, args...)
		cancel()
		if err != nil {
			return fmt.Errorf("%s config self-check: %w", check.Service, err)
		}
	}
	return nil
}

func validateStagedConfig(path, target string) error {
	extension := strings.ToLower(filepath.Ext(target))
	if extension != ".yaml" && extension != ".yml" && extension != ".json" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read staged config %s: %w", target, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return fmt.Errorf("staged config %s is empty", target)
	}
	var decoded any
	if extension == ".json" {
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("validate staged JSON %s: %w", target, err)
		}
	} else if err := yaml.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("validate staged YAML %s: %w", target, err)
	}
	return nil
}

func backupUpgradeTargets(transactionDir string, artifacts []upgradeArtifact) ([]upgradeBackup, error) {
	backupDir := filepath.Join(transactionDir, "backup")
	if err := os.Mkdir(backupDir, 0o700); err != nil {
		return nil, fmt.Errorf("create backup directory: %w", err)
	}
	backups := make([]upgradeBackup, len(artifacts))
	for i, artifact := range artifacts {
		info, err := os.Lstat(artifact.Target)
		if errors.Is(err, os.ErrNotExist) {
			backups[i] = upgradeBackup{Target: artifact.Target}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect upgrade target %s: %w", artifact.Target, err)
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("upgrade target %s must be a regular file, refusing to replace %s", artifact.Target, info.Mode().Type())
		}
		backupPath := filepath.Join(backupDir, fmt.Sprintf("%03d", i))
		if err := copyFileSync(artifact.Target, backupPath, info.Mode().Perm()); err != nil {
			return nil, fmt.Errorf("backup %s: %w", artifact.Target, err)
		}
		backups[i] = upgradeBackup{Target: artifact.Target, BackupPath: backupPath, Existed: true, Mode: uint32(info.Mode().Perm())}
	}
	if err := syncDirectoryPath(backupDir); err != nil {
		return nil, fmt.Errorf("sync backup directory: %w", err)
	}
	return backups, nil
}

func applyUpgrade(staged []string, artifacts []upgradeArtifact) error {
	for i, artifact := range artifacts {
		mode, _ := parseFileMode(artifact.Mode)
		if err := atomicInstallFile(staged[i], artifact.Target, mode); err != nil {
			return fmt.Errorf("switch artifact %s: %w", artifact.Target, err)
		}
	}
	return nil
}

func atomicInstallFile(source, target string, mode os.FileMode) error {
	directory := filepath.Dir(target)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create target directory %s: %w", directory, err)
	}
	temporary, err := os.CreateTemp(directory, ".trojan-upgrade-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	sourceFile, err := os.Open(source)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(temporary, sourceFile)
	closeSourceErr := sourceFile.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeSourceErr != nil {
		return closeSourceErr
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, target); err != nil {
		return err
	}
	committed = true
	return syncDirectoryPath(directory)
}

func restartAndCheck(manifest upgradeManifest, host upgradeHost) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(manifest.HealthTimeout)*time.Second)
	defer cancel()
	if err := host.DaemonReload(ctx); err != nil {
		return err
	}
	for _, service := range manifest.Services {
		if err := host.Restart(ctx, service); err != nil {
			return err
		}
	}
	return checkUpgradeHealth(ctx, manifest.Services, manifest.HealthChecks, host)
}

func checkUpgradeHealth(ctx context.Context, services []string, checks []upgradeHealthCheck, host upgradeHost) error {
	for {
		var failures []error
		for _, service := range services {
			if err := host.IsActive(ctx, service); err != nil {
				failures = append(failures, err)
			}
		}
		for _, check := range checks {
			if err := host.Health(ctx, check); err != nil {
				failures = append(failures, err)
			}
		}
		if len(failures) == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(append([]error{fmt.Errorf("health check deadline exceeded: %w", ctx.Err())}, failures...)...)
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func rollbackUpgrade(journal upgradeJournal, host upgradeHost) error {
	var restoreErrors []error
	for i := len(journal.Backups) - 1; i >= 0; i-- {
		backup := journal.Backups[i]
		if backup.Existed {
			if err := atomicInstallFile(backup.BackupPath, backup.Target, os.FileMode(backup.Mode)); err != nil {
				restoreErrors = append(restoreErrors, fmt.Errorf("restore %s: %w", backup.Target, err))
			}
		} else if err := os.Remove(backup.Target); err != nil && !errors.Is(err, os.ErrNotExist) {
			restoreErrors = append(restoreErrors, fmt.Errorf("remove new target %s: %w", backup.Target, err))
		} else if err == nil {
			if syncErr := syncDirectoryPath(filepath.Dir(backup.Target)); syncErr != nil {
				restoreErrors = append(restoreErrors, syncErr)
			}
		}
	}
	if len(restoreErrors) > 0 {
		return errors.Join(restoreErrors...)
	}
	timeout := journal.HealthTimeout
	if timeout <= 0 {
		timeout = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()
	if err := host.DaemonReload(ctx); err != nil {
		return err
	}
	for _, service := range journal.Services {
		if err := host.Restart(ctx, service); err != nil {
			return err
		}
	}
	return checkUpgradeHealth(ctx, journal.Services, journal.HealthChecks, host)
}

func recoverInterruptedUpgrade(activeJournal string, host upgradeHost, now func() time.Time) error {
	data, err := os.ReadFile(activeJournal)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var journal upgradeJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return fmt.Errorf("decode active upgrade journal: %w", err)
	}
	if journal.Phase == "committed" {
		return removeAndSync(activeJournal)
	}
	var recoveryCause error
	if journal.Phase == "healthy" {
		timeout := journal.HealthTimeout
		if timeout <= 0 {
			timeout = 30
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
		healthErr := checkUpgradeHealth(ctx, journal.Services, journal.HealthChecks, host)
		cancel()
		if healthErr == nil {
			auditErr := appendUpgradeAudit(journal.AuditLog, upgradeAuditRecord{ID: journal.ID, Version: journal.Version, Status: "committed_after_recovery", StartedAt: journal.StartedAt, EndedAt: now().UTC(), Artifacts: journal.ArtifactHashes})
			if auditErr != nil {
				return fmt.Errorf("resume healthy upgrade audit commit: %w", auditErr)
			}
			journal.Phase = "committed"
			if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
				return fmt.Errorf("persist recovered committed upgrade journal: %w", err)
			}
			return removeAndSync(activeJournal)
		}
		recoveryCause = fmt.Errorf("previously healthy upgrade failed recovery health check: %w", healthErr)
	}
	if len(journal.Backups) != len(journal.Artifacts) || journal.Transaction == "" {
		return errors.New("active upgrade journal is incomplete; refusing automatic recovery")
	}
	rollbackErr := rollbackUpgrade(journal, host)
	status := "recovered_after_interruption"
	if rollbackErr != nil {
		status = "recovery_failed"
	}
	auditError := errors.Join(recoveryCause, rollbackErr)
	auditErr := appendUpgradeAudit(journal.AuditLog, upgradeAuditRecord{ID: journal.ID, Version: journal.Version, Status: status, StartedAt: journal.StartedAt, EndedAt: now().UTC(), Error: errorString(auditError)})
	if rollbackErr != nil {
		return errors.Join(rollbackErr, auditErr)
	}
	return errors.Join(removeAndSync(activeJournal), auditErr)
}

func acquireUpgradeLock(path string) (func() error, error) {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open upgrade lock: %w", err)
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("another upgrade is already running: %w", err)
	}
	return func() error {
		unlockErr := unix.Flock(int(file.Fd()), unix.LOCK_UN)
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}

func copyFileSync(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		_ = output.Close()
		if !committed {
			_ = os.Remove(target)
		}
	}()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	committed = true
	return nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".upgrade-json-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(mode); err != nil {
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return err
	}
	committed = true
	return syncDirectoryPath(directory)
}

func appendUpgradeAudit(path string, record upgradeAuditRecord) error {
	if path == "" {
		path = defaultUpgradeAuditLog
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectoryPath(directory)
}

func removeAndSync(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return syncDirectoryPath(filepath.Dir(path))
}

func syncDirectoryPath(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func errorString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
