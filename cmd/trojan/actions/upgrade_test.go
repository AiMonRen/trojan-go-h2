package actions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeUpgradeHost struct {
	mu                      sync.Mutex
	events                  []string
	failRestartValue        string
	failActiveCount         int
	failHealthCount         int
	failHealthUntilRollback bool
	daemonReloads           int
	binaryErr               error
	configCheckErr          error
	daemonErr               error
}

func (h *fakeUpgradeHost) record(event string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, event)
}

func (h *fakeUpgradeHost) RunBinary(_ context.Context, path string, args ...string) error {
	h.record("binary:" + filepath.Base(path) + ":" + strings.Join(args, ","))
	if len(args) > 0 && args[0] == "config-check" {
		return h.configCheckErr
	}
	return h.binaryErr
}

func (h *fakeUpgradeHost) DaemonReload(context.Context) error {
	h.record("daemon-reload")
	h.daemonReloads++
	return h.daemonErr
}

func (h *fakeUpgradeHost) Restart(_ context.Context, service string) error {
	h.record("restart:" + service)
	if service == h.failRestartValue {
		h.failRestartValue = ""
		return errors.New("injected restart failure")
	}
	return nil
}

func (h *fakeUpgradeHost) IsActive(_ context.Context, service string) error {
	h.record("active:" + service)
	if h.failActiveCount > 0 {
		h.failActiveCount--
		return errors.New("injected inactive service")
	}
	return nil
}

func (h *fakeUpgradeHost) Health(_ context.Context, check upgradeHealthCheck) error {
	h.record("health:" + check.Name)
	if h.failHealthUntilRollback && h.daemonReloads < 2 {
		return errors.New("injected health failure before rollback")
	}
	if h.failHealthCount > 0 {
		h.failHealthCount--
		return errors.New("injected health failure")
	}
	return nil
}

func sha256String(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func writeTestUpgradeManifest(t *testing.T, root string, manifest upgradeManifest) string {
	t.Helper()
	path := filepath.Join(root, "upgrade.json")
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testUpgradeManifest(t *testing.T, host *fakeUpgradeHost) (string, string, string, string) {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "trojan-go.new")
	target := filepath.Join(root, "bin", "trojan-go")
	stateDir := filepath.Join(root, "state")
	auditLog := filepath.Join(root, "log", "audit.jsonl")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("old-binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := upgradeManifest{
		Version: "test-v2",
		Artifacts: []upgradeArtifact{{
			Source: source, Target: target, SHA256: sha256String("new-binary"), Mode: "0755", VerifyArgs: []string{"-version"},
		}},
		Services:     []string{"control-service", "gateway-service"},
		HealthChecks: []upgradeHealthCheck{{Name: "control", Type: "tcp", Target: "127.0.0.1:8082"}},
		StateDir:     stateDir, AuditLog: auditLog, HealthTimeout: 1,
	}
	return writeTestUpgradeManifest(t, root, manifest), target, stateDir, auditLog
}

func fixedUpgradeClock() func() time.Time {
	base := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex
	var count time.Duration
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		count += time.Millisecond
		return base.Add(count)
	}
}

func readAuditRecords(t *testing.T, path string) []upgradeAuditRecord {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	records := make([]upgradeAuditRecord, 0, len(lines))
	for _, line := range lines {
		var record upgradeAuditRecord
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatal(err)
		}
		records = append(records, record)
	}
	return records
}

func TestExecuteUpgradeCommitsVerifiedArtifacts(t *testing.T) {
	host := &fakeUpgradeHost{}
	manifestPath, target, stateDir, auditLog := testUpgradeManifest(t, host)
	if err := executeUpgrade(manifestPath, host, fixedUpgradeClock()); err != nil {
		t.Fatalf("execute upgrade: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new-binary" {
		t.Fatalf("target = %q, want new binary", data)
	}
	if _, err := os.Stat(filepath.Join(stateDir, "active.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active journal still exists: %v", err)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "committed" || records[0].Artifacts[target] != sha256String("new-binary") {
		t.Fatalf("unexpected audit records: %+v", records)
	}
	wantEvents := []string{
		"binary:000:-version", "daemon-reload", "restart:control-service", "restart:gateway-service",
		"active:control-service", "active:gateway-service", "health:control",
	}
	if !reflect.DeepEqual(host.events, wantEvents) {
		t.Fatalf("events = %v, want %v", host.events, wantEvents)
	}
}

func TestExecuteUpgradeRunsConfigChecksBeforeSwitch(t *testing.T) {
	host := &fakeUpgradeHost{}
	root := t.TempDir()
	binarySource := filepath.Join(root, "trojan-go.new")
	configSource := filepath.Join(root, "gateway.new.yaml")
	binaryTarget := filepath.Join(root, "bin", "trojan-go")
	configTarget := filepath.Join(root, "etc", "gateway.yaml")
	for _, directory := range []string{filepath.Dir(binaryTarget), filepath.Dir(configTarget)} {
		if err := os.MkdirAll(directory, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(binarySource, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configSource, []byte("gateway: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binaryTarget, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configTarget, []byte("gateway: {old: true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := upgradeManifest{
		Version: "v2",
		Artifacts: []upgradeArtifact{
			{Source: binarySource, Target: binaryTarget, SHA256: sha256String("binary"), Mode: "0755", VerifyArgs: []string{"-version"}},
			{Source: configSource, Target: configTarget, SHA256: sha256String("gateway: {}\n"), Mode: "0600"},
		},
		ConfigChecks: []upgradeConfigCheck{{BinaryTarget: binaryTarget, Service: "gateway", ConfigTarget: configTarget}},
		Services:     []string{"gateway-service"}, StateDir: filepath.Join(root, "state"), AuditLog: filepath.Join(root, "audit.jsonl"), HealthTimeout: 1,
	}
	manifestPath := writeTestUpgradeManifest(t, root, manifest)
	if err := executeUpgrade(manifestPath, host, fixedUpgradeClock()); err != nil {
		t.Fatalf("execute upgrade: %v", err)
	}
	if len(host.events) < 2 || host.events[0] != "binary:000:-version" || !strings.HasPrefix(host.events[1], "binary:000:config-check,--service,gateway,--config,") || !strings.HasSuffix(host.events[1], "/staging/001") {
		t.Fatalf("config check was not run before switching: %v", host.events)
	}
}

func TestRunUpgradeConfigChecksUsesStagedGatewayDependencies(t *testing.T) {
	host := &fakeUpgradeHost{}
	root := t.TempDir()
	targets := []string{
		filepath.Join(root, "bin", "trojan-go"),
		filepath.Join(root, "etc", "gateway.yaml"),
		filepath.Join(root, "tls", "gateway.crt"),
		filepath.Join(root, "tls", "gateway.key"),
	}
	staged := []string{
		filepath.Join(root, "state", "staging", "000"),
		filepath.Join(root, "state", "staging", "001"),
		filepath.Join(root, "state", "staging", "002"),
		filepath.Join(root, "state", "staging", "003"),
	}
	manifest := upgradeManifest{
		Artifacts: []upgradeArtifact{
			{Target: targets[0]},
			{Target: targets[1]},
			{Target: targets[2]},
			{Target: targets[3]},
		},
		ConfigChecks: []upgradeConfigCheck{{BinaryTarget: targets[0], Service: "gateway", ConfigTarget: targets[1]}},
	}
	if err := runUpgradeConfigChecks(manifest, staged, host); err != nil {
		t.Fatalf("run config checks: %v", err)
	}
	want := "binary:000:config-check,--service,gateway,--config," + staged[1] + ",--path-override," + targets[2] + "," + staged[2] + ",--path-override," + targets[3] + "," + staged[3]
	if !reflect.DeepEqual(host.events, []string{want}) {
		t.Fatalf("events = %v, want %v", host.events, []string{want})
	}
}

func TestExecuteUpgradeRejectsFailedConfigCheckBeforeSwitch(t *testing.T) {
	host := &fakeUpgradeHost{configCheckErr: errors.New("invalid staged config")}
	manifestPath, target, _, auditLog := testUpgradeManifest(t, host)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest upgradeManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[0].VerifyArgs = nil
	manifest.ConfigChecks = []upgradeConfigCheck{{BinaryTarget: target, Service: "data-plane", ConfigTarget: target}}
	manifestPath = writeTestUpgradeManifest(t, filepath.Dir(manifestPath), manifest)
	if err := executeUpgrade(manifestPath, host, fixedUpgradeClock()); err == nil || !strings.Contains(err.Error(), "config self-check") {
		t.Fatalf("expected config self-check error, got %v", err)
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "old-binary" {
		t.Fatalf("target changed before config validation: %q", current)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "rejected" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestExecuteUpgradeRejectsChecksumBeforeTargetChange(t *testing.T) {
	host := &fakeUpgradeHost{}
	manifestPath, target, _, auditLog := testUpgradeManifest(t, host)
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest upgradeManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	manifestPath = writeTestUpgradeManifest(t, filepath.Dir(manifestPath), manifest)
	if err := executeUpgrade(manifestPath, host, fixedUpgradeClock()); err == nil || !strings.Contains(err.Error(), "SHA-256 mismatch") {
		t.Fatalf("expected checksum error, got %v", err)
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "old-binary" {
		t.Fatalf("target changed after rejected artifact: %q", current)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "rejected" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestExecuteUpgradeRollsBackAfterRestartFailure(t *testing.T) {
	host := &fakeUpgradeHost{failRestartValue: "gateway-service"}
	manifestPath, target, stateDir, auditLog := testUpgradeManifest(t, host)
	err := executeUpgrade(manifestPath, host, fixedUpgradeClock())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected rolled-back failure, got %v", err)
	}
	current, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(current) != "old-binary" {
		t.Fatalf("target was not restored: %q", current)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "active.json")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("active journal still exists after rollback: %v", statErr)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "rolled_back" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
	joined := strings.Join(host.events, ",")
	if strings.Count(joined, "daemon-reload") != 2 || strings.Count(joined, "restart:control-service") != 2 || strings.Count(joined, "restart:gateway-service") != 2 {
		t.Fatalf("old services were not restarted after rollback: %v", host.events)
	}
}

func TestExecuteUpgradeRollsBackAfterHealthFailure(t *testing.T) {
	host := &fakeUpgradeHost{failHealthUntilRollback: true}
	manifestPath, target, _, auditLog := testUpgradeManifest(t, host)
	err := executeUpgrade(manifestPath, host, fixedUpgradeClock())
	if err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected health rollback, got %v", err)
	}
	current, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(current) != "old-binary" {
		t.Fatalf("target was not restored: %q", current)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "rolled_back" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestExecuteUpgradeReportsRollbackHealthFailure(t *testing.T) {
	host := &fakeUpgradeHost{failHealthCount: 1000}
	manifestPath, target, stateDir, auditLog := testUpgradeManifest(t, host)
	err := executeUpgrade(manifestPath, host, fixedUpgradeClock())
	if err == nil || !strings.Contains(err.Error(), "rollback failed") {
		t.Fatalf("expected rollback failure, got %v", err)
	}
	current, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(current) != "old-binary" {
		t.Fatalf("file rollback must still restore target: %q", current)
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "active.json")); statErr != nil {
		t.Fatalf("active journal must remain for operator recovery: %v", statErr)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "rollback_failed" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestRecoverHealthyUpgradeCommitsAfterRecheck(t *testing.T) {
	root := t.TempDir()
	stateDir := filepath.Join(root, "state")
	auditLog := filepath.Join(root, "audit.jsonl")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	journal := upgradeJournal{
		ID: "healthy-interrupted", Version: "v2", Phase: "healthy", StartedAt: time.Now(), Transaction: root,
		Artifacts: []upgradeArtifact{{Target: filepath.Join(root, "target")}}, ArtifactHashes: map[string]string{filepath.Join(root, "target"): sha256String("new")},
		Backups: []upgradeBackup{{Target: filepath.Join(root, "target")}}, Services: []string{"gateway-service"},
		HealthChecks: []upgradeHealthCheck{{Name: "gateway", Type: "tcp", Target: "127.0.0.1:443"}}, HealthTimeout: 1, AuditLog: auditLog,
	}
	activeJournal := filepath.Join(stateDir, "active.json")
	if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &fakeUpgradeHost{}
	if err := recoverInterruptedUpgrade(activeJournal, host, fixedUpgradeClock()); err != nil {
		t.Fatalf("recover healthy upgrade: %v", err)
	}
	if _, err := os.Stat(activeJournal); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active journal still exists: %v", err)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "committed_after_recovery" || records[0].Artifacts[journal.Artifacts[0].Target] == "" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
	if !reflect.DeepEqual(host.events, []string{"active:gateway-service", "health:gateway"}) {
		t.Fatalf("healthy recovery must not restart or rollback: %v", host.events)
	}
}

func TestRecoverInterruptedUpgradeRestoresBackups(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	backup := filepath.Join(root, "backup")
	stateDir := filepath.Join(root, "state")
	auditLog := filepath.Join(root, "audit.jsonl")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("partially-switched"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(backup, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal := upgradeJournal{
		ID: "interrupted", Version: "v2", Phase: "switched", StartedAt: time.Now(), Transaction: root,
		Artifacts: []upgradeArtifact{{Target: target}}, Backups: []upgradeBackup{{Target: target, BackupPath: backup, Existed: true, Mode: 0o600}},
		Services: []string{"gateway-service"}, AuditLog: auditLog,
	}
	activeJournal := filepath.Join(stateDir, "active.json")
	if err := writeJSONAtomic(activeJournal, journal, 0o600); err != nil {
		t.Fatal(err)
	}
	host := &fakeUpgradeHost{}
	if err := recoverInterruptedUpgrade(activeJournal, host, fixedUpgradeClock()); err != nil {
		t.Fatalf("recover interrupted upgrade: %v", err)
	}
	current, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "old" {
		t.Fatalf("target = %q, want old", current)
	}
	records := readAuditRecords(t, auditLog)
	if len(records) != 1 || records[0].Status != "recovered_after_interruption" {
		t.Fatalf("unexpected audit records: %+v", records)
	}
}

func TestValidateUpgradeManifestNormalizesConfigCheckTargets(t *testing.T) {
	manifest := upgradeManifest{
		Version: "v",
		Artifacts: []upgradeArtifact{
			{Source: "binary", Target: "/opt/trojan-go", SHA256: strings.Repeat("0", 64), Mode: "0755"},
			{Source: "config", Target: "/etc/trojan-go/gateway.yaml", SHA256: strings.Repeat("1", 64), Mode: "0600"},
		},
		ConfigChecks: []upgradeConfigCheck{{BinaryTarget: "/opt/./trojan-go", Service: "gateway", ConfigTarget: "/etc/trojan-go/../trojan-go/gateway.yaml"}},
		Services:     []string{"gateway-service"},
	}
	if err := validateUpgradeManifest(&manifest); err != nil {
		t.Fatalf("validate manifest: %v", err)
	}
	check := manifest.ConfigChecks[0]
	if check.BinaryTarget != "/opt/trojan-go" || check.ConfigTarget != "/etc/trojan-go/gateway.yaml" {
		t.Fatalf("config check targets were not normalized: %+v", check)
	}
}

func TestValidateUpgradeManifestRejectsUnsafeInputs(t *testing.T) {
	tests := []struct {
		name     string
		manifest upgradeManifest
		contains string
	}{
		{name: "relative target", manifest: upgradeManifest{Version: "v", Artifacts: []upgradeArtifact{{Source: "x", Target: "relative", SHA256: strings.Repeat("0", 64), Mode: "0600"}}, Services: []string{"gateway-service"}}, contains: "absolute"},
		{name: "unsafe service", manifest: upgradeManifest{Version: "v", Artifacts: []upgradeArtifact{{Source: "x", Target: "/safe", SHA256: strings.Repeat("0", 64), Mode: "0600"}}, Services: []string{"gateway;reboot"}}, contains: "invalid systemd"},
		{name: "public health target", manifest: upgradeManifest{Version: "v", Artifacts: []upgradeArtifact{{Source: "x", Target: "/safe", SHA256: strings.Repeat("0", 64), Mode: "0600"}}, Services: []string{"gateway-service"}, HealthChecks: []upgradeHealthCheck{{Name: "public", Type: "tcp", Target: "8.8.8.8:53"}}}, contains: "loopback"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateUpgradeManifest(&test.manifest)
			if err == nil || !strings.Contains(err.Error(), test.contains) {
				t.Fatalf("expected %q error, got %v", test.contains, err)
			}
		})
	}
}
