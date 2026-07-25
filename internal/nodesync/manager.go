package nodesync

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/trafficoutbox"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"gorm.io/gorm"
)

type trafficStats struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type NodeSyncManager struct {
	mu              sync.Mutex
	db              *gorm.DB
	masterURL       string
	secret          string
	syncInterval    time.Duration
	auths           []statistic.Authenticator
	pendingTraffic  map[string]trafficStats // 已从认证器取走、尚未被主节点确认的固定批次
	queuedTraffic   map[string]trafficStats // 等待组成下一批的新增流量，不与失败批次混合
	pendingSyncID   string                  // 固定批次的幂等键，失败重试必须保持不变
	outbox          *trafficoutbox.File
	outboxLoadError error
	syncClient      *http.Client
	heartbeatClient *http.Client
	failureCount    int
	nextSyncAt      time.Time
	done            chan struct{}
}

// L-08 migration status: NewManager constructor has been added.
//
// The process-global singleton behaviour is preserved for backwards compatibility:
//   - InitManager still only takes effect the first time it is called in a process,
//     delegating to NewManager for actual construction.
//   - GetManager returns nil until InitManager has run, and returns the same
//     instance for the rest of the process lifetime.
//
// Migration path (now available):
//   - Use NewManager(...) (*NodeSyncManager, error) to create isolated instances
//     for tests and new call sites that need proper isolation.
//   - Production code can continue using InitManager as before.
//
// Removing the singleton entirely requires lifecycle/dependency-injection
// changes across the data plane and the worker control service, which remains
// out of scope for this change.
//
// Note also that L-08 covered a second item — bounded, forced shutdown of
// in-flight Gateway/ServiceRouter connections — which is tracked and fixed in
// internal/webserver (Gateway.Close/ServiceRouter.Close drain with a deadline
// and then force-close). This comment only documents the singleton part.
var (
	globalManager *NodeSyncManager
	managerOnce   sync.Once
)

// GetManager returns the process-global manager, or nil when InitManager has not
// been called yet. See the KNOWN LIMITATION note above.
func GetManager() *NodeSyncManager {
	return globalManager
}

const (
	defaultSyncInterval = 60 * time.Second
	syncTimeout         = 10 * time.Second
	heartbeatTimeout    = 5 * time.Second
	maxSyncBackoff      = 10 * time.Minute
)

func normalizedSyncInterval(intervalSec int) time.Duration {
	if intervalSec <= 0 {
		return defaultSyncInterval
	}
	return time.Duration(intervalSec) * time.Second
}

func newSyncHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          32,
		MaxIdleConnsPerHost:   8,
		MaxConnsPerHost:       16,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: time.Second,
		ResponseHeaderTimeout: timeout,
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

var readCryptoRandom = cryptorand.Read

func newSyncID() (string, error) {
	buf := make([]byte, 16)
	if _, err := readCryptoRandom(buf); err != nil {
		return "", fmt.Errorf("read cryptographic random source: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func validateUserHashes(hashes []string) error {
	seen := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		if len(hash) != 56 {
			return fmt.Errorf("invalid user hash length %d", len(hash))
		}
		decoded, err := hex.DecodeString(hash)
		if err != nil || len(decoded) != 28 {
			return errors.New("invalid SHA-224 user hash")
		}
		if _, exists := seen[hash]; exists {
			return errors.New("duplicate user hash in sync response")
		}
		seen[hash] = struct{}{}
	}
	return nil
}

func boundedSyncBackoff(interval time.Duration, failures int) time.Duration {
	if failures <= 0 {
		return 0
	}
	backoff := interval
	for i := 1; i < failures && backoff < maxSyncBackoff; i++ {
		backoff *= 2
	}
	if backoff > maxSyncBackoff {
		backoff = maxSyncBackoff
	}
	// Add at most 20% jitter to avoid many workers retrying simultaneously.
	return backoff + time.Duration(rand.Int64N(int64(backoff)/5+1))
}

func (m *NodeSyncManager) syncReady(now time.Time) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.nextSyncAt.IsZero() || !now.Before(m.nextSyncAt)
}

func (m *NodeSyncManager) recordSyncFailure(reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureCount++
	backoff := boundedSyncBackoff(m.syncInterval, m.failureCount)
	m.nextSyncAt = time.Now().Add(backoff)
	log.Warnf("node sync manager: %s; retrying after %s", reason, backoff.Round(time.Second))
}

func (m *NodeSyncManager) recordSyncSuccess() {
	m.mu.Lock()
	m.failureCount = 0
	m.nextSyncAt = time.Time{}
	m.mu.Unlock()
}

func (m *NodeSyncManager) getSyncClient() *http.Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.syncClient == nil {
		m.syncClient = newSyncHTTPClient(syncTimeout)
	}
	return m.syncClient
}

func (m *NodeSyncManager) getHeartbeatClient() *http.Client {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.heartbeatClient == nil {
		m.heartbeatClient = newSyncHTTPClient(heartbeatTimeout)
	}
	return m.heartbeatClient
}

// NewManager creates an isolated NodeSyncManager instance.
//
// This is the migration path documented in L-08: production code continues to
// use InitManager (which now delegates here), while tests and new call sites
// can hold their own instance for proper isolation.
//
// Parameters:
//   - masterURL: the master node's sync endpoint URL
//   - secret: the node's shared secret for authentication
//   - intervalSec: sync interval in seconds (0 or negative for default)
//   - outboxPath: optional path for the persistent traffic outbox file
//
// Returns a configured manager and any error encountered during outbox setup.
func NewManager(masterURL, secret string, intervalSec int, outboxPath ...string) (*NodeSyncManager, error) {
	interval := normalizedSyncInterval(intervalSec)
	if intervalSec <= 0 {
		log.Warnf("node sync manager: invalid sync interval %ds; using default %s", intervalSec, interval)
	}
	var path string
	if len(outboxPath) > 0 {
		path = outboxPath[0]
	}
	outbox, outboxErr := trafficoutbox.NewFile(path)
	m := &NodeSyncManager{
		masterURL:       masterURL,
		secret:          secret,
		syncInterval:    interval,
		pendingTraffic:  make(map[string]trafficStats),
		queuedTraffic:   make(map[string]trafficStats),
		outbox:          outbox,
		outboxLoadError: outboxErr,
		done:            make(chan struct{}),
	}
	if outboxErr == nil {
		outboxErr = m.loadOutbox()
		m.outboxLoadError = outboxErr
	}
	if outboxErr != nil {
		log.Errorf("node sync manager: traffic outbox unavailable: %v", outboxErr)
	}
	log.Infof("node sync manager created: master_url=%s, interval=%s, outbox=%s", masterURL, interval, path)
	return m, nil
}

// InitManager creates the process-global manager. It is idempotent by design:
// only the first call in a process has any effect, and later calls are ignored
// rather than reconfiguring or replacing the running manager. See the KNOWN
// LIMITATION (L-08) note next to globalManager for the reasoning and the planned
// migration to an injectable constructor.
//
// This function now delegates to NewManager for the actual construction.
func InitManager(masterURL, secret string, intervalSec int, outboxPath ...string) {
	alreadyInitialized := true
	managerOnce.Do(func() {
		alreadyInitialized = false
		m, err := NewManager(masterURL, secret, intervalSec, outboxPath...)
		if err != nil {
			log.Errorf("node sync manager: failed to create manager: %v", err)
			return
		}
		globalManager = m
	})
	// Make the singleton's swallowed re-init observable instead of silent: a
	// second call with different settings is a configuration bug the operator
	// needs to see.
	if alreadyInitialized {
		log.Warnf("node sync manager: already initialized; ignoring re-init request for master_url=%s (process-global singleton, L-08)", masterURL)
	}
}

func (m *NodeSyncManager) loadOutbox() error {
	if m.outbox == nil {
		return nil
	}
	state, err := m.outbox.Load()
	if err != nil {
		return err
	}
	m.pendingSyncID = state.PendingSyncID
	m.pendingTraffic = fromOutboxTraffic(state.Pending)
	m.queuedTraffic = fromOutboxTraffic(state.Queued)
	return nil
}

func toOutboxTraffic(source map[string]trafficStats) map[string]trafficoutbox.Traffic {
	result := make(map[string]trafficoutbox.Traffic, len(source))
	for hash, value := range source {
		result[hash] = trafficoutbox.Traffic{Up: value.Up, Down: value.Down}
	}
	return result
}

func fromOutboxTraffic(source map[string]trafficoutbox.Traffic) map[string]trafficStats {
	result := make(map[string]trafficStats, len(source))
	for hash, value := range source {
		result[hash] = trafficStats{Up: value.Up, Down: value.Down}
	}
	return result
}

func (m *NodeSyncManager) persistOutboxLocked() error {
	if m.outbox == nil {
		return nil
	}
	return m.outbox.Save(trafficoutbox.State{
		PendingSyncID: m.pendingSyncID,
		Pending:       toOutboxTraffic(m.pendingTraffic),
		Queued:        toOutboxTraffic(m.queuedTraffic),
	})
}

func (m *NodeSyncManager) SetDB(db *gorm.DB) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.db = db
}

func (m *NodeSyncManager) AddAuthenticator(auth statistic.Authenticator) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.auths = append(m.auths, auth)
}

func (m *NodeSyncManager) Start(ctx context.Context) {
	go m.syncLoop(ctx)
	go m.heartbeatLoop(ctx)
}

func (m *NodeSyncManager) Stop() {
	select {
	case <-m.done:
	default:
		close(m.done)
	}
}

func (m *NodeSyncManager) syncLoop(ctx context.Context) {
	ticker := time.NewTicker(m.syncInterval)
	defer ticker.Stop()

	// 启动时等待认证器初始化完成后再执行首次同步
	// 避免认证器还没注册就静默跳过
	m.waitForAuth(3 * time.Second)
	m.performSync()

	for {
		select {
		case <-ticker.C:
			m.performSync()
		case <-m.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

func (m *NodeSyncManager) waitForAuth(timeout time.Duration) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		ready := len(m.auths) > 0
		m.mu.Unlock()
		if ready {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func (m *NodeSyncManager) performSync() {
	if !m.syncReady(time.Now()) {
		return
	}

	m.mu.Lock()
	if m.outboxLoadError != nil {
		err := m.outboxLoadError
		m.mu.Unlock()
		m.recordSyncFailure(fmt.Sprintf("traffic outbox unavailable: %v", err))
		return
	}
	if len(m.auths) == 0 {
		m.mu.Unlock()
		return
	}
	if m.pendingTraffic == nil {
		m.pendingTraffic = make(map[string]trafficStats)
	}
	if m.queuedTraffic == nil {
		m.queuedTraffic = make(map[string]trafficStats)
	}

	// 1. 收集新增流量到队列。TakeTraffic 只会在 outbox 检查点成功后清零，
	//    因此进程在 Reset/写盘边界崩溃时不会形成未持久化的丢失窗口。
	for _, auth := range m.auths {
		for _, st := range auth.ListUsers() {
			hash := st.Hash()
			_, _, err := st.TakeTraffic(func(sent, recv uint64) error {
				queued, existed := m.queuedTraffic[hash]
				if queued.Up > ^uint64(0)-recv || queued.Down > ^uint64(0)-sent {
					return fmt.Errorf("traffic aggregation overflow for user %s", hash)
				}
				updated := trafficStats{Up: queued.Up + recv, Down: queued.Down + sent}
				m.queuedTraffic[hash] = updated
				if err := m.persistOutboxLocked(); err != nil {
					if existed {
						m.queuedTraffic[hash] = queued
					} else {
						delete(m.queuedTraffic, hash)
					}
					return fmt.Errorf("checkpoint traffic for user %s: %w", hash, err)
				}
				return nil
			})
			if err != nil {
				m.mu.Unlock()
				m.recordSyncFailure(err.Error())
				return
			}
		}
	}

	// 若没有未确认批次，则先生成幂等键，成功后再冻结当前队列。随机源异常时
	// 不发送无幂等键的流量报告，已收集的流量继续留在 queuedTraffic 等待重试。
	if len(m.pendingTraffic) == 0 && len(m.queuedTraffic) > 0 {
		syncID, err := newSyncID()
		if err != nil {
			m.mu.Unlock()
			m.recordSyncFailure(fmt.Sprintf("failed to generate idempotency key: %v", err))
			return
		}
		oldQueued := m.queuedTraffic
		m.pendingTraffic = oldQueued
		m.queuedTraffic = make(map[string]trafficStats)
		m.pendingSyncID = syncID
		if err := m.persistOutboxLocked(); err != nil {
			m.pendingTraffic = make(map[string]trafficStats)
			m.queuedTraffic = oldQueued
			m.pendingSyncID = ""
			m.mu.Unlock()
			m.recordSyncFailure(fmt.Sprintf("failed to freeze traffic outbox batch: %v", err))
			return
		}
	}

	// 没有流量时仍同步用户哈希，但请求使用独立随机键。空流量请求不写 outbox，
	// 因为它不产生计费副作用。
	requestSyncID := m.pendingSyncID
	if requestSyncID == "" {
		syncID, err := newSyncID()
		if err != nil {
			m.mu.Unlock()
			m.recordSyncFailure(fmt.Sprintf("failed to generate idempotency key: %v", err))
			return
		}
		requestSyncID = syncID
	}

	// 复制固定批次；请求期间继续产生的流量会留在 queuedTraffic，等待下一次确认后发送。
	trafficMap := make(map[string]trafficStats, len(m.pendingTraffic))
	for hash, traffic := range m.pendingTraffic {
		trafficMap[hash] = traffic
	}
	syncID := requestSyncID
	m.mu.Unlock()

	// 2. 发送请求给主节点
	reqBody := struct {
		Traffic map[string]trafficStats `json:"traffic"`
	}{
		Traffic: trafficMap,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		m.recordSyncFailure(fmt.Sprintf("failed to marshal request body: %v", err))
		return
	}

	req, err := http.NewRequest(http.MethodPost, m.masterURL, bytes.NewBuffer(data))
	if err != nil {
		m.recordSyncFailure(fmt.Sprintf("failed to create request: %v", err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", m.secret)
	req.Header.Set("X-Node-Sync-ID", syncID)

	resp, err := m.getSyncClient().Do(req)
	if err != nil {
		m.recordSyncFailure(fmt.Sprintf("request to master failed: %v", err))
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		m.recordSyncFailure(fmt.Sprintf("master returned abnormal status: %d", resp.StatusCode))
		return
	}

	var respBody struct {
		Users []string `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		m.recordSyncFailure(fmt.Sprintf("failed to decode response: %v", err))
		return
	}
	if err := validateUserHashes(respBody.Users); err != nil {
		m.recordSyncFailure(fmt.Sprintf("master returned invalid user hashes: %v", err))
		return
	}

	// 主节点已明确返回成功：先持久化删除已确认批次，再更新内存状态。
	// 若删除失败，保留原批次与同步 ID；后续重试由 Master 回执去重。
	m.mu.Lock()
	if len(trafficMap) > 0 {
		oldPending := m.pendingTraffic
		oldSyncID := m.pendingSyncID
		m.pendingTraffic = make(map[string]trafficStats)
		m.pendingSyncID = ""
		if err := m.persistOutboxLocked(); err != nil {
			m.pendingTraffic = oldPending
			m.pendingSyncID = oldSyncID
			m.mu.Unlock()
			m.recordSyncFailure(fmt.Sprintf("failed to acknowledge traffic outbox batch: %v", err))
			return
		}
	}
	m.mu.Unlock()

	// 3. 将最新的哈希列表同步回本地代理
	m.mu.Lock()
	auths := append([]statistic.Authenticator(nil), m.auths...)
	m.mu.Unlock()

	// 建立主节点有效用户哈希的 map
	masterHashes := make(map[string]bool)
	for _, h := range respBody.Users {
		masterHashes[h] = true
	}

	for _, auth := range auths {
		// 获取该 authenticator 目前已有的用户哈希
		localHashes := make(map[string]bool)
		for _, u := range auth.ListUsers() {
			localHashes[u.Hash()] = true
		}

		// 3.1 删除已失效的用户
		// L-01: these failures leave the local data plane diverged from the
		// master (a revoked user can still connect, or a new user cannot), so
		// they are logged at warning level rather than debug.
		for h := range localHashes {
			if !masterHashes[h] {
				if err := auth.DelUser(h); err != nil {
					log.Warnf("node sync performSync: failed to delete user hash %s, it may still be able to connect until the next sync: %v", h, err)
				}
			}
		}

		// 3.2 添加新激活的用户
		for h := range masterHashes {
			if !localHashes[h] {
				if err := auth.AddUser(h); err != nil {
					log.Warnf("node sync performSync: failed to add user hash %s, it cannot connect until the next sync: %v", h, err)
				}
			}
		}
	}

	// 4. 将最新的哈希列表同步写入从节点本地 SQLite 数据库作为缓存，以保障从节点断电/重启后的离线代理可用性
	m.mu.Lock()
	db := m.db
	m.mu.Unlock()
	if db != nil {
		if err := db.Transaction(func(tx *gorm.DB) error {
			var result *gorm.DB
			if len(respBody.Users) > 0 {
				result = tx.Where("hash NOT IN ?", respBody.Users).Delete(&database.User{})
			} else {
				result = tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&database.User{})
			}
			if result.Error != nil {
				return result.Error
			}

			for _, h := range respBody.Users {
				var localU database.User
				err := tx.Where("hash = ?", h).First(&localU).Error
				if err == nil {
					continue
				}
				if !errors.Is(err, gorm.ErrRecordNotFound) {
					return err
				}
				// S-08: a worker node caches only the authentication hash the
				// master sent; it never receives the plaintext password and so
				// cannot hold a usable credential. Password is therefore left
				// empty. It used to be the literal "placeholder-pwd", the only
				// hardcoded credential in the tree, which risked being read
				// back by any code path that generates client configs and
				// silently produced a config with a bogus password.
				// Authentication uses Hash alone, so an empty Password is
				// correct here; callers that need a real credential must go
				// through the master.
				newUser := database.User{
					Username: "sync-user-" + h[:6],
					Password: "",
					Hash:     h,
					Status:   0,
				}
				if err := tx.Create(&newUser).Error; err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			m.recordSyncFailure(fmt.Sprintf("failed to update local user cache: %v", err))
			return
		}
	}
	m.recordSyncSuccess()
}

// heartbeatLoop sends lightweight heartbeats to the master every 30 seconds.
// This is independent of the data sync loop so the master always knows
// the slave is alive, even when there's no traffic or sync fails temporarily.
func (m *NodeSyncManager) heartbeatLoop(ctx context.Context) {
	// 等待认证器就绪
	m.waitForAuth(3 * time.Second)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.performHeartbeat()
		case <-m.done:
			return
		case <-ctx.Done():
			return
		}
	}
}

const (
	syncEndpointPath       = "/control/v1/nodes/sync"
	legacySyncEndpointPath = "/admin/api/node/sync"
)

// heartbeatURL derives the heartbeat endpoint from either the service boundary
// URL or the pre-service legacy URL so existing cold data deployments remain
// readable while new generated configurations use /control/v1.
func heartbeatURL(masterURL string) (string, error) {
	u, err := url.Parse(masterURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid master sync URL %q", masterURL)
	}
	switch {
	case strings.HasSuffix(u.Path, syncEndpointPath):
		u.Path = strings.TrimSuffix(u.Path, syncEndpointPath) + "/control/v1/nodes/heartbeat"
	case strings.HasSuffix(u.Path, legacySyncEndpointPath):
		u.Path = strings.TrimSuffix(u.Path, legacySyncEndpointPath) + "/admin/api/node/heartbeat"
	default:
		return "", fmt.Errorf("master sync URL path must end with %s", syncEndpointPath)
	}
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

// performHeartbeat sends a lightweight ping to the master's /node/heartbeat endpoint.
// Failure is logged but not fatal — the sync loop will update LastHeartbeat on its next success.
func (m *NodeSyncManager) performHeartbeat() {
	if m.masterURL == "" {
		return
	}
	hbURL, err := heartbeatURL(m.masterURL)
	if err != nil {
		log.Warn("heartbeat: invalid master sync URL:", err)
		return
	}

	req, err := http.NewRequest("POST", hbURL, nil)
	if err != nil {
		log.Warn("heartbeat: failed to create request:", err)
		return
	}
	req.Header.Set("X-Node-Secret", m.secret)

	resp, err := m.getHeartbeatClient().Do(req)
	if err != nil {
		log.Warn("heartbeat: request to master failed:", err)
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("heartbeat: master returned abnormal status: %d", resp.StatusCode)
	}
}
