package nodesync

import (
	"bytes"
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
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
	syncClient      *http.Client
	heartbeatClient *http.Client
	failureCount    int
	nextSyncAt      time.Time
	done            chan struct{}
}

var (
	globalManager *NodeSyncManager
	managerOnce   sync.Once
)

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

func InitManager(masterURL, secret string, intervalSec int) {
	managerOnce.Do(func() {
		interval := normalizedSyncInterval(intervalSec)
		if intervalSec <= 0 {
			log.Warnf("node sync manager: invalid sync interval %ds; using default %s", intervalSec, interval)
		}
		globalManager = &NodeSyncManager{
			masterURL:      masterURL,
			secret:         secret,
			syncInterval:   interval,
			pendingTraffic: make(map[string]trafficStats),
			queuedTraffic:  make(map[string]trafficStats),
			done:           make(chan struct{}),
		}
		log.Infof("node sync manager initialized: master_url=%s, interval=%s", masterURL, interval)
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

	// 1. 收集新增流量到队列。已发送但尚未确认的批次保持原样，避免请求超时后
	//    主节点已记账而从节点重试时把后续流量一并重复上报。
	for _, auth := range m.auths {
		for _, st := range auth.ListUsers() {
			sent, recv := st.ResetTraffic()
			if sent == 0 && recv == 0 {
				continue
			}
			hash := st.Hash()
			queued := m.queuedTraffic[hash]
			queued.Up += recv   // 客户端上传 = 节点接收
			queued.Down += sent // 客户端下载 = 节点发送
			m.queuedTraffic[hash] = queued
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
		m.pendingTraffic = m.queuedTraffic
		m.queuedTraffic = make(map[string]trafficStats)
		m.pendingSyncID = syncID
	}

	// 没有流量时仍同步用户哈希，但请求使用独立随机键，避免与流量批次语义混用。
	if m.pendingSyncID == "" {
		syncID, err := newSyncID()
		if err != nil {
			m.mu.Unlock()
			m.recordSyncFailure(fmt.Sprintf("failed to generate idempotency key: %v", err))
			return
		}
		m.pendingSyncID = syncID
	}

	// 复制固定批次；请求期间继续产生的流量会留在 queuedTraffic，等待下一次确认后发送。
	trafficMap := make(map[string]trafficStats, len(m.pendingTraffic))
	for hash, traffic := range m.pendingTraffic {
		trafficMap[hash] = traffic
	}
	syncID := m.pendingSyncID
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
	m.recordSyncSuccess()

	// 主节点已明确返回成功：只移除刚刚发送的快照，保留请求期间新加入的流量。
	m.mu.Lock()
	for hash, sent := range trafficMap {
		pending := m.pendingTraffic[hash]
		if pending.Up < sent.Up || pending.Down < sent.Down {
			log.Warnf("node sync performSync: pending traffic changed unexpectedly for user %s; retaining for retry", hash)
			continue
		}
		pending.Up -= sent.Up
		pending.Down -= sent.Down
		if pending.Up == 0 && pending.Down == 0 {
			delete(m.pendingTraffic, hash)
		} else {
			m.pendingTraffic[hash] = pending
		}
	}
	if len(m.pendingTraffic) == 0 {
		m.pendingSyncID = ""
	}
	m.mu.Unlock()

	// 3. 将最新的哈希列表同步回本地代理
	m.mu.Lock()
	defer m.mu.Unlock()

	// 建立主节点有效用户哈希的 map
	masterHashes := make(map[string]bool)
	for _, h := range respBody.Users {
		masterHashes[h] = true
	}

	for _, auth := range m.auths {
		// 获取该 authenticator 目前已有的用户哈希
		localHashes := make(map[string]bool)
		for _, u := range auth.ListUsers() {
			localHashes[u.Hash()] = true
		}

		// 3.1 删除已失效的用户
		for h := range localHashes {
			if !masterHashes[h] {
				if err := auth.DelUser(h); err != nil {
					log.Debugf("node sync performSync: failed to delete user hash %s: %v", h, err)
				}
			}
		}

		// 3.2 添加新激活的用户
		for h := range masterHashes {
			if !localHashes[h] {
				if err := auth.AddUser(h); err != nil {
					log.Debugf("node sync performSync: failed to add user hash %s: %v", h, err)
				}
			}
		}
	}

	// 4. 将最新的哈希列表同步写入从节点本地 SQLite 数据库作为缓存，以保障从节点断电/重启后的离线代理可用性
	if m.db != nil {
		m.db.Transaction(func(tx *gorm.DB) error {
			if len(respBody.Users) > 0 {
				tx.Where("hash NOT IN ?", respBody.Users).Delete(&database.User{})
			} else {
				tx.Session(&gorm.Session{AllowGlobalUpdate: true}).Delete(&database.User{})
			}

			for _, h := range respBody.Users {
				var localU database.User
				if tx.Where("hash = ?", h).First(&localU).Error != nil {
					newUser := database.User{
						Username: "sync-user-" + h[:6],
						Password: "placeholder-pwd",
						Hash:     h,
						Status:   0,
					}
					tx.Create(&newUser)
				}
			}
			return nil
		})
	}
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

const syncEndpointPath = "/admin/api/node/sync"

// heartbeatURL derives the heartbeat endpoint only from a valid absolute sync URL.
// It avoids string slicing so malformed worker configuration cannot panic the process.
func heartbeatURL(masterURL string) (string, error) {
	u, err := url.Parse(masterURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid master sync URL %q", masterURL)
	}
	if !strings.HasSuffix(u.Path, syncEndpointPath) {
		return "", fmt.Errorf("master sync URL path must end with %s", syncEndpointPath)
	}
	u.Path = strings.TrimSuffix(u.Path, syncEndpointPath) + "/admin/api/node/heartbeat"
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
