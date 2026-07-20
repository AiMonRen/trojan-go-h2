package nodesync

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"gorm.io/gorm"
)

type NodeSyncManager struct {
	mu           sync.Mutex
	db           *gorm.DB
	masterURL    string
	secret       string
	syncInterval time.Duration
	auths        []statistic.Authenticator
	done         chan struct{}
}

var (
	globalManager *NodeSyncManager
	managerOnce   sync.Once
)

func GetManager() *NodeSyncManager {
	return globalManager
}

func InitManager(masterURL, secret string, intervalSec int) {
	managerOnce.Do(func() {
		globalManager = &NodeSyncManager{
			masterURL:    masterURL,
			secret:       secret,
			syncInterval: time.Duration(intervalSec) * time.Second,
			done:         make(chan struct{}),
		}
		log.Infof("node sync manager initialized: master_url=%s, interval=%ds", masterURL, intervalSec)
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
	m.mu.Lock()
	if len(m.auths) == 0 {
		m.mu.Unlock()
		return
	}

	// 1. 收集本地产生的流量增量并重置计数器
	trafficMap := make(map[string]struct {
		Up   uint64 `json:"up"`
		Down uint64 `json:"down"`
	})

	for _, auth := range m.auths {
		for _, st := range auth.ListUsers() {
			hash := st.Hash()
			sent, recv := st.ResetTraffic()
			if sent == 0 && recv == 0 {
				continue
			}
			t := trafficMap[hash]
			t.Up += recv      // 客户端上传 = 节点接收
			t.Down += sent    // 客户端下载 = 节点发送
			trafficMap[hash] = t
		}
	}
	m.mu.Unlock()

	// 2. 发送请求给主节点
	reqBody := struct {
		Traffic map[string]struct {
			Up   uint64 `json:"up"`
			Down uint64 `json:"down"`
		} `json:"traffic"`
	}{
		Traffic: trafficMap,
	}

	data, err := json.Marshal(reqBody)
	if err != nil {
		log.Error("node sync performSync: failed to marshal request body:", err)
		return
	}

	req, err := http.NewRequest("POST", m.masterURL, bytes.NewBuffer(data))
	if err != nil {
		log.Error("node sync performSync: failed to create request:", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", m.secret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Warn("node sync performSync: request to master failed:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Warnf("node sync performSync: master returned abnormal status: %d", resp.StatusCode)
		return
	}

	var respBody struct {
		Users []string `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		log.Error("node sync performSync: failed to decode response:", err)
		return
	}

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
