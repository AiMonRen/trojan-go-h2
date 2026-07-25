package webserver

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gorm.io/gorm"
)

// ─── 节点管理 API 处理器 ──────────────────────────────

type publicNode struct {
	ID            uint       `json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Name          string     `json:"name"`
	Address       string     `json:"address"`
	DetectedIP    string     `json:"detected_ip"`
	Port          int        `json:"port"`
	Status        int        `json:"status"`
	LastHeartbeat *time.Time `json:"last_heartbeat"`
	TrafficRate   float64    `json:"traffic_rate"`
	WSEnabled     bool       `json:"ws_enabled"`
	WSPath        string     `json:"ws_path"`
	SNI           string     `json:"sni"`
}

func toPublicNode(node database.Node) publicNode {
	return publicNode{
		ID: node.ID, CreatedAt: node.CreatedAt, UpdatedAt: node.UpdatedAt,
		Name: node.Name, Address: node.Address, DetectedIP: node.DetectedIP,
		Port: node.Port, Status: node.Status, LastHeartbeat: node.LastHeartbeat,
		TrafficRate: node.TrafficRate, WSEnabled: node.WSEnabled,
		WSPath: node.WSPath, SNI: node.SNI,
	}
}

func toPublicNodes(nodes []database.Node) []publicNode {
	result := make([]publicNode, 0, len(nodes))
	for _, node := range nodes {
		result = append(result, toPublicNode(node))
	}
	return result
}

func (s *AdminServer) handleListNodes(c *gin.Context) {
	var nodes []database.Node
	if err := s.db.Find(&nodes).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取节点列表失败"})
		return
	}

	// 如果当前不是从节点（即为主节点），则将主节点自身作为虚拟节点加入列表头部
	if !s.isNode {
		mainNodeName := "主节点"
		var cfgTitle database.Config
		// L-01 (F-1): distinguish "no site_title row" (fall back to the default
		// label) from a real database failure. Treating both as "use default"
		// hides outages and lets the panel render stale/incorrect data.
		switch err := s.db.Where("`key` = ?", "site_title").First(&cfgTitle).Error; {
		case err == nil:
			if cfgTitle.Value != "" {
				mainNodeName = cfgTitle.Value
			}
		case errors.Is(err, gorm.ErrRecordNotFound):
			// no custom title configured yet, keep the default
		default:
			log.Errorf("node list: read site_title: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取节点列表失败"})
			return
		}

		// L-04: the synthetic main-node entry must only ever advertise a
		// domain that the operator configured (gateway/embedded config, or the
		// canonical serverDomain). The request Host header is attacker
		// controlled, so it is never used as a fallback: a poisoned Host would
		// otherwise be echoed back into the panel and copied into client
		// configs. When no canonical domain is known we omit the entry (and log
		// it) instead of publishing an untrusted address.
		mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
		if mainDomain == "" {
			mainDomain = s.serverDomain
		}
		if mainDomain == "" {
			log.Warn("node list: canonical domain not configured, omitting synthetic main node entry")
		} else {
			now := time.Now()
			mainNode := database.Node{
				ID:            999999, // 使用特殊的大ID标识系统内置主节点
				Name:          mainNodeName,
				Address:       mainDomain,
				Port:          mainPort,
				TrafficRate:   1.0,
				WSEnabled:     mainWs,
				WSPath:        mainWsPath,
				LastHeartbeat: &now,
			}
			nodes = append([]database.Node{mainNode}, nodes...)
		}
	}

	c.JSON(http.StatusOK, toPublicNodes(nodes))
}

func (s *AdminServer) handleAddNode(c *gin.Context) {
	var req struct {
		Name        string   `json:"name"`
		Address     string   `json:"address"`
		Port        int      `json:"port"`
		TrafficRate *float64 `json:"traffic_rate"`
		WSEnabled   bool     `json:"ws_enabled"`
		WSPath      string   `json:"ws_path"`
		SNI         string   `json:"sni"`
		Secret      string   `json:"secret"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}
	// L-02: name/address/ws-path/SNI now go through the shared validators so
	// the create and update paths enforce identical rules.
	if err := validateNodeName(req.Name); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateNodeAddress(req.Address); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.Port != 0 && (req.Port < 1 || req.Port > 65535) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "端口必须在 1-65535 范围内"})
		return
	}
	if err := validateWSPath(req.WSPath); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateSNI(req.SNI); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	trafficRate := 1.0
	if req.TrafficRate != nil {
		trafficRate = *req.TrafficRate
	}
	if err := validateTrafficRate(trafficRate); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "流量倍率必须大于 0 且不超过 1000"})
		return
	}
	secret := req.Secret
	if secret == "" {
		// Generate 256 bits instead of the previous 128-bit default.
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成节点通信密钥"})
			return
		}
		secret = hex.EncodeToString(b)
	}
	pendingSecret, err := database.PendingNodeSecretMarker()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法准备节点凭据"})
		return
	}
	node := database.Node{
		Name: req.Name, Address: req.Address, Port: req.Port, TrafficRate: trafficRate,
		WSEnabled: req.WSEnabled, WSPath: req.WSPath, SNI: req.SNI, Secret: pendingSecret,
	}
	if node.Port == 0 {
		node.Port = 443
	}
	if node.WSPath == "" {
		node.WSPath = "/trojan-go"
	}
	if err := s.db.Create(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := database.SetNodeSecret(s.db, &node, secret); err != nil {
		// L-01: the compensating delete can itself fail and leave a node row
		// without a usable secret, so report it instead of discarding it.
		if delErr := s.db.Delete(&node).Error; delErr != nil {
			log.Errorf("create node: rollback of node %d failed after secret encryption error, a node row without a valid secret may remain: %v", node.ID, delErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "节点凭据加密失败"})
		return
	}
	// The clear-text Secret is deliberately returned only in this creation reply.
	c.JSON(http.StatusOK, gin.H{"node": toPublicNode(node), "secret": secret})
}

func (s *AdminServer) handleUpdateNode(c *gin.Context) {
	id := c.Param("id")
	if id == "999999" {
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Name != "" {
			var cfg database.Config
			if err := s.db.Where("`key` = ?", "site_title").Assign(database.Config{Value: req.Name}).FirstOrCreate(&cfg, database.Config{Key: "site_title"}).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "主节点名称更新成功"})
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Address     string   `json:"address"`
		Port        *int     `json:"port"`
		TrafficRate *float64 `json:"traffic_rate"`
		WSEnabled   *bool    `json:"ws_enabled"`
		WSPath      string   `json:"ws_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var node database.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	updates := map[string]interface{}{}
	// L-02: apply the same validators as the create path; previously an update
	// could store a name or address that create would have rejected.
	if req.Name != "" {
		if err := validateNodeName(req.Name); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["name"] = req.Name
	}
	if req.Address != "" {
		if err := validateNodeAddress(req.Address); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["address"] = req.Address
	}
	if req.Port != nil {
		if *req.Port < 1 || *req.Port > 65535 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "端口必须在 1-65535 范围内"})
			return
		}
		updates["port"] = *req.Port
	}
	if req.TrafficRate != nil {
		if err := validateTrafficRate(*req.TrafficRate); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "流量倍率必须大于 0 且不超过 1000"})
			return
		}
		updates["traffic_rate"] = *req.TrafficRate
	}
	if req.WSEnabled != nil {
		updates["ws_enabled"] = *req.WSEnabled
	}
	if req.WSPath != "" {
		path := req.WSPath
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		if err := validateWSPath(path); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["ws_path"] = path
	}
	if err := s.db.Model(&node).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新节点失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (s *AdminServer) handleRotateNodeSecret(c *gin.Context) {
	id := c.Param("id")
	if id == "999999" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "主节点没有 Worker 通信密钥"})
		return
	}
	var node database.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成节点通信密钥"})
		return
	}
	secret := hex.EncodeToString(b)
	if err := database.SetNodeSecret(s.db, &node, secret); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "节点通信密钥轮换失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"node": toPublicNode(node), "secret": secret, "message": "通信密钥已轮换；请立即更新对应 Worker 配置并重启服务"})
}

func (s *AdminServer) handleDeleteNode(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	var node database.Node
	if err := s.db.First(&node, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	if err := s.db.Delete(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除节点失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "已删除"})
}

// ─── 从节点心跳与数据同步接口 ───────────────────────────

func (s *AdminServer) handleNodeSync(c *gin.Context) {
	secret := c.GetHeader("X-Node-Secret")
	if secret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少通信密钥"})
		return
	}
	node, err := database.NodeBySecret(s.db, secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的通信密钥"})
		return
	}
	now := time.Now()
	node.LastHeartbeat = &now
	node.Status = 1
	clientIP := c.ClientIP()
	if clientIP != "" && clientIP != "::1" && clientIP != "127.0.0.1" {
		node.DetectedIP = clientIP
	}
	if err := s.db.Save(&node).Error; err != nil {
		log.Errorf("heartbeat: save node %d: %v", node.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "心跳信息更新失败"})
		return
	}

	var req struct {
		Traffic map[string]struct {
			Up   uint64 `json:"up"`
			Down uint64 `json:"down"`
		} `json:"traffic"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && len(req.Traffic) > 0 {
		// Worker retries reuse X-Node-Sync-ID. Reject traffic without this key:
		// accepting legacy unkeyed reports would reintroduce duplicate charging.
		syncID := c.GetHeader("X-Node-Sync-ID")
		if syncID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "缺少流量同步幂等键"})
			return
		}
		if len(syncID) > 64 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的流量同步幂等键"})
			return
		}
		// Persist the key and traffic update in the same transaction so a lost HTTP
		// response cannot double-charge users. Validate only newly accepted batches:
		// an already-receipted retry must remain successful even if the node rate was
		// changed after the original commit.
		if err := s.db.Transaction(func(tx *gorm.DB) error {
			receipt := database.NodeSyncReceipt{NodeID: node.ID, SyncID: syncID}
			result := tx.Where("node_id = ? AND sync_id = ?", node.ID, syncID).FirstOrCreate(&receipt)
			if result.Error != nil {
				return result.Error
			}
			if result.RowsAffected == 0 {
				// This exact accepted batch has already been accounted for.
				return nil
			}

			increments := make(map[string]trafficIncrement, len(req.Traffic))
			for hash, traffic := range req.Traffic {
				increment, err := newTrafficIncrement(traffic.Up, traffic.Down, node.TrafficRate)
				if err != nil {
					return err
				}
				increments[hash] = increment
			}
			for hash, increment := range increments {
				if err := persistTrafficIncrement(tx, hash, increment); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			if isTrafficValueError(err) {
				log.Warnf("node sync: rejected invalid traffic batch for node %d: %v", node.ID, err)
				c.JSON(http.StatusBadRequest, gin.H{"error": "无效的流量数据"})
				return
			}
			log.Error("node sync: failed to persist traffic batch:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "流量同步失败"})
			return
		}
	}

	var users []database.User
	if err := s.db.Where("status = ?", 0).Find(&users).Error; err != nil {
		log.Errorf("node sync: list active users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取有效用户失败"})
		return
	}
	validHashes := []string{}
	for _, u := range users {
		if u.ExpiryTime != nil && !u.ExpiryTime.IsZero() && u.ExpiryTime.Before(now) {
			continue
		}
		if u.Quota > 0 && u.Used >= u.Quota {
			continue
		}
		if u.Hash != "" {
			validHashes = append(validHashes, u.Hash)
		}
	}
	c.JSON(http.StatusOK, gin.H{"users": validHashes})
}

// handleNodeHeartbeat 从节点独立心跳上报（与数据同步解耦，30s 一次轻量 ping）
func (s *AdminServer) handleNodeHeartbeat(c *gin.Context) {
	secret := c.GetHeader("X-Node-Secret")
	if secret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少通信密钥"})
		return
	}
	node, err := database.NodeBySecret(s.db, secret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的通信密钥"})
		return
	}
	now := time.Now()
	node.LastHeartbeat = &now
	node.Status = 1
	if ip := c.ClientIP(); ip != "" && ip != "::1" && ip != "127.0.0.1" {
		node.DetectedIP = ip
	}
	if err := s.db.Save(&node).Error; err != nil {
		log.Errorf("heartbeat: save node %d: %v", node.ID, err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "心跳信息更新失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// ─── Hysteria2 协议管理 API ─────────────────────────

// handleHysteriaAuth verifies a user password for the Hysteria2 server.
// Called by hysteria2-server's HTTP auth backend on every new QUIC connection.
// Request: {"password": "clear-text-password"}
// Response: {"ok": true, "quota": ..., "used": ...} or {"ok": false}
func (s *AdminServer) handleHysteriaAuth(c *gin.Context) {
	// Hysteria2 HTTP auth 的请求体格式因版本而异，使用通用 map 兼容多种字段名
	var raw map[string]interface{}
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false})
		return
	}
	// 尝试 Hysteria2 可能使用的各种密码字段名
	password := ""
	for _, key := range []string{"password", "pass", "user", "username", "token", "auth"} {
		if v, ok := raw[key]; ok {
			if s, ok := v.(string); ok && s != "" {
				password = s
				break
			}
		}
	}
	if password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false})
		return
	}
	var user database.User
	if err := s.db.Where("hash = ?", common.SHA224String(password)).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false})
		return
	}
	if user.Status != 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false})
		return
	}
	now := time.Now()
	if user.ExpiryTime != nil && !user.ExpiryTime.IsZero() && user.ExpiryTime.Before(now) {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false})
		return
	}
	if user.Quota > 0 && user.Used >= user.Quota {
		c.JSON(http.StatusUnauthorized, gin.H{"ok": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":    true,
		"quota": user.Quota,
		"used":  user.Used,
	})
}

// handleGetHysteriaConfig returns current Hysteria2 protocol settings.
// F-1: distinguish ErrRecordNotFound (legitimate empty) from real DB failures.
// A DB error on any key aborts the whole request instead of returning empty
// strings that the panel would interpret as "not configured" and let the user
// overwrite with empty values on the next save.
func (s *AdminServer) handleGetHysteriaConfig(c *gin.Context) {
	keys := []string{"hysteria_enabled", "hysteria_port", "hysteria_up_mbps", "hysteria_down_mbps", "hysteria_masquerade_url"}
	result := gin.H{}
	for _, k := range keys {
		var cfg database.Config
		switch err := s.db.Where("`key` = ?", k).First(&cfg).Error; {
		case err == nil:
			result[k] = cfg.Value
		case errors.Is(err, gorm.ErrRecordNotFound):
			result[k] = ""
		default:
			log.Errorf("hysteria config: read %s from DB: %v", k, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "读取 Hysteria2 配置失败"})
			return
		}
	}
	c.JSON(http.StatusOK, result)
}

// handleSaveHysteriaConfig persists Hysteria2 protocol settings.
func (s *AdminServer) handleSaveHysteriaConfig(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	allowed := map[string]bool{
		"hysteria_enabled":        true,
		"hysteria_port":           true,
		"hysteria_up_mbps":        true,
		"hysteria_down_mbps":      true,
		"hysteria_masquerade_url": true,
	}
	// L-01: persist all accepted keys in one transaction and report failures.
	// Previously a failed upsert returned "已保存" while nothing was written,
	// and a partial failure could leave port/bandwidth settings inconsistent.
	err := s.db.Transaction(func(tx *gorm.DB) error {
		for k, v := range req {
			if !allowed[k] {
				continue
			}
			if err := tx.Where("`key` = ?", k).
				Assign(database.Config{Value: v}).
				FirstOrCreate(&database.Config{Key: k}).Error; err != nil {
				return fmt.Errorf("save %s: %w", k, err)
			}
		}
		return nil
	})
	if err != nil {
		log.Errorf("hysteria settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Hysteria2 配置保存失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Hysteria2 配置已保存"})
}
