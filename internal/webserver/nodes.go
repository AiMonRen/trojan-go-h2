package webserver

import (
	"crypto/rand"
	"encoding/hex"
	"net"
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
	s.db.Find(&nodes)

	// 如果当前不是从节点（即为主节点），则将主节点自身作为虚拟节点加入列表头部
	if !s.isNode {
		mainNodeName := "主节点"
		var cfgTitle database.Config
		if s.db.Where("`key` = ?", "site_title").First(&cfgTitle).Error == nil && cfgTitle.Value != "" {
			mainNodeName = cfgTitle.Value
		}

		host := c.Request.Host
		domain, _, err := net.SplitHostPort(host)
		if err != nil {
			domain = host
		}

		mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
		if mainDomain == "" {
			mainDomain = domain
		}

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

	c.JSON(http.StatusOK, toPublicNodes(nodes))
}

func (s *AdminServer) handleAddNode(c *gin.Context) {
	var req struct {
		Name        string  `json:"name"`
		Address     string  `json:"address"`
		Port        int     `json:"port"`
		TrafficRate float64 `json:"traffic_rate"`
		WSEnabled   bool    `json:"ws_enabled"`
		WSPath      string  `json:"ws_path"`
		SNI         string  `json:"sni"`
		Secret      string  `json:"secret"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}
	if req.Name == "" || req.Address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "节点名称和地址不能为空"})
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
		Name: req.Name, Address: req.Address, Port: req.Port, TrafficRate: req.TrafficRate,
		WSEnabled: req.WSEnabled, WSPath: req.WSPath, SNI: req.SNI, Secret: pendingSecret,
	}
	if node.Port == 0 {
		node.Port = 443
	}
	if node.TrafficRate == 0 {
		node.TrafficRate = 1
	}
	if node.WSPath == "" {
		node.WSPath = "/trojan-go"
	}
	if err := s.db.Create(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := database.SetNodeSecret(s.db, &node, secret); err != nil {
		s.db.Delete(&node)
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
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Address != "" {
		updates["address"] = req.Address
	}
	if req.Port != nil {
		updates["port"] = *req.Port
	}
	if req.TrafficRate != nil {
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
	var node database.Node
	if s.db.First(&node, c.Param("id")).Error == nil {
		s.db.Delete(&node)
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
	s.db.Save(&node)

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
		// Persist the key and traffic update in the same transaction so a lost HTTP
		// response cannot double-charge users.
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

			for hash, t := range req.Traffic {
				total := int64(t.Up + t.Down)
				if node.TrafficRate != 1.0 {
					total = int64(float64(total) * node.TrafficRate)
				}
				if err := tx.Model(&database.User{}).Where("hash = ?", hash).Updates(map[string]interface{}{
					"upload":   gorm.Expr("upload + ?", int64(t.Up)),
					"download": gorm.Expr("download + ?", int64(t.Down)),
					"used":     gorm.Expr("used + ?", total),
				}).Error; err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			log.Error("node sync: failed to persist traffic batch:", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "流量同步失败"})
			return
		}
	}

	var users []database.User
	s.db.Where("status = ?", 0).Find(&users)
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
	s.db.Save(&node)
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
func (s *AdminServer) handleGetHysteriaConfig(c *gin.Context) {
	keys := []string{"hysteria_enabled", "hysteria_port", "hysteria_up_mbps", "hysteria_down_mbps", "hysteria_masquerade_url"}
	result := gin.H{}
	for _, k := range keys {
		var cfg database.Config
		if s.db.Where("`key` = ?", k).First(&cfg).Error == nil {
			result[k] = cfg.Value
		} else {
			result[k] = ""
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
	for k, v := range req {
		if !allowed[k] {
			continue
		}
		s.db.Where("`key` = ?", k).Assign(database.Config{Value: v}).FirstOrCreate(&database.Config{Key: k})
	}
	c.JSON(http.StatusOK, gin.H{"message": "Hysteria2 配置已保存"})
}
