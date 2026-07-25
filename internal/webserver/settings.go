package webserver

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

func (s *AdminServer) handleGetWebSocket(c *gin.Context) {
	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取核心配置文件"})
		return
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析配置文件失败"})
		return
	}

	enabled := false
	wsVal, hasWs := cfg["websocket"]
	if hasWs {
		if ws, ok2 := wsVal.(map[string]any); ok2 {
			enabled, _ = ws["enabled"].(bool)
		} else if wsAny, ok3 := wsVal.(map[any]any); ok3 {
			enabled, _ = wsAny["enabled"].(bool)
		}
	}

	var wsYaml string
	if hasWs {
		if yamlData, err := yaml.Marshal(wsVal); err == nil {
			wsYaml = string(yamlData)
		}
	}
	if wsYaml == "" {
		wsYaml = "enabled: false\npath: /trojan-go\nhost: \"\""
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": enabled,
		"config":  wsYaml,
	})
}

func (s *AdminServer) handleUpdateWebSocket(c *gin.Context) {
	// Contract: this endpoint only toggles websocket.enabled. It deliberately
	// does NOT accept path/host (via a `config` blob) because only `enabled` is
	// ever persisted to config.yaml. Previously a `config` payload was echoed
	// back as success but its path/host fields were silently dropped on write,
	// leaving the API response inconsistent with disk. We now reject any attempt
	// to set path/host so callers get an explicit error instead of silent loss.
	var req struct {
		Enabled *bool   `json:"enabled"`
		Config  *string `json:"config"`
		Path    *string `json:"path"`
		Host    *string `json:"host"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}

	if req.Config != nil && *req.Config != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该接口仅支持切换 enabled，不支持通过 config 修改 path/host"})
		return
	}
	if req.Path != nil || req.Host != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "该接口仅支持切换 enabled，不支持修改 path/host"})
		return
	}
	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 enabled 参数"})
		return
	}

	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}
	var targetPath string
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			targetPath = p
			break
		}
	}
	if targetPath == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "未找到配置文件"})
		return
	}

	finalEnabled := *req.Enabled
	newContent, err := modifyYamlField(string(data), "websocket", "enabled", finalEnabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改配置文件失败"})
		return
	}

	// Write to a unique temp file in the target directory and atomic rename.
	// This prevents concurrent writers from corrupting each other and avoids
	// exposing sensitive configuration through weak permissions.
	info, statErr := os.Stat(targetPath)
	perm := os.FileMode(0o600)
	if statErr == nil {
		perm = info.Mode().Perm()
	}
	dir := filepath.Dir(targetPath)
	tmp, err := os.CreateTemp(dir, ".trojan-ws-*")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建临时配置文件失败"})
		return
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		_ = tmp.Close()
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置临时文件权限失败"})
		return
	}
	if _, err := tmp.WriteString(newContent); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入临时配置文件失败"})
		return
	}
	if err := tmp.Sync(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "同步临时配置文件失败"})
		return
	}
	if err := tmp.Close(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "关闭临时配置文件失败"})
		return
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重命名配置文件失败"})
		return
	}
	committed = true

	// Sync the directory to ensure the rename is durable before updating
	// the in-memory state. This guarantees memory and disk stay in sync
	// even if the process is killed immediately after the HTTP response.
	dirFd, _ := os.Open(dir)
	if dirFd != nil {
		_ = dirFd.Sync()
		_ = dirFd.Close()
	}
	s.wsEnabled = finalEnabled

	c.JSON(http.StatusOK, gin.H{"message": "WebSocket 配置更新成功"})
}

var publicSettingKeys = map[string]bool{
	"site_title": true, "clash_rules": true, "clash_rule_providers": true,
	"traffic_reset_day": true, "hysteria_enabled": true, "hysteria_port": true,
	"hysteria_up_mbps": true, "hysteria_down_mbps": true, "hysteria_masquerade_url": true,
	"reality_enabled": true, "reality_server_name": true, "reality_public_key": true,
	"reality_short_id": true, "tuic_enabled": true, "tuic_port": true,
	"tuic_congestion": true, "utls_fingerprint": true, "node_location": true,
	"clash_test_url": true, "sub_use_ws": true,
}

func (s *AdminServer) handleGetSettings(c *gin.Context) {
	var cfgs []database.Config
	// L-01: a failed read used to be indistinguishable from "no settings
	// stored", which makes the UI show defaults and silently overwrite real
	// values on the next save.
	if err := s.db.Where("`key` IN ?", publicSettingKeyList()).Find(&cfgs).Error; err != nil {
		log.Errorf("settings endpoint: read public settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取配置失败"})
		return
	}
	res := make(map[string]string, len(cfgs)+2)
	for _, v := range cfgs {
		res[v.Key] = v.Value
	}
	var adminUsername database.Config
	// L-01 (F-1): only a missing row may fall back to the config-file user.
	// A genuine query failure must surface as 500 instead of silently showing
	// the bootstrap username as if it were the stored one.
	res["admin_username"] = s.configUser
	switch err := s.db.Where("`key` = ?", "admin_username").First(&adminUsername).Error; {
	case err == nil:
		if adminUsername.Value != "" {
			res["admin_username"] = adminUsername.Value
		}
	case errors.Is(err, gorm.ErrRecordNotFound):
		// username never overridden through the panel, keep the config value
	default:
		log.Errorf("settings endpoint: read admin_username: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取配置失败"})
		return
	}
	res["is_node"] = strconv.FormatBool(s.isNode)
	c.JSON(http.StatusOK, res)
}

func publicSettingKeyList() []string {
	keys := make([]string, 0, len(publicSettingKeys))
	for key := range publicSettingKeys {
		keys = append(keys, key)
	}
	return keys
}

func (s *AdminServer) handleUpdateSettings(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// Validate every key before touching the database so a rejected field can
	// never leave earlier keys already persisted.
	for key := range req {
		if !publicSettingKeys[key] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "设置包含受保护或不支持的字段: " + key})
			return
		}
	}
	// F-2: the per-key Save loop used to commit each row on its own, so a
	// failure halfway through left a partially applied settings set (e.g. a new
	// clash_rules without the matching rule_providers). One transaction makes
	// the update all-or-nothing.
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		for key, value := range req {
			if err := tx.Save(&database.Config{Key: key, Value: value}).Error; err != nil {
				return fmt.Errorf("save setting %q: %w", key, err)
			}
		}
		return nil
	}); err != nil {
		log.Errorf("settings endpoint: update settings: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置保存失败"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "设置已更新"})
}

func (s *AdminServer) handleUpdateAdmin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	passwordChanged := req.Password != ""
	usernameChanged := req.Username != ""

	// Wrap username, password and JWT rotation in a single transaction.
	// If JWT rotation fails the password change rolls back, and vice versa.
	if usernameChanged || passwordChanged {
		tx := s.db.Begin()
		if tx.Error != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "开启管理员凭据事务失败"})
			return
		}
		if usernameChanged {
			if err := tx.Save(&database.Config{Key: "admin_username", Value: req.Username}).Error; err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "管理员用户名保存失败"})
				return
			}
		}
		if passwordChanged {
			if err := database.SetAdminPassword(tx, req.Password); err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "管理员密码保存失败"})
				return
			}
			newJWTSecret, err := database.RotateJWTSecret(tx)
			if err != nil {
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "会话密钥轮换失败"})
				return
			}
			if err := tx.Commit().Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "提交凭据事务失败"})
				return
			}
			// Only update in-memory secrets after the transaction is
			// committed successfully. setJWTSecret also drops every tracked
			// session so old tokens cannot be replayed.
			s.setJWTSecret(newJWTSecret)
		} else {
			if err := tx.Commit().Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "提交凭据事务失败"})
				return
			}
		}
		s.invalidateAdminCache()
	}
	c.JSON(http.StatusOK, gin.H{"message": "管理员凭据已更新，请重新登录"})
}

func (s *AdminServer) verifyJWT(ts string) (*jwt.Token, error) {
	return jwt.Parse(ts, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.getJWTSecret(), nil
	})
}
