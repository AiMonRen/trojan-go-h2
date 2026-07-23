package webserver

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/voidluo/trojan-go/internal/database"
	"gopkg.in/yaml.v3"
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
	var req struct {
		Enabled *bool   `json:"enabled"`
		Config  *string `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
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

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析配置文件失败"})
		return
	}

	if req.Config != nil && *req.Config != "" {
		var newWs map[string]any
		if err := yaml.Unmarshal([]byte(*req.Config), &newWs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 YAML 配置内容"})
			return
		}
		cfg["websocket"] = newWs

		enabled := false
		if val, ok := newWs["enabled"].(bool); ok {
			enabled = val
		}
		s.wsEnabled = enabled
		req.Enabled = &enabled // 同步给下方 modifyYamlField 使用
	} else if req.Enabled != nil {
		wsVal, ok := cfg["websocket"]
		if !ok {
			wsVal = make(map[string]any)
			cfg["websocket"] = wsVal
		}
		var ws map[string]any
		if wsMap, ok := wsVal.(map[string]any); ok {
			ws = wsMap
		} else if wsAny, ok2 := wsVal.(map[any]any); ok2 {
			ws = make(map[string]any)
			for k, v := range wsAny {
				if ks, ok3 := k.(string); ok3 {
					ws[ks] = v
				}
			}
			cfg["websocket"] = ws
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "配置文件中的 websocket 格式不正确"})
			return
		}
		ws["enabled"] = *req.Enabled
		s.wsEnabled = *req.Enabled
	}

	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 enabled 参数"})
		return
	}

	newContent, err := modifyYamlField(string(data), "websocket", "enabled", *req.Enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改配置文件失败"})
		return
	}

	tmpFile := targetPath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入临时配置文件失败"})
		return
	}
	if err := os.Rename(tmpFile, targetPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重命名配置文件失败"})
		return
	}

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
	s.db.Where("`key` IN ?", publicSettingKeyList()).Find(&cfgs)
	res := make(map[string]string, len(cfgs)+2)
	for _, v := range cfgs {
		res[v.Key] = v.Value
	}
	var adminUsername database.Config
	if s.db.Where("`key` = ?", "admin_username").First(&adminUsername).Error == nil && adminUsername.Value != "" {
		res["admin_username"] = adminUsername.Value
	} else {
		res["admin_username"] = s.configUser
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
	for key, value := range req {
		if !publicSettingKeys[key] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "设置包含受保护或不支持的字段: " + key})
			return
		}
		if err := s.db.Save(&database.Config{Key: key, Value: value}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "设置保存失败"})
			return
		}
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
	if req.Username != "" {
		if err := s.db.Save(&database.Config{Key: "admin_username", Value: req.Username}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "管理员用户名保存失败"})
			return
		}
		s.invalidateAdminCache()
	}
	if req.Password != "" {
		if err := database.SetAdminPassword(s.db, req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "管理员密码保存失败"})
			return
		}
		newJWTSecret, err := database.RotateJWTSecret(s.db)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "会话密钥轮换失败"})
			return
		}
		s.jwtSecret = newJWTSecret
		s.lastActiveNano.Store(0)
		s.invalidateAdminCache()
	}
	c.JSON(http.StatusOK, gin.H{"message": "管理员凭据已更新，请重新登录"})
}

func (s *AdminServer) verifyJWT(ts string) (*jwt.Token, error) {
	return jwt.Parse(ts, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
}
