package webserver

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

func (s *AdminServer) getMainNodeInfo() (string, int, bool, string) {
	// 默认回退值
	domain := ""
	port := 443
	wsEnabled := s.wsEnabled
	wsPath := s.wsPath

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
	if err == nil {
		var cfg map[string]any
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			// 1. 读取端口
			if lp, ok := cfg["local_port"].(int); ok {
				port = lp
			} else if lpFloat, ok := cfg["local_port"].(float64); ok {
				port = int(lpFloat)
			}

			// 2. 读取 SNI 域名
			if sslVal, ok := cfg["ssl"].(map[string]any); ok {
				if sni, ok2 := sslVal["sni"].(string); ok2 && sni != "" {
					domain = sni
				}
			} else if sslAny, ok := cfg["ssl"].(map[any]any); ok {
				if sni, ok2 := sslAny["sni"].(string); ok2 && sni != "" {
					domain = sni
				}
			}

			// 3. 读取 WebSocket 状态
			if wsVal, ok := cfg["websocket"].(map[string]any); ok {
				if en, ok2 := wsVal["enabled"].(bool); ok2 {
					wsEnabled = en
				}
				if path, ok2 := wsVal["path"].(string); ok2 {
					wsPath = path
				}
			} else if wsAny, ok := cfg["websocket"].(map[any]any); ok {
				if en, ok2 := wsAny["enabled"].(bool); ok2 {
					wsEnabled = en
				}
				if path, ok2 := wsAny["path"].(string); ok2 {
					wsPath = path
				}
			}
		}
	}
	return domain, port, wsEnabled, wsPath
}

func (s *AdminServer) getSubscriptionCache(key string) (subscriptionCacheEntry, bool) {
	s.subscriptionCacheMu.Lock()
	defer s.subscriptionCacheMu.Unlock()
	entry, ok := s.subscriptionCache[key]
	if !ok || !time.Now().Before(entry.ExpiresAt) {
		if ok {
			delete(s.subscriptionCache, key)
		}
		return subscriptionCacheEntry{}, false
	}
	return entry, true
}

func (s *AdminServer) invalidateSubscriptionCache() {
	s.subscriptionCacheMu.Lock()
	s.subscriptionCache = make(map[string]subscriptionCacheEntry)
	s.subscriptionCacheMu.Unlock()
}

func (s *AdminServer) invalidateSubscriptionAfterMutation() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			s.invalidateSubscriptionCache()
		}
		c.Next()
	}
}

func (s *AdminServer) cacheSubscription(key, body string) subscriptionCacheEntry {
	digest := sha256.Sum256([]byte(body))
	entry := subscriptionCacheEntry{
		Body:      body,
		ETag:      fmt.Sprintf("\"%x\"", digest),
		ExpiresAt: time.Now().Add(subscriptionCacheTTL),
	}
	s.subscriptionCacheMu.Lock()
	s.subscriptionCache[key] = entry
	s.subscriptionCacheMu.Unlock()
	return entry
}

func (s *AdminServer) handleSub(c *gin.Context) {
	if s.isNode {
		log.Warn("subscription request blocked on worker node")
		s.serveMaskPage(c)
		return
	}
	token := c.Query("token")
	if token == "" {
		c.String(http.StatusBadRequest, "Missing token")
		return
	}
	var user database.User
	if err := s.db.Where("hash = ? AND status = 0", token).First(&user).Error; err != nil {
		c.String(http.StatusNotFound, "Invalid token or user disabled")
		return
	}
	if user.ExpiryTime != nil && !user.ExpiryTime.IsZero() && user.ExpiryTime.Before(time.Now()) {
		c.String(http.StatusForbidden, "User expired")
		return
	}
	password, err := database.UserPassword(user)
	if err != nil || password == "" {
		log.Errorf("subscription: decrypt user credential id=%d: %v", user.ID, err)
		c.String(http.StatusInternalServerError, "Subscription credential unavailable")
		return
	}
	// The generator accepts the historical struct shape; this transient in-memory
	// assignment never persists or serializes the reusable password.
	user.Password = password
	domain, _, _ := net.SplitHostPort(c.Request.Host)
	if domain == "" {
		domain = c.Request.Host
	}

	mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
	if mainDomain == "" {
		mainDomain = domain
	}
	cacheKey := strings.Join([]string{user.Hash, mainDomain, strconv.Itoa(mainPort), strconv.FormatBool(mainWs), mainWsPath}, "\x00")
	entry, ok := s.getSubscriptionCache(cacheKey)
	if !ok {
		// 拉取全部节点生成订阅；短期缓存避免高频轮询反复进行数据库读取和 YAML 拼装。
		var nodes []database.Node
		s.db.Find(&nodes)
		entry = s.cacheSubscription(cacheKey, generateClashConfigMultiNode(s.db, user, nodes, mainDomain, mainPort, mainWs, mainWsPath))
	}

	c.Header("ETag", entry.ETag)
	c.Header("Cache-Control", "private, max-age=15")
	if c.GetHeader("If-None-Match") == entry.ETag {
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("Content-Type", "text/yaml; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=clash-%s.yaml", user.Username))
	c.String(http.StatusOK, entry.Body)
}

// ─── 多节点 Clash 订阅配置文件生成器 ─────────────────────

func generateClashConfigMultiNode(db *gorm.DB, u database.User, nodes []database.Node, defaultDomain string, defaultPort int, defaultWS bool, defaultWSPath string) string {
	var sb strings.Builder
	var cfgRules, cfgProviders database.Config
	rulesStr := ""
	if db.Where("`key` = ?", "clash_rules").First(&cfgRules).Error == nil {
		rulesStr = cfgRules.Value
	}
	providersStr := ""
	if db.Where("`key` = ?", "clash_rule_providers").First(&cfgProviders).Error == nil {
		providersStr = cfgProviders.Value
	}

	sb.WriteString("port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\n\n")
	sb.WriteString("dns:\n  enable: true\n  ipv6: false\n  listen: 0.0.0.0:53\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n  fallback:\n    - 8.8.8.8\n    - 1.1.1.1\n    - https://dns.google/dns-query\n  nameserver-policy:\n    'geosite:cn': 223.5.5.5\n    'github.com': 8.8.8.8\n    'cdn.jsdelivr.net': 119.29.29.29\n\n")
	sb.WriteString("tun:\n  enable: true\n  stack: gvisor\n  auto-route: true\n  auto-detect-interface: true\n\n")

	if providersStr != "" {
		if !strings.Contains(providersStr, "rule-providers:") {
			sb.WriteString("rule-providers:\n")
		}
		sb.WriteString(providersStr)
		sb.WriteString("\n\n")
	}

	// ---- 读取全局配置 ----
	getConfigValue := func(d *gorm.DB, key string) (string, error) {
		var c database.Config
		if err := d.Where("`key` = ?", key).First(&c).Error; err != nil {
			return "", err
		}
		return c.Value, nil
	}

	h2Enabled := db.Where("`key` = ? AND value = ?", "hysteria_enabled", "true").First(&database.Config{}).Error == nil

	h2PortStr := "443"
	if cfg, err := getConfigValue(db, "hysteria_port"); err == nil && cfg != "" {
		h2PortStr = cfg
	}
	h2UpStr := "100"
	if cfg, err := getConfigValue(db, "hysteria_up_mbps"); err == nil && cfg != "" {
		h2UpStr = cfg
	}
	h2DownStr := "300"
	if cfg, err := getConfigValue(db, "hysteria_down_mbps"); err == nil && cfg != "" {
		h2DownStr = cfg
	}

	// 当前订阅只发布 Trojan 与 Hysteria2。VLESS/Reality 和 TUIC 的底层预留
	// 配置保留在项目中，但不读取、不生成节点，也不参与客户端的路由选择。

	// 节点地区标签（如 "美国"）
	nodeLoc := "节点"
	if cfg, err := getConfigValue(db, "node_location"); err == nil && cfg != "" {
		nodeLoc = cfg
	}

	// sniFor 决定 SNI 字段：节点自定义 SNI 优先，否则用 Address（不合法 IP 需设 SNI）
	sniFor := func(addr, custom string) string {
		if custom != "" {
			return custom
		}
		return addr
	}

	// 测速 URL（默认用 Cloudflare 端点，比 gstatic 在国内快）
	testURL := "http://cp.cloudflare.com/generate_204"
	if cfg, err := getConfigValue(db, "clash_test_url"); err == nil && cfg != "" && cfg != "0" {
		testURL = cfg
	}

	// 是否在 Clash 订阅中输出 WebSocket 配置（非 CDN 场景关掉省 1 RTT）
	useWS := defaultWS
	if subWS, err := getConfigValue(db, "sub_use_ws"); err == nil && subWS == "false" {
		useWS = false
	}

	sb.WriteString("proxies:\n")

	// 收集当前订阅实际发布的双协议节点名。
	h2NodeNames := make([]string, 0, len(nodes)+1)
	tjNodeNames := make([]string, 0, len(nodes)+1)

	// ---- 1. 主节点 ----
	tjMainName := "tcp-" + nodeLoc
	h2MainName := "h-" + nodeLoc

	sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: false\n",
		tjMainName, defaultDomain, defaultPort, u.Password, defaultDomain))
	if useWS && defaultWS {
		sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: \"%s\"\n      headers:\n        Host: %s\n", defaultWSPath, defaultDomain))
	}
	sb.WriteString("\n")
	tjNodeNames = append(tjNodeNames, tjMainName)

	if h2Enabled {
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: false\n    up: \"%s Mbps\"\n    down: \"%s Mbps\"\n",
			h2MainName, defaultDomain, h2PortStr, u.Password, defaultDomain, h2UpStr, h2DownStr))
		sb.WriteString("\n")
		h2NodeNames = append(h2NodeNames, h2MainName)
	}

	// ---- 2. 从节点 ----
	for _, node := range nodes {
		nodeName := node.Name
		if nodeName == "" {
			nodeName = node.Address
		}
		isRelay := strings.Contains(nodeName, "(港转)") || strings.Contains(nodeName, "(转)")

		tjSlaveName := "tcp-" + nodeName
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: false\n",
			tjSlaveName, node.Address, node.Port, u.Password, sniFor(node.Address, node.SNI)))
		if useWS && node.WSEnabled {
			sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: \"%s\"\n      headers:\n        Host: %s\n", node.WSPath, node.Address))
		}
		sb.WriteString("\n")
		tjNodeNames = append(tjNodeNames, tjSlaveName)

		// 中继节点仅生成 TCP/Trojan 变体，Hysteria2/VLESS 不可经由 TCP 中转
		if isRelay {
			continue
		}

		if h2Enabled {
			h2SlaveName := "h-" + nodeName
			sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: false\n    up: \"%s Mbps\"\n    down: \"%s Mbps\"\n",
				h2SlaveName, node.Address, h2PortStr, u.Password, sniFor(node.Address, node.SNI), h2UpStr, h2DownStr))
			sb.WriteString("\n")
			h2NodeNames = append(h2NodeNames, h2SlaveName)
		}

	}

	// ---- 代理组：Trojan 为 AI/日常主力，Hysteria2 供视频、下载与 UDP 质量较好的网络使用 ----
	sb.WriteString("proxy-groups:\n")
	sb.WriteString("  - name: \"🌐 节点选择\"\n    type: select\n    proxies:\n      - \"♻️ 自动选择\"\n      - \"TROJAN\"\n")
	if h2Enabled && len(h2NodeNames) > 0 {
		sb.WriteString("      - \"HYSTERIA\"\n")
	}
	for _, name := range tjNodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}
	for _, name := range h2NodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	sb.WriteString(fmt.Sprintf("  - name: \"♻️ 自动选择\"\n    type: url-test\n    url: %s\n    interval: 300\n    tolerance: 50\n    proxies:\n", testURL))
	for _, name := range tjNodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}
	for _, name := range h2NodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	sb.WriteString(fmt.Sprintf("  - name: \"TROJAN\"\n    type: url-test\n    url: %s\n    interval: 300\n    tolerance: 50\n    proxies:\n", testURL))
	for _, name := range tjNodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	if h2Enabled && len(h2NodeNames) > 0 {
		sb.WriteString(fmt.Sprintf("  - name: \"HYSTERIA\"\n    type: fallback\n    url: %s\n    interval: 300\n    proxies:\n", testURL))
		for _, name := range h2NodeNames {
			sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
		}
	}

	for _, groupName := range []string{"🤖 AI 服务", "💻 AI 编程"} {
		// 服务专属组首选“跟随节点选择”：用户修改主选择组后，AI/编程服务立即继承，
		// 同时保留协议组和单节点作为手动覆盖选项。
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"\n      - \"TROJAN\"\n", groupName))
		for _, name := range tjNodeNames {
			sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
		}
		if h2Enabled && len(h2NodeNames) > 0 {
			sb.WriteString("      - \"HYSTERIA\"\n")
			for _, name := range h2NodeNames {
				sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
			}
		}
	}

	// 与 AI 服务一致：服务分组默认可“跟随节点选择”，但允许显式切至直连。
	sb.WriteString("  - name: \"Ⓜ️ 微软服务\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"\n      - DIRECT\n")
	sb.WriteString("  - name: \"🎯 全球直连\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"\n      - DIRECT\n")
	sb.WriteString("  - name: \"🐟 漏网之鱼\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"\n      - \"TROJAN\"\n      - DIRECT\n")

	if rulesStr != "" {
		sb.WriteString("\n")
		if !strings.Contains(rulesStr, "rules:") {
			sb.WriteString("rules:\n")
		}
		sb.WriteString(rulesStr)
	} else {
		sb.WriteString("\nrules:\n  - GEOIP,CN,🎯 全球直连\n  - MATCH,🐟 漏网之鱼")
	}
	sb.WriteString("\n")
	return sb.String()
}
