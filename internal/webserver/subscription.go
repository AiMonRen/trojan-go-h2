package webserver

import (
	"crypto/sha256"
	"errors"
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
	// Unified Gateway deployments publish the Gateway port, never the private
	// Trojan data-plane port. WebSocket output is disabled until the Gateway has
	// an explicit Trojan-over-WebSocket adapter.
	gatewayPaths := []string{"gateway.yaml", "gateway.yml", "/etc/trojan-go/gateway.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		gatewayPaths = append([]string{filepath.Join(dir, "gateway.yaml"), filepath.Join(dir, "gateway.yml")}, gatewayPaths...)
	}
	for _, path := range gatewayPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg struct {
			Gateway struct {
				Listen string `yaml:"listen"`
			} `yaml:"gateway"`
			SSL struct {
				Cert string `yaml:"cert"`
			} `yaml:"ssl"`
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			continue
		}
		port := 443
		if _, portText, err := net.SplitHostPort(cfg.Gateway.Listen); err == nil {
			if parsed, err := strconv.Atoi(portText); err == nil && parsed > 0 {
				port = parsed
			}
		}
		domain := ""
		if cfg.SSL.Cert != "" {
			domain = filepath.Base(filepath.Dir(cfg.SSL.Cert))
		}
		return domain, port, false, ""
	}

	// Legacy embedded configuration fallback.
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

	// L-04: the published main-node address comes only from operator-controlled
	// configuration (gateway/embedded config first, then the canonical
	// serverDomain). c.Request.Host is attacker controlled and is deliberately
	// not used as a fallback — a poisoned Host header would otherwise end up in
	// every generated client config. Without a canonical domain we fail closed,
	// matching the share-link behaviour.
	mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
	if mainDomain == "" {
		mainDomain = s.serverDomain
	}
	if mainDomain == "" {
		log.Warn("subscription: canonical domain not configured, refusing to generate subscription")
		c.String(http.StatusInternalServerError, "服务域名未配置，请在面板设置中配置 canonical domain")
		return
	}
	cacheKey := strings.Join([]string{user.Hash, mainDomain, strconv.Itoa(mainPort), strconv.FormatBool(mainWs), mainWsPath}, "\x00")
	entry, ok := s.getSubscriptionCache(cacheKey)
	if !ok {
		// 拉取全部节点生成订阅；短期缓存避免高频轮询反复进行数据库读取和 YAML 拼装。
		var nodes []database.Node
		if err := s.db.Find(&nodes).Error; err != nil {
			c.String(http.StatusInternalServerError, "节点数据不可用，请稍后重试")
			return
		}
		entry = s.cacheSubscription(cacheKey, generateClashConfigMultiNode(s.db, user, nodes, mainDomain, mainPort, mainWs, mainWsPath))
	}

	c.Header("ETag", entry.ETag)
	c.Header("Cache-Control", "private, max-age=15")
	if c.GetHeader("If-None-Match") == entry.ETag {
		c.Status(http.StatusNotModified)
		return
	}
	c.Header("Content-Type", "text/yaml; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=clash-%s.yaml", sanitizeFilename(user.Username)))
	c.String(http.StatusOK, entry.Body)
}

// yamlScalar encodes a Go string as an inline YAML scalar that parses back to
// exactly the same string.
//
// KNOWN LIMITATION (M-09): the subscription document is still assembled as
// hand-written text rather than marshalled from a full Clash/Mihomo model. To
// keep that safe, every dynamic value goes through this function, and the
// quoting decision is delegated to gopkg.in/yaml.v3 instead of a hand-rolled
// escape table. The library owns the YAML 1.1/1.2 rules the previous ad-hoc
// implementation kept missing: number-like values (`443`, `0x1f`, `1_000`),
// `~`/`null`/`Null`/`NULL`, every case variant of `true`/`false`/`yes`/`no`/
// `on`/`off`, sexagesimals and dates, tabs, leading and trailing whitespace,
// and control characters.
//
// Multi-line and other values that yaml.v3 would render as a block scalar are
// re-encoded with an explicit double-quoted style so the result always stays
// on one line, which the surrounding hand-written template requires.
//
// generateClashConfigMultiNode additionally re-parses the finished document, so
// an encoding mistake here cannot ship a broken subscription silently.
func yamlScalar(value string) string {
	if encoded, ok := marshalInlineScalar(value, 0); ok {
		return encoded
	}
	if encoded, ok := marshalInlineScalar(value, yaml.DoubleQuotedStyle); ok {
		return encoded
	}
	// Unreachable in practice; fall back to a conservative quoted form rather
	// than emitting a raw value that could break the document structure.
	return strconv.Quote(value)
}

// marshalInlineScalar renders value with the requested yaml.v3 style and
// reports whether the result is usable as a single-line inline scalar.
func marshalInlineScalar(value string, style yaml.Style) (string, bool) {
	node := yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: style}
	out, err := yaml.Marshal(&node)
	if err != nil {
		return "", false
	}
	encoded := strings.TrimRight(string(out), "\n")
	if encoded == "" || strings.ContainsAny(encoded, "\n\r") {
		return "", false
	}
	return encoded, true
}

// yamlScalarRoundTrips reports whether the emitted scalar parses back to the
// original Go string. Used by the encoder's own tests and available for
// defensive checks.
func yamlScalarRoundTrips(value string) bool {
	var holder struct {
		V string `yaml:"v"`
	}
	if err := yaml.Unmarshal([]byte("v: "+yamlScalar(value)+"\n"), &holder); err != nil {
		return false
	}
	return holder.V == value
}

// sanitizeFilename removes characters unsafe for HTTP Content-Disposition
// filenames, replacing them with underscores.
func sanitizeFilename(name string) string {
	if name == "" {
		return "config"
	}
	replacer := strings.NewReplacer(
		"\r", "_", "\n", "_", "\x00", "_",
		`"`, "_", `'`, "_",
		"\\", "_", "/", "_", ":", "_",
	)
	safe := replacer.Replace(name)
	safe = strings.TrimSpace(safe)
	if safe == "" {
		return "config"
	}
	return safe
}

// ─── 多节点 Clash 订阅配置文件生成器 ─────────────────────

// generateClashConfigMultiNode renders the subscription document and then
// re-parses it as YAML before returning.
//
// The reverse parse is the safety net for the hand-written emission described
// in yamlScalar's KNOWN LIMITATION note. Operator-supplied `rules` and
// `rule-providers` fragments are pasted in verbatim, so a malformed fragment is
// the most likely cause of a broken document. When validation fails the
// document is regenerated with those fragments dropped (built-in defaults are
// used instead) so clients still receive a parsable configuration.
// generateClashConfigMultiNode renders the Clash/Mihomo subscription for one
// user and guarantees the result parses as YAML before it is served.
//
// KNOWN LIMITATION (M-09): the document is still assembled as hand-written text.
// What is mitigated today:
//   - every dynamic value (node name, server, password, SNI, WS path, ...) is
//     encoded by yamlScalar, which delegates quoting to gopkg.in/yaml.v3 instead
//     of a hand-rolled escape table;
//   - the finished document is re-parsed here (validateGeneratedYAML), so a
//     broken subscription cannot be served silently;
//   - if operator-supplied clash_rules / clash_rule_providers fragments make the
//     document unparsable, they are dropped and the built-in defaults are used.
//
// What is NOT fixed:
//   - `proxies` and `proxy-groups` are still emitted as text rather than
//     marshalled from typed structs, so the structural shape of the document
//     depends on this template being correct;
//   - operator `rules` / `rule-providers` fragments are inlined verbatim. They
//     are validated only by the post-render parse, which proves the document is
//     syntactically valid YAML — not that the fragment means what the operator
//     intended, and not that it cannot alter the effective routing.
//
// Intended next step (not done here): serialize `proxies` and `proxy-groups`
// through yaml.Marshal on typed structs while still inlining the operator
// fragments. That is a bounded change and does not require rewriting the whole
// document into a full Clash/Mihomo model.
func generateClashConfigMultiNode(db *gorm.DB, u database.User, nodes []database.Node, defaultDomain string, defaultPort int, defaultWS bool, defaultWSPath string) string {
	var cfgRules, cfgProviders database.Config
	rulesStr := ""
	// F-1: distinguish ErrRecordNotFound (legitimate empty) from real DB failures.
	// M-09 fallback mechanism ensures built-in defaults are used when DB is unavailable.
	switch err := db.Where("`key` = ?", "clash_rules").First(&cfgRules).Error; {
	case err == nil:
		rulesStr = cfgRules.Value
	case errors.Is(err, gorm.ErrRecordNotFound):
		// no custom rules configured, use built-in defaults
	default:
		log.Errorf("subscription: read clash_rules from DB: %v", err)
	}
	providersStr := ""
	switch err := db.Where("`key` = ?", "clash_rule_providers").First(&cfgProviders).Error; {
	case err == nil:
		providersStr = cfgProviders.Value
	case errors.Is(err, gorm.ErrRecordNotFound):
		// no custom providers configured, use built-in defaults
	default:
		log.Errorf("subscription: read clash_rule_providers from DB: %v", err)
	}

	config := renderClashConfigMultiNode(db, u, nodes, defaultDomain, defaultPort, defaultWS, defaultWSPath, rulesStr, providersStr)
	if err := validateGeneratedYAML(config); err == nil {
		return config
	} else if rulesStr == "" && providersStr == "" {
		// No operator fragments involved: the generator itself produced
		// invalid YAML. Surface it loudly; returning the text unchanged keeps
		// the previous behaviour rather than serving an empty subscription.
		log.Errorf("subscription: generated Clash config failed YAML validation for user %q: %v", u.Username, err)
		return config
	} else {
		log.Warnf("subscription: custom clash_rules/clash_rule_providers made the config unparsable for user %q (%v); falling back to built-in defaults", u.Username, err)
	}

	fallback := renderClashConfigMultiNode(db, u, nodes, defaultDomain, defaultPort, defaultWS, defaultWSPath, "", "")
	if err := validateGeneratedYAML(fallback); err != nil {
		log.Errorf("subscription: built-in Clash config template failed YAML validation for user %q: %v", u.Username, err)
	}
	return fallback
}

// validateGeneratedYAML parses the rendered document to prove it is
// syntactically valid YAML before it is handed to a client.
func validateGeneratedYAML(document string) error {
	var parsed any
	return yaml.Unmarshal([]byte(document), &parsed)
}

func renderClashConfigMultiNode(db *gorm.DB, u database.User, nodes []database.Node, defaultDomain string, defaultPort int, defaultWS bool, defaultWSPath string, rulesStr, providersStr string) string {
	var sb strings.Builder

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

	// ---- 读取全局配置（批量查询，减少 DB 往返） ----
	// F-1: on DB error, default to h2Enabled=false (safer) but log for observability.
	var hysteriaEnabledCfg database.Config
	h2Err := db.Where("`key` = ? AND value = ?", "hysteria_enabled", "true").First(&hysteriaEnabledCfg).Error
	h2Enabled := h2Err == nil
	if h2Err != nil && !errors.Is(h2Err, gorm.ErrRecordNotFound) {
		log.Errorf("subscription: read hysteria_enabled from DB: %v", h2Err)
	}

	// Batch-fetch the remaining subscription-scoped configs in one roundtrip.
	batchKeys := []string{"hysteria_port", "hysteria_up_mbps", "hysteria_down_mbps", "node_location", "clash_test_url", "sub_use_ws"}
	var batchCfgs []database.Config
	if err := db.Where("`key` IN ?", batchKeys).Find(&batchCfgs).Error; err != nil {
		log.Errorf("subscription: batch-read configs: %v", err)
	}
	batchMap := make(map[string]string, len(batchCfgs))
	for _, c := range batchCfgs {
		batchMap[c.Key] = c.Value
	}

	h2PortStr := "443"
	if v, ok := batchMap["hysteria_port"]; ok && v != "" {
		h2PortStr = v
	}
	h2UpStr := "100"
	if v, ok := batchMap["hysteria_up_mbps"]; ok && v != "" {
		h2UpStr = v
	}
	h2DownStr := "300"
	if v, ok := batchMap["hysteria_down_mbps"]; ok && v != "" {
		h2DownStr = v
	}

	// 当前订阅只发布 Trojan 与 Hysteria2。VLESS/Reality 和 TUIC 的底层预留
	// 配置保留在项目中，但不读取、不生成节点，也不参与客户端的路由选择。

	// 节点地区标签（如 "美国"）
	nodeLoc := "节点"
	if v, ok := batchMap["node_location"]; ok && v != "" {
		nodeLoc = v
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
	if v, ok := batchMap["clash_test_url"]; ok && v != "" && v != "0" {
		testURL = v
	}

	// 是否在 Clash 订阅中输出 WebSocket 配置（非 CDN 场景关掉省 1 RTT）
	useWS := defaultWS
	if v, ok := batchMap["sub_use_ws"]; ok && v == "false" {
		useWS = false
	}

	sb.WriteString("proxies:\n")

	// 收集当前订阅实际发布的双协议节点名。
	h2NodeNames := make([]string, 0, len(nodes)+1)
	tjNodeNames := make([]string, 0, len(nodes)+1)

	// ---- 1. 主节点 ----
	tjMainName := "tcp-" + nodeLoc
	h2MainName := "h-" + nodeLoc

	sb.WriteString(fmt.Sprintf("  - name: %s\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: false\n",
		yamlScalar(tjMainName), yamlScalar(defaultDomain), defaultPort, yamlScalar(u.Password), yamlScalar(defaultDomain)))
	if useWS && defaultWS {
		sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: %s\n      headers:\n        Host: %s\n",
			yamlScalar(defaultWSPath), yamlScalar(defaultDomain)))
	}
	sb.WriteString("\n")
	tjNodeNames = append(tjNodeNames, tjMainName)

	if h2Enabled {
		sb.WriteString(fmt.Sprintf("  - name: %s\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: false\n    up: %s\n    down: %s\n",
			yamlScalar(h2MainName), yamlScalar(defaultDomain), yamlScalar(h2PortStr), yamlScalar(u.Password), yamlScalar(defaultDomain),
			yamlScalar(h2UpStr+" Mbps"), yamlScalar(h2DownStr+" Mbps")))
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
		sb.WriteString(fmt.Sprintf("  - name: %s\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: false\n",
			yamlScalar(tjSlaveName), yamlScalar(node.Address), node.Port, yamlScalar(u.Password), yamlScalar(sniFor(node.Address, node.SNI))))
		if useWS && node.WSEnabled {
			sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: %s\n      headers:\n        Host: %s\n",
				yamlScalar(node.WSPath), yamlScalar(node.Address)))
		}
		sb.WriteString("\n")
		tjNodeNames = append(tjNodeNames, tjSlaveName)

		// 中继节点仅生成 TCP/Trojan 变体，Hysteria2/VLESS 不可经由 TCP 中转
		if isRelay {
			continue
		}

		if h2Enabled {
			h2SlaveName := "h-" + nodeName
			sb.WriteString(fmt.Sprintf("  - name: %s\n    type: hysteria2\n    server: %s\n    port: %s\n    password: %s\n    sni: %s\n    skip-cert-verify: false\n    up: %s\n    down: %s\n",
				yamlScalar(h2SlaveName), yamlScalar(node.Address), yamlScalar(h2PortStr), yamlScalar(u.Password), yamlScalar(sniFor(node.Address, node.SNI)),
				yamlScalar(h2UpStr+" Mbps"), yamlScalar(h2DownStr+" Mbps")))
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
		sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
	}
	for _, name := range h2NodeNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
	}

	sb.WriteString(fmt.Sprintf("  - name: \"♻️ 自动选择\"\n    type: url-test\n    url: %s\n    interval: 300\n    tolerance: 50\n    proxies:\n", yamlScalar(testURL)))
	for _, name := range tjNodeNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
	}
	for _, name := range h2NodeNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
	}

	sb.WriteString(fmt.Sprintf("  - name: \"TROJAN\"\n    type: url-test\n    url: %s\n    interval: 300\n    tolerance: 50\n    proxies:\n", yamlScalar(testURL)))
	for _, name := range tjNodeNames {
		sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
	}

	if h2Enabled && len(h2NodeNames) > 0 {
		sb.WriteString(fmt.Sprintf("  - name: \"HYSTERIA\"\n    type: fallback\n    url: %s\n    interval: 300\n    proxies:\n", yamlScalar(testURL)))
		for _, name := range h2NodeNames {
			sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
		}
	}

	for _, groupName := range []string{"🤖 AI 服务", "💻 AI 编程"} {
		// 服务专属组首选“跟随节点选择”：用户修改主选择组后，AI/编程服务立即继承，
		// 同时保留协议组和单节点作为手动覆盖选项。
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: select\n    proxies:\n      - \"🌐 节点选择\"\n      - \"TROJAN\"\n", groupName))
		for _, name := range tjNodeNames {
			sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
		}
		if h2Enabled && len(h2NodeNames) > 0 {
			sb.WriteString("      - \"HYSTERIA\"\n")
			for _, name := range h2NodeNames {
				sb.WriteString(fmt.Sprintf("      - %s\n", yamlScalar(name)))
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
