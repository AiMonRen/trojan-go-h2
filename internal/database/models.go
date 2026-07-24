package database

import (
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// User 代理用户模型
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"` // ID 必须显式标记为 id 供前端调用
	CreatedAt time.Time `json:"created_at"`
	Username  string    `json:"username"`                                  // 用户名/备注，方便管理区别人
	Hash      string    `gorm:"uniqueIndex;not null;size:255" json:"hash"` // Trojan 密码的 SHA224 哈希值
	// Password accepts legacy restore/create payloads only. Ordinary management
	// responses must use publicUser, which never includes this field.
	Password           string     `json:"password,omitempty"`
	PasswordCiphertext string     `gorm:"type:text" json:"-"`
	PasswordKeyID      string     `gorm:"size:64" json:"-"`
	Quota              int64      `gorm:"default:-1" json:"quota"`   // 流量限额 (字节, -1 为无限)
	Used               int64      `gorm:"default:0" json:"used"`     // 已用总流量
	Upload             int64      `gorm:"default:0" json:"upload"`   // 上传
	Download           int64      `gorm:"default:0" json:"download"` // 下载
	ExpiryTime         *time.Time `json:"expiry_time"`               // 过期时间
	IPLimit            int        `gorm:"default:0" json:"ip_limit"` // IP 限制数目
	Status             int        `gorm:"default:0" json:"status"`   // 0: 正常, 1: 禁用
}

// Config 全局管理配置模型
type Config struct {
	Key   string `gorm:"primaryKey;size:255"`
	Value string
}

// Node 代理节点模型
type Node struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	Name       string    `gorm:"size:255;not null" json:"name"`    // 节点名称，如 "香港 01"
	Address    string    `gorm:"size:255;not null" json:"address"` // 节点对外地址 (域名/IP)
	DetectedIP string    `gorm:"size:64" json:"detected_ip"`       // 自动检测到的心跳来源 IP
	Port       int       `gorm:"default:443" json:"port"`          // 对外端口
	// Secret is retained for legacy-row compatibility. The active credential is
	// encrypted and authenticated through SecretHash, never exposed as JSON.
	Secret           string     `gorm:"size:255;uniqueIndex" json:"-"`
	SecretCiphertext string     `gorm:"type:text" json:"-"`
	SecretHash       string     `gorm:"size:64;uniqueIndex" json:"-"`
	SecretKeyID      string     `gorm:"size:64" json:"-"`
	SecretRotatedAt  *time.Time `json:"-"`
	Status           int        `gorm:"default:0" json:"status"`         // 0: 离线, 1: 在线
	LastHeartbeat    *time.Time `json:"last_heartbeat"`                  // 上次心跳时间
	TrafficRate      float64    `gorm:"default:1.0" json:"traffic_rate"` // 流量结算倍率

	// Clash 订阅所需参数
	WSEnabled bool   `gorm:"default:false" json:"ws_enabled"`              // 是否启用 Websocket
	WSPath    string `gorm:"size:255;default:'/trojan-go'" json:"ws_path"` // Websocket 路径
	SNI       string `gorm:"size:255" json:"sni"`                          // TLS SNI 字段（空=使用 Address）
}

// NodeSyncReceipt stores the idempotency key for a traffic-reporting batch.
// NodeID + SyncID is unique so a worker retry cannot double-charge traffic.
type NodeSyncReceipt struct {
	ID        uint      `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"index"`
	NodeID    uint      `gorm:"not null;uniqueIndex:idx_node_sync_receipt"`
	SyncID    string    `gorm:"size:64;not null;uniqueIndex:idx_node_sync_receipt"`
}

// DataPlaneSyncReceipt stores accepted traffic batch IDs from the local
// standalone Trojan data-plane. SyncID is globally unique per master database.
type DataPlaneSyncReceipt struct {
	ID        uint      `gorm:"primaryKey"`
	CreatedAt time.Time `gorm:"index"`
	SyncID    string    `gorm:"size:64;not null;uniqueIndex"`
}

const (
	NodeSyncReceiptRetention      = 30 * 24 * time.Hour
	DataPlaneSyncReceiptRetention = 30 * 24 * time.Hour
)

// CleanupExpiredNodeSyncReceipts removes old idempotency receipts after their
// retry safety window. A 30-day retention keeps normal worker retry protection
// while preventing the receipt table from growing without bound.
func CleanupExpiredNodeSyncReceipts(db *gorm.DB, now time.Time) (int64, error) {
	if db == nil {
		return 0, nil
	}
	result := db.Where("created_at < ?", now.Add(-NodeSyncReceiptRetention)).Delete(&NodeSyncReceipt{})
	return result.RowsAffected, result.Error
}

// CleanupExpiredDataPlaneSyncReceipts bounds the local data-plane idempotency
// table while retaining the same retry-safety window as worker sync receipts.
func CleanupExpiredDataPlaneSyncReceipts(db *gorm.DB, now time.Time) (int64, error) {
	if db == nil {
		return 0, nil
	}
	result := db.Where("created_at < ?", now.Add(-DataPlaneSyncReceiptRetention)).Delete(&DataPlaneSyncReceipt{})
	return result.RowsAffected, result.Error
}

// prioritizeAIRules keeps explicit AI policies ahead of broad remote rule sets.
// Clash/Mihomo stops at the first matching rule, so a proxy rule set that includes
// anthropic.com or similar domains must not bypass the dedicated service group.
func prioritizeAIRules(rules string) string {
	lines := strings.Split(rules, "\n")
	aiRules := make([]string, 0)
	remaining := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(line, ",🤖 AI 服务") || strings.Contains(line, ",💻 AI 编程") {
			aiRules = append(aiRules, line)
			continue
		}
		remaining = append(remaining, line)
	}
	if len(aiRules) == 0 {
		return rules
	}

	insertAt := -1
	for i, line := range remaining {
		if strings.Contains(line, "RULE-SET,google,") || strings.Contains(line, "RULE-SET,proxy,") {
			insertAt = i
			break
		}
	}
	if insertAt == -1 {
		for i, line := range remaining {
			if strings.Contains(line, "MATCH,") {
				insertAt = i
				break
			}
		}
	}
	if insertAt == -1 {
		return rules
	}

	ordered := make([]string, 0, len(lines))
	ordered = append(ordered, remaining[:insertAt]...)
	ordered = append(ordered, aiRules...)
	ordered = append(ordered, remaining[insertAt:]...)
	return strings.Join(ordered, "\n")
}

// OpenReadOnly opens an existing deployment database without migrations,
// seed writes, or schema changes. It is used by standalone data-plane readers
// so admin-service remains the sole direct writer of the Master database.
func OpenReadOnly(dbPath string) (*gorm.DB, error) {
	isMySQL := strings.HasPrefix(dbPath, "mysql:")
	var dialector gorm.Dialector
	if isMySQL {
		dialector = mysql.Open(strings.TrimPrefix(dbPath, "mysql:"))
	} else {
		dialector = sqlite.Open(dbPath)
	}
	db, err := gorm.Open(dialector, &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		return nil, err
	}
	if !isMySQL {
		if err := db.Exec("PRAGMA query_only=ON;").Error; err != nil {
			return nil, err
		}
		if sqlDB, sqlErr := db.DB(); sqlErr == nil {
			// SQLite query_only is connection-scoped. A single pooled connection
			// guarantees every data-plane query remains on the protected session.
			sqlDB.SetMaxOpenConns(1)
			sqlDB.SetMaxIdleConns(1)
		}
	}
	return db, nil
}

// InitDb 初始化数据库
func InitDb(dbPath string) (*gorm.DB, error) {
	var dialector gorm.Dialector
	isMySQL := strings.HasPrefix(dbPath, "mysql:")
	if isMySQL {
		dsn := strings.TrimPrefix(dbPath, "mysql:")
		dialector = mysql.Open(dsn)
	} else {
		dialector = sqlite.Open(dbPath)
	}

	db, err := gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return nil, err
	}

	if !isMySQL {
		// 开启 WAL 模式以支持多进程高频读写安全（仅限于 SQLite）
		db.Exec("PRAGMA journal_mode=WAL;")
	}

	// 自动迁移模型
	err = db.AutoMigrate(&User{}, &Config{}, &Node{}, &NodeSyncReceipt{}, &DataPlaneSyncReceipt{})
	if err != nil {
		return nil, err
	}
	now := time.Now()
	if _, cleanupErr := CleanupExpiredNodeSyncReceipts(db, now); cleanupErr != nil {
		return nil, cleanupErr
	}
	if _, cleanupErr := CleanupExpiredDataPlaneSyncReceipts(db, now); cleanupErr != nil {
		return nil, cleanupErr
	}

	// 初始化默认配置
	defaultRules := `  - RULE-SET,reject,REJECT
  - RULE-SET,applications,DIRECT
  - DOMAIN,clash.razord.top,DIRECT
  - DOMAIN,yacd.haishan.me,DIRECT
  - RULE-SET,private,DIRECT

  # 国际 AI 服务：优先 Trojan，避免与视频/下载共用自动测速路径。
  - DOMAIN-SUFFIX,openai.com,🤖 AI 服务
  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 服务
  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 服务
  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 服务
  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务
  - DOMAIN-SUFFIX,claude.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,claudeusercontent.com,🤖 AI 服务
  - DOMAIN,generativelanguage.googleapis.com,🤖 AI 服务
  - DOMAIN,aiplatform.googleapis.com,🤖 AI 服务
  - DOMAIN,aistudio.google.com,🤖 AI 服务
  - DOMAIN,ai.google.dev,🤖 AI 服务
  - DOMAIN-SUFFIX,x.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,grok.com,🤖 AI 服务
  - DOMAIN-SUFFIX,mistral.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,openrouter.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,perplexity.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,poe.com,🤖 AI 服务
  - DOMAIN-SUFFIX,huggingface.co,🤖 AI 服务
  - DOMAIN-SUFFIX,hf.co,🤖 AI 服务
  - DOMAIN-SUFFIX,hf.space,🤖 AI 服务
  - DOMAIN-SUFFIX,replicate.com,🤖 AI 服务
  - DOMAIN-SUFFIX,replicate.delivery,🤖 AI 服务
  - DOMAIN-SUFFIX,together.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,together.xyz,🤖 AI 服务
  - DOMAIN-SUFFIX,groq.com,🤖 AI 服务
  - DOMAIN-SUFFIX,fireworks.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,cohere.ai,🤖 AI 服务
  - DOMAIN-SUFFIX,cohere.com,🤖 AI 服务

  # AI 编程与 IDE 依赖。
  - DOMAIN-SUFFIX,githubcopilot.com,💻 AI 编程
  - DOMAIN,copilot-proxy.githubusercontent.com,💻 AI 编程
  - DOMAIN,copilot-telemetry.githubusercontent.com,💻 AI 编程
  - DOMAIN-SUFFIX,cursor.com,💻 AI 编程
  - DOMAIN-SUFFIX,cursor.sh,💻 AI 编程
  - DOMAIN-SUFFIX,cursorapi.com,💻 AI 编程
  - DOMAIN-SUFFIX,codeium.com,💻 AI 编程
  - DOMAIN-SUFFIX,windsurf.com,💻 AI 编程
  - DOMAIN-SUFFIX,v0.dev,💻 AI 编程
  - DOMAIN-SUFFIX,bolt.new,💻 AI 编程
  - DOMAIN-SUFFIX,lovable.dev,💻 AI 编程
  - DOMAIN-SUFFIX,replit.com,💻 AI 编程
  - DOMAIN,daily-cloudcode-pa.googleapis.com,💻 AI 编程
  - DOMAIN,cloudcode-pa.googleapis.com,💻 AI 编程
  - DOMAIN,cloudcode.googleapis.com,💻 AI 编程
  - DOMAIN,oauth2.googleapis.com,💻 AI 编程

  # 国内 AI 与常见办公服务优先直连；微软组允许用户手工切换代理。
  - DOMAIN-SUFFIX,qwen.ai,🎯 全球直连
  - DOMAIN,dashscope.aliyuncs.com,🎯 全球直连
  - DOMAIN-SUFFIX,zhipuai.cn,🎯 全球直连
  - DOMAIN-SUFFIX,bigmodel.cn,🎯 全球直连
  - DOMAIN-SUFFIX,moonshot.cn,🎯 全球直连
  - DOMAIN-SUFFIX,kimi.com,🎯 全球直连
  - DOMAIN-SUFFIX,doubao.com,🎯 全球直连
  - DOMAIN-SUFFIX,volces.com,🎯 全球直连
  - DOMAIN-SUFFIX,xfyun.cn,🎯 全球直连
  - DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,office365.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,outlook.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,live.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,onedrive.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,sharepoint.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,azure.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,visualstudio.com,Ⓜ️ 微软服务
  - DOMAIN-SUFFIX,bing.com,Ⓜ️ 微软服务

  - DOMAIN-SUFFIX,github.com,🌐 节点选择
  - DOMAIN-SUFFIX,github.io,🌐 节点选择
  - DOMAIN-SUFFIX,githubassets.com,🌐 节点选择
  - DOMAIN-SUFFIX,githubusercontent.com,🌐 节点选择
  - DOMAIN-SUFFIX,jsdelivr.net,🌐 节点选择
  - DOMAIN-SUFFIX,google.com,🌐 节点选择
  - DOMAIN-SUFFIX,googleapis.com,🌐 节点选择
  - DOMAIN-SUFFIX,googleusercontent.com,🌐 节点选择
  - DOMAIN-SUFFIX,gstatic.com,🌐 节点选择
  - DOMAIN-SUFFIX,googlevideo.com,🌐 节点选择
  - DOMAIN-SUFFIX,youtube.com,🌐 节点选择
  - DOMAIN-SUFFIX,ytimg.com,🌐 节点选择
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,🌐 节点选择
  - RULE-SET,proxy,🌐 节点选择
  - RULE-SET,direct,DIRECT
  - IP-CIDR,192.168.0.0/16,🎯 全球直连,no-resolve
  - IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve
  - IP-CIDR,172.16.0.0/12,🎯 全球直连,no-resolve
  - IP-CIDR,127.0.0.0/8,🎯 全球直连,no-resolve
  - IP-CIDR,100.64.0.0/10,🎯 全球直连,no-resolve
  - IP-CIDR6,::1/128,🎯 全球直连,no-resolve
  - IP-CIDR6,fc00::/7,🎯 全球直连,no-resolve
  - IP-CIDR6,fe80::/10,🎯 全球直连,no-resolve
  - RULE-SET,cncidr,DIRECT
  - RULE-SET,telegramcidr,🌐 节点选择
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,🎯 全球直连
  - MATCH,🐟 漏网之鱼`

	defaultProviders := `  reject:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
    path: ./ruleset/reject.yaml
    interval: 86400

  icloud:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/icloud.txt"
    path: ./ruleset/icloud.yaml
    interval: 86400

  apple:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/apple.txt"
    path: ./ruleset/apple.yaml
    interval: 86400

  google:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/google.txt"
    path: ./ruleset/google.yaml
    interval: 86400

  proxy:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/proxy.yaml
    interval: 86400

  direct:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: ./ruleset/direct.yaml
    interval: 86400

  private:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/private.txt"
    path: ./ruleset/private.yaml
    interval: 86400

  telegramcidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/telegramcidr.txt"
    path: ./ruleset/telegramcidr.yaml
    interval: 86400

  cncidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400

  applications:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt"
    path: ./ruleset/applications.yaml
    interval: 86400`

	seeds := []Config{
		{Key: "site_title", Value: "Trojan-Go 管理面板"},
		{Key: "clash_rules", Value: defaultRules},
		{Key: "clash_rule_providers", Value: defaultProviders},
		{Key: "traffic_reset_day", Value: "0"},
		// Hysteria2 协议配置（QUIC/UDP 主力协议，Trojan 降级备用）
		{Key: "hysteria_enabled", Value: "false"},
		{Key: "hysteria_port", Value: "443"},
		{Key: "hysteria_up_mbps", Value: "100"},
		{Key: "hysteria_down_mbps", Value: "500"},
		{Key: "hysteria_masquerade_url", Value: "https://www.bilibili.com"},
		// VLESS + Reality 反封锁协议（偷合法网站 TLS 指纹，抵御 DPI 检测）
		{Key: "reality_enabled", Value: "false"},
		{Key: "reality_server_name", Value: "swdist.apple.com"},
		{Key: "reality_private_key", Value: ""}, // 空=部署时自动生成
		{Key: "reality_public_key", Value: ""},
		{Key: "reality_short_id", Value: "8b9a1c3d"},
		// TUIC 协议（QUIC/UDP，BBR 拥塞控制，Hysteria2 的高带宽备选）
		{Key: "tuic_enabled", Value: "false"},
		{Key: "tuic_port", Value: "9443"},
		{Key: "tuic_congestion", Value: "bbr"},
		// uTLS 指纹伪装（模拟 Chrome 浏览器的 TLS 握手特征）
		{Key: "utls_fingerprint", Value: "chrome"},
		// Clash 订阅节点显示名称中的地区标签（如 "美国"）
		{Key: "node_location", Value: "节点"},
		// Clash 测试延迟的测速 URL（0=关闭 url-test）
		{Key: "clash_test_url", Value: "http://cp.cloudflare.com/generate_204"},
		// 订阅中是否输出 WebSocket 配置（非 CDN 场景建议关闭以省 1 RTT）
		{Key: "sub_use_ws", Value: "false"},
	}
	for _, seed := range seeds {
		db.Where("key = ?", seed.Key).FirstOrCreate(&Config{Key: seed.Key, Value: seed.Value})
	}

	if err := RunMigrations(db); err != nil {
		return nil, err
	}

	return db, nil
}
