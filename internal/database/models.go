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
	ID          uint      `gorm:"primaryKey" json:"id"`               // ID 必须显式标记为 id 供前端调用
	CreatedAt   time.Time `json:"created_at"`
	Username    string    `json:"username"`                           // 用户名/备注，方便管理区别人
	Hash        string    `gorm:"uniqueIndex;not null;size:255" json:"hash"`   // Trojan 密码的 SHA224 哈希值
	Password    string    `json:"password"`                           // 明文密码（方便管理端查看和分发）
	Quota       int64     `gorm:"default:-1" json:"quota"`            // 流量限额 (字节, -1 为无限)
	Used        int64     `gorm:"default:0" json:"used"`              // 已用总流量
	Upload      int64     `gorm:"default:0" json:"upload"`            // 上传
	Download    int64     `gorm:"default:0" json:"download"`          // 下载
	ExpiryTime  *time.Time `json:"expiry_time"`                       // 过期时间
	IPLimit     int       `gorm:"default:0" json:"ip_limit"`          // IP 限制数目
	Status      int       `gorm:"default:0" json:"status"`            // 0: 正常, 1: 禁用
}

// Config 全局管理配置模型
type Config struct {
	Key   string `gorm:"primaryKey;size:255"`
	Value string
}

// Node 代理节点模型
type Node struct {
	ID            uint       `gorm:"primaryKey" json:"id"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Name          string     `gorm:"size:255;not null" json:"name"`       // 节点名称，如 "香港 01"
	Address       string     `gorm:"size:255;not null" json:"address"`    // 节点对外地址 (域名/IP)
	DetectedIP    string     `gorm:"size:64" json:"detected_ip"`          // 自动检测到的心跳来源 IP
	Port          int        `gorm:"default:443" json:"port"`             // 对外端口
	Secret        string     `gorm:"size:255;not null;uniqueIndex" json:"secret"` // 节点通信密钥
	Status        int        `gorm:"default:0" json:"status"`             // 0: 离线, 1: 在线
	LastHeartbeat *time.Time `json:"last_heartbeat"`                      // 上次心跳时间
	TrafficRate   float64    `gorm:"default:1.0" json:"traffic_rate"`     // 流量结算倍率

	// Clash 订阅所需参数
	WSEnabled     bool       `gorm:"default:false" json:"ws_enabled"`     // 是否启用 Websocket
	WSPath        string     `gorm:"size:255;default:'/trojan-go'" json:"ws_path"` // Websocket 路径
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
	err = db.AutoMigrate(&User{}, &Config{}, &Node{})
	if err != nil {
		return nil, err
	}

	// 初始化默认配置
	defaultRules := `  - RULE-SET,reject,REJECT
  - RULE-SET,applications,DIRECT
  - DOMAIN,clash.razord.top,DIRECT
  - DOMAIN,yacd.haishan.me,DIRECT
  - RULE-SET,private,DIRECT
  - DOMAIN-SUFFIX,jsdelivr.net,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - DOMAIN-SUFFIX,googleusercontent.com,PROXY
  - DOMAIN-SUFFIX,gstatic.com,PROXY
  - DOMAIN-SUFFIX,googlevideo.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - DOMAIN-SUFFIX,ytimg.com,PROXY
  - RULE-SET,icloud,DIRECT
  - RULE-SET,apple,DIRECT
  - RULE-SET,google,PROXY
  - RULE-SET,proxy,PROXY
  - RULE-SET,direct,DIRECT
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve
  - RULE-SET,cncidr,DIRECT
  - RULE-SET,telegramcidr,PROXY
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,PROXY`

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
		{Key: "hysteria_port", Value: "8443"},
		{Key: "hysteria_up_mbps", Value: "100"},
		{Key: "hysteria_down_mbps", Value: "500"},
		{Key: "hysteria_masquerade_url", Value: "https://www.bilibili.com"},
		// Clash 订阅节点显示名称中的地区标签（如 "美国"）
		{Key: "node_location", Value: "节点"},
		// Clash 测试延迟的测速 URL（0=关闭 url-test）
		{Key: "clash_test_url", Value: "http://cp.cloudflare.com/generate_204"},
		// 订阅中是否输出 WebSocket 配置（非 CDN 场景建议关闭以省 1 RTT）
		{Key: "sub_use_ws", Value: "false"},
	}
	for _, seed := range seeds {
		db.FirstOrCreate(&Config{}, seed)
	}

	// 补丁：修正历史存量数据中的错误规则组名称及 Google 直连逻辑错误 (静默处理)
	var oldRule Config
	if db.Where("key = ? AND value LIKE ?", "clash_rules", "%MATCH,Trojan%").Limit(1).Find(&oldRule).RowsAffected > 0 {
		newVal := strings.ReplaceAll(oldRule.Value, "MATCH,Trojan", "MATCH,PROXY")
		db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
	}
	if db.Where("key = ? AND value LIKE ?", "clash_rules", "%- RULE-SET,google,DIRECT%").Limit(1).Find(&oldRule).RowsAffected > 0 {
		newVal := strings.ReplaceAll(oldRule.Value, "- RULE-SET,google,DIRECT", "- RULE-SET,google,PROXY")
		db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
	}
	if db.Where("key = ? AND value NOT LIKE ?", "clash_rules", "%jsdelivr.net%").Limit(1).Find(&oldRule).RowsAffected > 0 {
		newVal := strings.ReplaceAll(oldRule.Value, "- RULE-SET,private,DIRECT", "- RULE-SET,private,DIRECT\n  - DOMAIN-SUFFIX,jsdelivr.net,PROXY")
		db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
	}
	if db.Where("key = ? AND value NOT LIKE ?", "clash_rules", "%google.com,PROXY%").Limit(1).Find(&oldRule).RowsAffected > 0 {
		var googleRules string
		if strings.Contains(oldRule.Value, "  - MATCH,PROXY") {
			googleRules = `  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - DOMAIN-SUFFIX,googleusercontent.com,PROXY
  - DOMAIN-SUFFIX,gstatic.com,PROXY
  - DOMAIN-SUFFIX,googlevideo.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - DOMAIN-SUFFIX,ytimg.com,PROXY
  - MATCH,PROXY`
			newVal := strings.ReplaceAll(oldRule.Value, "  - MATCH,PROXY", googleRules)
			db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
		} else if strings.Contains(oldRule.Value, "- MATCH,PROXY") {
			googleRules = `  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - DOMAIN-SUFFIX,googleusercontent.com,PROXY
  - DOMAIN-SUFFIX,gstatic.com,PROXY
  - DOMAIN-SUFFIX,googlevideo.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - DOMAIN-SUFFIX,ytimg.com,PROXY
- MATCH,PROXY`
			newVal := strings.ReplaceAll(oldRule.Value, "- MATCH,PROXY", googleRules)
			db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
		}
	}
	if db.Where("key = ? AND value LIKE ?", "clash_rules", "%- RULE-SET,lancidr,DIRECT%").Limit(1).Find(&oldRule).RowsAffected > 0 {
		lanRules := `  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,100.64.0.0/10,DIRECT,no-resolve`
		newVal := strings.ReplaceAll(oldRule.Value, "  - RULE-SET,lancidr,DIRECT", lanRules)
		db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
	}

	// 补丁：修正历史存量数据中由于上次 lancidr 替换多出了 2 个空格（变成 4 个空格的 "    - IP-CIDR"）导致 Clash 解析错误的 Bug
	var badRule Config
	if db.Where("key = ? AND value LIKE ?", "clash_rules", "%    - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve%").Limit(1).Find(&badRule).RowsAffected > 0 {
		newVal := strings.ReplaceAll(badRule.Value, "    - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve", "  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
		db.Model(&Config{}).Where("key = ?", "clash_rules").Update("value", newVal)
	}

	// 补丁：从老用户的配置中移除冗余未使用的 rule-providers
	var oldProviders Config
	if db.Where("key = ?", "clash_rule_providers").First(&oldProviders).Error == nil {
		changed := false
		val := oldProviders.Value
		gfwStr := "\n\n  gfw:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt\"\n    path: ./ruleset/gfw.yaml\n    interval: 86400"
		if strings.Contains(val, gfwStr) {
			val = strings.ReplaceAll(val, gfwStr, "")
			changed = true
		} else {
			gfwStr2 := "  gfw:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/gfw.txt\"\n    path: ./ruleset/gfw.yaml\n    interval: 86400\n\n"
			if strings.Contains(val, gfwStr2) {
				val = strings.ReplaceAll(val, gfwStr2, "")
				changed = true
			}
		}
		gfStr := "\n\n  greatfire:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt\"\n    path: ./ruleset/greatfire.yaml\n    interval: 86400"
		if strings.Contains(val, gfStr) {
			val = strings.ReplaceAll(val, gfStr, "")
			changed = true
		} else {
			gfStr2 := "  greatfire:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/greatfire.txt\"\n    path: ./ruleset/greatfire.yaml\n    interval: 86400\n\n"
			if strings.Contains(val, gfStr2) {
				val = strings.ReplaceAll(val, gfStr2, "")
				changed = true
			}
		}
		tldStr := "\n\n  tld-not-cn:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt\"\n    path: ./ruleset/tld-not-cn.yaml\n    interval: 86400"
		if strings.Contains(val, tldStr) {
			val = strings.ReplaceAll(val, tldStr, "")
			changed = true
		} else {
			tldStr2 := "  tld-not-cn:\n    type: http\n    behavior: domain\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/tld-not-cn.txt\"\n    path: ./ruleset/tld-not-cn.yaml\n    interval: 86400\n\n"
			if strings.Contains(val, tldStr2) {
				val = strings.ReplaceAll(val, tldStr2, "")
				changed = true
			}
		}
		if strings.Contains(val, "  lancidr:") {
			lanStr := "\n\n  lancidr:\n    type: http\n    behavior: ipcidr\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt\"\n    path: ./ruleset/lancidr.yaml\n    interval: 86400"
			if strings.Contains(val, lanStr) {
				val = strings.ReplaceAll(val, lanStr, "")
				changed = true
			} else {
				lanStr2 := "  lancidr:\n    type: http\n    behavior: ipcidr\n    url: \"https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt\"\n    path: ./ruleset/lancidr.yaml\n    interval: 86400\n\n"
				if strings.Contains(val, lanStr2) {
					val = strings.ReplaceAll(val, lanStr2, "")
					changed = true
				}
			}
		}
		if changed {
			db.Model(&Config{}).Where("key = ?", "clash_rule_providers").Update("value", val)
		}
	}

	return db, nil
}
