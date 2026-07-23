package webserver

import (
	"fmt"
	"strconv"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gorm.io/gorm"
)

func (s *AdminServer) resetTrafficWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var cfg database.Config
			if s.db.Where("`key` = ?", "traffic_reset_day").First(&cfg).Error == nil {
				resetDay := 0
				fmt.Sscanf(cfg.Value, "%d", &resetDay)
				if resetDay > 0 && time.Now().Day() == resetDay {
					// 检查本月是否已重置过，防止一天内重置多次
					lastResetMonth := ""
					var cfgLast database.Config
					if s.db.Where("`key` = ?", "last_reset_month").First(&cfgLast).Error == nil {
						lastResetMonth = cfgLast.Value
					}
					currentMonth := time.Now().Format("2006-01")
					if lastResetMonth != currentMonth {
						log.Infof("自动重置日已达(%d号)，正在清空所有用户流量...", resetDay)
						s.db.Model(&database.User{}).Updates(map[string]interface{}{"used": 0, "upload": 0, "download": 0})
						s.db.Save(&database.Config{Key: "last_reset_month", Value: currentMonth})
					}
				}
			}
		case <-s.done:
			return
		}
	}
}

// trafficSyncWorker 定期将内存中的实时流量统计同步到数据库中
func (s *AdminServer) trafficSyncWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if len(s.auths) == 0 {
				continue
			}
			// 从所有认证器链路收集并合并流量
			trafficMap := make(map[string]struct{ up, down uint64 })
			for _, a := range s.auths {
				for _, st := range a.ListUsers() {
					hash := st.Hash()
					sent, recv := st.ResetTraffic()
					if sent == 0 && recv == 0 {
						continue
					}
					v := trafficMap[hash]
					v.up += recv   // 客户端上传 = 服务端接收
					v.down += sent // 客户端下载 = 服务端发送
					trafficMap[hash] = v
				}
			}

			if len(trafficMap) == 0 {
				select {
				case <-s.done:
					return
				default:
				}
				continue
			}

			// 开启事务，合并所有流量更新操作，防止碎片化 I/O 导致 SQLite 锁定
			s.db.Transaction(func(tx *gorm.DB) error {
				for hash, t := range trafficMap {
					tx.Model(&database.User{}).Where("hash = ?", hash).Updates(map[string]interface{}{
						"upload":   gorm.Expr("upload + ?", int64(t.up)),
						"download": gorm.Expr("download + ?", int64(t.down)),
						"used":     gorm.Expr("used + ?", int64(t.up+t.down)),
					})
				}
				return nil
			})
		case <-s.done:
			return
		}
	}
}

// ─── 流量格式化工具函数 ──────────────────────────────
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/float64(TB), 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/float64(GB), 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/float64(MB), 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/float64(KB), 'f', 2, 64) + " KB"
	default:
		return strconv.FormatUint(bytes, 10) + " B"
	}
}
