package webserver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"gorm.io/gorm"
)

func (s *AdminServer) resetTrafficWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.runScheduledTrafficReset()
		case <-s.done:
			return
		}
	}
}

// runScheduledTrafficReset performs the monthly traffic reset when the
// configured reset day is reached.
//
// L-01: every database access reports its error instead of being discarded.
// The reset itself and the last_reset_month bookkeeping run in one transaction,
// so a crash cannot leave counters cleared while the month marker still points
// at the previous month (which would clear them again on the next tick).
func (s *AdminServer) runScheduledTrafficReset() {
	var cfg database.Config
	if err := s.db.Where("`key` = ?", "traffic_reset_day").First(&cfg).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Errorf("traffic reset worker: read traffic_reset_day: %v", err)
		}
		return
	}
	resetDay, err := strconv.Atoi(strings.TrimSpace(cfg.Value))
	if err != nil {
		log.Errorf("traffic reset worker: traffic_reset_day %q is not a number: %v", cfg.Value, err)
		return
	}
	if resetDay <= 0 || time.Now().Day() != resetDay {
		return
	}

	// 检查本月是否已重置过，防止一天内重置多次
	lastResetMonth := ""
	var cfgLast database.Config
	if err := s.db.Where("`key` = ?", "last_reset_month").First(&cfgLast).Error; err != nil {
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			log.Errorf("traffic reset worker: read last_reset_month: %v", err)
			// Without a reliable marker a reset could repeat within the same
			// day, so skip this tick and retry on the next one.
			return
		}
	} else {
		lastResetMonth = cfgLast.Value
	}

	currentMonth := time.Now().Format("2006-01")
	if lastResetMonth == currentMonth {
		return
	}

	log.Infof("自动重置日已达(%d号)，正在清空所有用户流量...", resetDay)
	err = s.db.Transaction(func(tx *gorm.DB) error {
		result := tx.Model(&database.User{}).
			Where("1 = 1").
			Updates(map[string]any{"used": 0, "upload": 0, "download": 0})
		if result.Error != nil {
			return fmt.Errorf("clear user traffic counters: %w", result.Error)
		}
		if err := tx.Save(&database.Config{Key: "last_reset_month", Value: currentMonth}).Error; err != nil {
			return fmt.Errorf("record last_reset_month: %w", err)
		}
		log.Infof("已清空 %d 个用户的流量计数", result.RowsAffected)
		return nil
	})
	if err != nil {
		log.Errorf("traffic reset worker: monthly reset failed, will retry on the next tick: %v", err)
	}
}

type collectedTraffic struct {
	user       statistic.User
	sent, recv uint64
}

type trafficSnapshot struct {
	up, down uint64
}

func (s *AdminServer) syncEmbeddedTrafficOnce() error {
	// Phase 1: snapshot all in-memory traffic counters without resetting them.
	//
	// The same user (hash) may be tracked by multiple authenticators, each with
	// its own counter. The database increment must be the aggregate across all
	// of them, but the later per-counter subtraction must use *that counter's
	// own* snapshot. Recording only the aggregate and subtracting it from every
	// counter would over-deduct (and underflow) whenever a hash appears in more
	// than one authenticator, so we keep both views.
	snapshots := make(map[string]trafficSnapshot)
	var perUser []collectedTraffic
	for _, auth := range s.auths {
		for _, user := range auth.ListUsers() {
			sent, recv := user.GetTraffic()
			if sent == 0 && recv == 0 {
				continue
			}
			hash := user.Hash()
			cur := snapshots[hash]
			up, err := addTrafficTotals(cur.up, recv)
			if err != nil {
				return fmt.Errorf("aggregate embedded upload traffic for user %s: %w", hash, err)
			}
			down, err := addTrafficTotals(cur.down, sent)
			if err != nil {
				return fmt.Errorf("aggregate embedded download traffic for user %s: %w", hash, err)
			}
			cur.up = up
			cur.down = down
			snapshots[hash] = cur
			// Keep this counter's own reading for an exact subtraction later.
			perUser = append(perUser, collectedTraffic{user: user, sent: sent, recv: recv})
		}
	}
	if len(snapshots) == 0 {
		return nil
	}

	// Phase 2: persist the snapshot to the database in a single transaction.
	// If this fails, in-memory counters are untouched — no data is lost and
	// the next sync cycle will retry with accumulated traffic.
	err := s.db.Transaction(func(tx *gorm.DB) error {
		increments := make(map[string]trafficIncrement, len(snapshots))
		for hash, snap := range snapshots {
			increment, err := newTrafficIncrement(snap.up, snap.down, 1)
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
	})
	if err != nil {
		return err
	}

	// Phase 3: the database commit succeeded. Subtract from each counter exactly
	// what was read from that counter in Phase 1 — never the cross-authenticator
	// aggregate. New traffic that arrived between Phase 1 and Phase 3 stays in
	// the counter and will be picked up next cycle.
	for _, collected := range perUser {
		collected.user.SubtractTraffic(collected.sent, collected.recv)
	}
	return nil
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
			if err := s.syncEmbeddedTrafficOnce(); err != nil {
				log.Errorf("persist embedded traffic batch: %v", err)
			}
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
