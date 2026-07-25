package webserver

import (
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
)

func (s *AdminServer) receiptCleanupWorker() {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			now := time.Now()
			deleted, err := database.CleanupExpiredNodeSyncReceipts(s.db, now)
			if err != nil {
				log.Errorf("cleanup node sync receipts: %v", err)
			} else if deleted > 0 {
				log.Infof("cleaned up %d expired node sync receipts", deleted)
			}
			deleted, err = database.CleanupExpiredDataPlaneSyncReceipts(s.db, now)
			if err != nil {
				log.Errorf("cleanup data-plane sync receipts: %v", err)
			} else if deleted > 0 {
				log.Infof("cleaned up %d expired data-plane sync receipts", deleted)
			}
		case <-s.done:
			return
		}
	}
}
