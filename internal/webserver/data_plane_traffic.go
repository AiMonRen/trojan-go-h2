package webserver

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gorm.io/gorm"
)

type dataPlaneTrafficValue struct {
	Up   uint64 `json:"up"`
	Down uint64 `json:"down"`
}

type dataPlaneTrafficRequest struct {
	SyncID  string                           `json:"sync_id"`
	Traffic map[string]dataPlaneTrafficValue `json:"traffic"`
}

// handleDataPlaneTraffic accepts only loopback-origin requests because its route
// is registered inside /internal/control/v1. SyncID and increments are written
// in the same transaction so a lost response can be retried without double use.
func (s *AdminServer) handleDataPlaneTraffic(c *gin.Context) {
	var request dataPlaneTrafficRequest
	if err := c.ShouldBindJSON(&request); err != nil || request.SyncID == "" || len(request.Traffic) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data-plane traffic batch"})
		return
	}
	if len(request.SyncID) > 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data-plane sync id"})
		return
	}
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		receipt := database.DataPlaneSyncReceipt{SyncID: request.SyncID}
		result := tx.Where("sync_id = ?", request.SyncID).FirstOrCreate(&receipt)
		if result.Error != nil {
			return result.Error
		}
		if result.RowsAffected == 0 {
			return nil
		}

		increments := make(map[string]trafficIncrement, len(request.Traffic))
		for hash, traffic := range request.Traffic {
			if hash == "" {
				continue
			}
			increment, err := newTrafficIncrement(traffic.Up, traffic.Down, 1)
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
	}); err != nil {
		if isTrafficValueError(err) {
			log.Warnf("rejected invalid data-plane traffic batch: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid data-plane traffic values"})
			return
		}
		log.Errorf("persist data-plane traffic batch: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "data-plane traffic persistence failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
