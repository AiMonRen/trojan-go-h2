package webserver

import (
	"fmt"
	"math"

	"github.com/voidluo/trojan-go/internal/database"
	"gorm.io/gorm"
)

const (
	maxTrafficCounter          int64   = 1<<63 - 1
	maxTrafficCounterExclusive float64 = 1 << 63
)

type trafficIncrement struct {
	Upload   int64
	Download int64
	Used     int64
}

type trafficValueError struct {
	reason string
}

func (e *trafficValueError) Error() string {
	return e.reason
}

func invalidTrafficValue(format string, args ...any) error {
	return &trafficValueError{reason: fmt.Sprintf(format, args...)}
}

func isTrafficValueError(err error) bool {
	_, ok := err.(*trafficValueError)
	return ok
}

func validateTrafficRate(rate float64) error {
	if err := database.ValidateTrafficRate(rate); err != nil {
		return invalidTrafficValue("%v", err)
	}
	return nil
}

func newTrafficIncrement(up, down uint64, rate float64) (trafficIncrement, error) {
	if err := validateTrafficRate(rate); err != nil {
		return trafficIncrement{}, err
	}
	if up > uint64(maxTrafficCounter) {
		return trafficIncrement{}, invalidTrafficValue("upload traffic exceeds int64 capacity")
	}
	if down > uint64(maxTrafficCounter) {
		return trafficIncrement{}, invalidTrafficValue("download traffic exceeds int64 capacity")
	}
	if up > uint64(maxTrafficCounter)-down {
		return trafficIncrement{}, invalidTrafficValue("total traffic exceeds int64 capacity")
	}

	total := up + down
	used := int64(total)
	if rate != 1 {
		scaled := float64(total) * rate
		if math.IsNaN(scaled) || math.IsInf(scaled, 0) || scaled < 0 || scaled >= maxTrafficCounterExclusive {
			return trafficIncrement{}, invalidTrafficValue("scaled traffic exceeds int64 capacity")
		}
		used = int64(scaled)
	}
	return trafficIncrement{Upload: int64(up), Download: int64(down), Used: used}, nil
}

func addTrafficTotals(current, delta uint64) (uint64, error) {
	if current > ^uint64(0)-delta {
		return 0, invalidTrafficValue("traffic aggregation exceeds uint64 capacity")
	}
	return current + delta, nil
}

func persistTrafficIncrement(tx *gorm.DB, hash string, increment trafficIncrement) error {
	if hash == "" || (increment.Upload == 0 && increment.Download == 0 && increment.Used == 0) {
		return nil
	}

	result := tx.Model(&database.User{}).
		Where("hash = ?", hash).
		Where("upload >= 0 AND upload <= ?", maxTrafficCounter-increment.Upload).
		Where("download >= 0 AND download <= ?", maxTrafficCounter-increment.Download).
		Where("used >= 0 AND used <= ?", maxTrafficCounter-increment.Used).
		Updates(map[string]any{
			"upload":   gorm.Expr("upload + ?", increment.Upload),
			"download": gorm.Expr("download + ?", increment.Download),
			"used":     gorm.Expr("used + ?", increment.Used),
		})
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected > 0 {
		return nil
	}

	var count int64
	if err := tx.Model(&database.User{}).Where("hash = ?", hash).Count(&count).Error; err != nil {
		return err
	}
	if count == 0 {
		// Unknown users may race with a user-list refresh. Preserve the existing
		// behavior of ignoring their traffic rather than failing the whole batch.
		return nil
	}
	return invalidTrafficValue("stored traffic counters cannot accept this increment")
}
