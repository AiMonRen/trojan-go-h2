package webserver

import (
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/statistic"
	"gorm.io/gorm"
)

// SyncAuthenticatorFromDatabase refreshes the proxy data-plane authenticator
// from the existing database. It performs reads only, so admin-service remains
// the only master SQLite writer after service separation.
func SyncAuthenticatorFromDatabase(db *gorm.DB, auth statistic.Authenticator) error {
	var users []database.User
	if err := db.Where("status = ?", 0).Find(&users).Error; err != nil {
		return err
	}
	now := time.Now()
	valid := make(map[string]struct{}, len(users))
	for _, user := range users {
		if user.Hash == "" || (user.ExpiryTime != nil && !user.ExpiryTime.IsZero() && user.ExpiryTime.Before(now)) || (user.Quota > 0 && user.Used >= user.Quota) {
			continue
		}
		valid[user.Hash] = struct{}{}
		_ = auth.AddUser(user.Hash)
	}
	for _, user := range auth.ListUsers() {
		if _, ok := valid[user.Hash()]; !ok {
			_ = auth.DelUser(user.Hash())
		}
	}
	return nil
}
