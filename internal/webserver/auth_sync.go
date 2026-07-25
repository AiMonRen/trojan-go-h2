package webserver

import (
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
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
		if ok, runtimeUser := auth.AuthUser(user.Hash); ok {
			runtimeUser.SetIPLimit(user.IPLimit)
			continue
		}
		if err := auth.AddUser(user.Hash); err != nil {
			return err
		}
		if ok, runtimeUser := auth.AuthUser(user.Hash); ok {
			runtimeUser.SetIPLimit(user.IPLimit)
		}
	}
	for _, user := range auth.ListUsers() {
		if _, ok := valid[user.Hash()]; !ok {
			if err := auth.DelUser(user.Hash()); err != nil {
				log.Errorf("auth sync: remove stale user from data plane: %v", err)
			}
		}
	}
	return nil
}

// syncAuthAddUser propagates a newly activated user to every attached
// authenticator.
//
// L-01: AddUser/DelUser used to be called with the error discarded, so a
// data-plane refusal produced a silent split-brain between the database and the
// running proxy. The API result still reflects the committed database state
// (that write already succeeded), but the failure is now recorded so operators
// can see that a resync is required. context identifies the caller for logs.
func (s *AdminServer) syncAuthAddUser(context, hash string) {
	if hash == "" {
		return
	}
	for _, a := range s.auths {
		if err := a.AddUser(hash); err != nil {
			log.Errorf("%s: add user to data-plane authenticator failed, database and proxy are out of sync until the next resync: %v", context, err)
		}
	}
}

// syncAuthDelUser removes a user from every attached authenticator, reporting
// failures for the same reason as syncAuthAddUser.
func (s *AdminServer) syncAuthDelUser(context, hash string) {
	if hash == "" {
		return
	}
	for _, a := range s.auths {
		if err := a.DelUser(hash); err != nil {
			log.Errorf("%s: remove user from data-plane authenticator failed, the user may still be able to connect until the next resync: %v", context, err)
		}
	}
}
