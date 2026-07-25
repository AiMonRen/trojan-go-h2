package webserver

import (
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
)

// TestScheduledTrafficResetClearsCountersAndMarksMonth covers L-01 for the
// automatic reset worker: the update result is now checked and the month marker
// is written in the same transaction, so the reset is both observable and
// idempotent within a month.
func TestScheduledTrafficResetClearsCountersAndMarksMonth(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "reset.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	srv := &AdminServer{db: db}

	today := time.Now().Day()
	if err := db.Save(&database.Config{Key: "traffic_reset_day", Value: strconv.Itoa(today)}).Error; err != nil {
		t.Fatalf("set reset day: %v", err)
	}
	users := []database.User{
		{Username: "a", Hash: "hash-a", Used: 100, Upload: 60, Download: 40, Quota: -1},
		{Username: "b", Hash: "hash-b", Used: 300, Upload: 100, Download: 200, Quota: -1},
	}
	for i := range users {
		if err := db.Create(&users[i]).Error; err != nil {
			t.Fatalf("create user: %v", err)
		}
	}

	srv.runScheduledTrafficReset()

	var stored []database.User
	if err := db.Find(&stored).Error; err != nil {
		t.Fatalf("read users: %v", err)
	}
	for _, u := range stored {
		if u.Used != 0 || u.Upload != 0 || u.Download != 0 {
			t.Fatalf("user %s counters not cleared: used=%d up=%d down=%d",
				u.Username, u.Used, u.Upload, u.Download)
		}
	}

	var marker database.Config
	if err := db.Where("`key` = ?", "last_reset_month").First(&marker).Error; err != nil {
		t.Fatalf("last_reset_month not recorded: %v", err)
	}
	if want := time.Now().Format("2006-01"); marker.Value != want {
		t.Fatalf("last_reset_month = %q, want %q", marker.Value, want)
	}

	// A second run in the same month must be a no-op: re-dirty the counters and
	// confirm they survive.
	if err := db.Model(&database.User{}).Where("1 = 1").
		Updates(map[string]any{"used": 7, "upload": 3, "download": 4}).Error; err != nil {
		t.Fatalf("re-dirty counters: %v", err)
	}
	srv.runScheduledTrafficReset()

	stored = nil
	if err := db.Find(&stored).Error; err != nil {
		t.Fatalf("read users: %v", err)
	}
	for _, u := range stored {
		if u.Used != 7 {
			t.Fatalf("second reset in the same month must be skipped, user %s used=%d", u.Username, u.Used)
		}
	}
}

// TestScheduledTrafficResetSkipsInvalidConfig verifies the worker refuses to act
// on a malformed traffic_reset_day instead of silently treating it as 0.
func TestScheduledTrafficResetSkipsInvalidConfig(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "reset.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	srv := &AdminServer{db: db}

	if err := db.Save(&database.Config{Key: "traffic_reset_day", Value: "not-a-day"}).Error; err != nil {
		t.Fatalf("set reset day: %v", err)
	}
	if err := db.Create(&database.User{Username: "a", Hash: "hash-a", Used: 100, Quota: -1}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	srv.runScheduledTrafficReset()

	var user database.User
	if err := db.Where("username = ?", "a").First(&user).Error; err != nil {
		t.Fatalf("read user: %v", err)
	}
	if user.Used != 100 {
		t.Fatalf("counters must be untouched on invalid config, used=%d", user.Used)
	}
	var marker database.Config
	if err := db.Where("`key` = ?", "last_reset_month").First(&marker).Error; err == nil && marker.Value != "" {
		t.Fatalf("last_reset_month must not be written on invalid config, got %q", marker.Value)
	}
}
