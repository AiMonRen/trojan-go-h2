package database

import (
	"testing"
	"time"
)

func TestOpenReadOnlyReadsExistingRowsAndRejectsWrites(t *testing.T) {
	path := t.TempDir() + "/database.db"
	writer, err := InitDb(path)
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	if err := writer.Create(&User{Username: "existing", Hash: "read-only-hash"}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if sqlDB, err := writer.DB(); err == nil {
		_ = sqlDB.Close()
	}

	reader, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("open read-only database: %v", err)
	}
	var user User
	if err := reader.Where("hash = ?", "read-only-hash").First(&user).Error; err != nil {
		t.Fatalf("read existing user: %v", err)
	}
	if err := reader.Create(&Config{Key: "must-not-write", Value: "x"}).Error; err == nil {
		t.Fatal("read-only database unexpectedly accepted a write")
	}
}

func TestCleanupExpiredDataPlaneSyncReceipts(t *testing.T) {
	db, err := InitDb(t.TempDir() + "/database.db")
	if err != nil {
		t.Fatalf("init database: %v", err)
	}
	now := time.Now().UTC()
	if err := db.Create(&DataPlaneSyncReceipt{SyncID: "expired-data-plane", CreatedAt: now.Add(-DataPlaneSyncReceiptRetention - time.Hour)}).Error; err != nil {
		t.Fatalf("create expired receipt: %v", err)
	}
	if err := db.Create(&DataPlaneSyncReceipt{SyncID: "current-data-plane", CreatedAt: now.Add(-DataPlaneSyncReceiptRetention + time.Hour)}).Error; err != nil {
		t.Fatalf("create current receipt: %v", err)
	}
	deleted, err := CleanupExpiredDataPlaneSyncReceipts(db, now)
	if err != nil {
		t.Fatalf("cleanup receipts: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d receipts, want 1", deleted)
	}
}

func TestCleanupExpiredNodeSyncReceipts(t *testing.T) {
	db, err := InitDb(t.TempDir() + "/database.db")
	if err != nil {
		t.Fatalf("init database: %v", err)
	}

	now := time.Now().UTC()
	expired := NodeSyncReceipt{
		NodeID:    1,
		SyncID:    "expired-receipt",
		CreatedAt: now.Add(-NodeSyncReceiptRetention - time.Hour),
	}
	current := NodeSyncReceipt{
		NodeID:    1,
		SyncID:    "current-receipt",
		CreatedAt: now.Add(-NodeSyncReceiptRetention + time.Hour),
	}
	if err := db.Create(&expired).Error; err != nil {
		t.Fatalf("create expired receipt: %v", err)
	}
	if err := db.Create(&current).Error; err != nil {
		t.Fatalf("create current receipt: %v", err)
	}

	deleted, err := CleanupExpiredNodeSyncReceipts(db, now)
	if err != nil {
		t.Fatalf("cleanup receipts: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted %d receipts, want 1", deleted)
	}

	var count int64
	if err := db.Model(&NodeSyncReceipt{}).Count(&count).Error; err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if count != 1 {
		t.Fatalf("remaining receipts = %d, want 1", count)
	}
}
