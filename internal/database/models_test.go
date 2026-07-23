package database

import (
	"testing"
	"time"
)

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
