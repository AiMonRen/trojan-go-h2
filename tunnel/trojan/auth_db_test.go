package trojan

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/statistic"
	"github.com/voidluo/trojan-go/statistic/memory"
)

func TestDataPlaneAuthenticatorLoadsExistingDatabaseUsers(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "existing.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	expired := time.Now().Add(-time.Hour)
	users := []database.User{
		{Username: "active", Hash: "active-hash", Quota: -1, Status: 0},
		{Username: "disabled", Hash: "disabled-hash", Quota: -1, Status: 1},
		{Username: "expired", Hash: "expired-hash", Quota: -1, Status: 0, ExpiryTime: &expired},
		{Username: "quota", Hash: "quota-hash", Quota: 100, Used: 100, Status: 0},
	}
	if err := db.Create(&users).Error; err != nil {
		t.Fatalf("create existing users: %v", err)
	}
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := webserver.SyncAuthenticatorFromDatabase(db, auth); err != nil {
		t.Fatalf("SyncAuthenticatorFromDatabase: %v", err)
	}
	if ok, _ := auth.AuthUser("active-hash"); !ok {
		t.Fatal("active existing user must be loaded")
	}
	for _, hash := range []string{"disabled-hash", "expired-hash", "quota-hash"} {
		if ok, _ := auth.AuthUser(hash); ok {
			t.Fatalf("inactive user %q must not be loaded", hash)
		}
	}
}

func TestRefreshDataPlaneAuthenticatorAppliesDatabaseChanges(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "refresh.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	user := database.User{Username: "refresh", Hash: "refresh-hash", Quota: -1, Status: 0}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go refreshDataPlaneAuthenticator(ctx, db, auth, 10*time.Millisecond)

	waitAuthState(t, auth, "refresh-hash", true)
	if err := db.Model(&database.User{}).Where("id = ?", user.ID).Update("status", 1).Error; err != nil {
		t.Fatalf("disable user: %v", err)
	}
	waitAuthState(t, auth, "refresh-hash", false)
}

func waitAuthState(t *testing.T, auth statistic.Authenticator, hash string, want bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		ok, _ := auth.AuthUser(hash)
		if ok == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("auth state for %q did not become %v", hash, want)
}
