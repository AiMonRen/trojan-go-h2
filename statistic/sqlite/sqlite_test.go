package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
)

func TestSqliteConfigDefaults(t *testing.T) {
	ctx, err := config.WithYAMLConfig(context.Background(), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg == nil {
		t.Fatal("config is nil")
	}
	if cfg.Sqlite.DbPath != "trojan-go.db" {
		t.Errorf("default DbPath = %q, want trojan-go.db", cfg.Sqlite.DbPath)
	}
	if cfg.Sqlite.CheckRate != 60 {
		t.Errorf("default CheckRate = %d, want 60", cfg.Sqlite.CheckRate)
	}
}

func TestSqliteNewAuthenticatorBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Populate all configs via empty YAML first, then override sqlite
	ctx, err := config.WithYAMLConfig(ctx, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = config.WithConfig(ctx, Name, &Config{
		Sqlite: SqliteConfig{
			Enabled:   true,
			DbPath:    "file::memory:?cache=shared",
			CheckRate: 60,
		},
	})

	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal("NewAuthenticator:", err)
	}
	if auth == nil {
		t.Fatal("authenticator is nil")
	}

	common.Must(auth.AddUser("newuser"))

	valid, user := auth.AuthUser("newuser")
	if !valid || user == nil {
		t.Fatal("AuthUser failed")
	}

	user.AddTraffic(100, 200)
	sent, recv := user.GetTraffic()
	if sent != 100 || recv != 200 {
		t.Errorf("traffic = (%d, %d), want (100, 200)", sent, recv)
	}

	auth.Close()
	time.Sleep(100 * time.Millisecond)
}

func TestSqliteAuthenticatorClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	ctx, err := config.WithYAMLConfig(ctx, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = config.WithConfig(ctx, Name, &Config{
		Sqlite: SqliteConfig{
			Enabled:   true,
			DbPath:    "file::memory:?cache=shared",
			CheckRate: 30,
		},
	})

	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal(err)
	}

	cancel()
	time.Sleep(50 * time.Millisecond)
	if err := auth.Close(); err != nil {
		t.Log("Close returned error:", err)
	}
}

func TestSqliteUserLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, err := config.WithYAMLConfig(ctx, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = config.WithConfig(ctx, Name, &Config{
		Sqlite: SqliteConfig{
			Enabled:   true,
			DbPath:    "file::memory:?cache=shared",
			CheckRate: 60,
		},
	})

	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer auth.Close()

	users := []string{"user1", "user2", "user3"}
	for _, hash := range users {
		common.Must(auth.AddUser(hash))
	}

	for _, hash := range users {
		valid, u := auth.AuthUser(hash)
		if !valid || u == nil {
			t.Errorf("AuthUser(%q) failed", hash)
		}
		if u.Hash() != hash {
			t.Errorf("Hash() = %q, want %q", u.Hash(), hash)
		}
	}

	all := auth.ListUsers()
	if len(all) < 3 {
		t.Errorf("ListUsers returned %d, want >= 3", len(all))
	}
}

func TestSqliteNoPanicOnDisabledConfig(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ctx, err := config.WithYAMLConfig(ctx, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	ctx = config.WithConfig(ctx, Name, &Config{
		Sqlite: SqliteConfig{
			Enabled:   false,
			DbPath:    "file::memory:?cache=shared",
			CheckRate: 60,
		},
	})

	auth, err := NewAuthenticator(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth.Close()
}
