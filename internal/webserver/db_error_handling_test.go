package webserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
	"gorm.io/gorm"
)

// newDBErrorServer builds an AdminServer backed by a throwaway SQLite file.
func newDBErrorServer(t *testing.T) *AdminServer {
	t.Helper()
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "db-errors.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	return newAdminServer(db, "config-admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "vpn.example.com", false)
}

// poisonWrites makes every create/update touching a row that predicate matches
// fail, which is how a mid-request database error is simulated deterministically.
func poisonWrites(t *testing.T, db *gorm.DB, predicate func(dest any) bool) {
	t.Helper()
	fail := func(tx *gorm.DB) {
		if tx.Statement != nil && predicate(tx.Statement.Dest) {
			tx.AddError(errors.New("simulated database failure"))
		}
	}
	if err := db.Callback().Create().Before("gorm:create").Register("test:poison_create", fail); err != nil {
		t.Fatalf("register create callback: %v", err)
	}
	if err := db.Callback().Update().Before("gorm:update").Register("test:poison_update", fail); err != nil {
		t.Fatalf("register update callback: %v", err)
	}
}

func performJSON(srv *AdminServer, handler func(*gin.Context), method, target string, body any) *httptest.ResponseRecorder {
	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	ginContext.Request = httptest.NewRequest(method, target, bytes.NewReader(payload))
	ginContext.Request.Header.Set("Content-Type", "application/json")
	handler(ginContext)
	return response
}

// F-1: a broken settings read inside handleListNodes must surface as 500
// instead of silently falling back to the default main-node label.
func TestListNodesReportsSettingsReadFailure(t *testing.T) {
	srv := newDBErrorServer(t)
	if err := srv.db.Migrator().DropTable(&database.Config{}); err != nil {
		t.Fatalf("drop configs table: %v", err)
	}

	response := performJSON(srv, srv.handleListNodes, http.MethodGet, "/nodes", nil)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
}

// F-1: a missing site_title row is not an error, the default label is used.
func TestListNodesFallsBackWhenSiteTitleMissing(t *testing.T) {
	isolateNodeInfoConfig(t)
	srv := newDBErrorServer(t)
	if err := srv.db.Where("`key` = ?", "site_title").Delete(&database.Config{}).Error; err != nil {
		t.Fatalf("delete site_title: %v", err)
	}

	response := performJSON(srv, srv.handleListNodes, http.MethodGet, "/nodes", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var nodes []publicNode
	if err := json.Unmarshal(response.Body.Bytes(), &nodes); err != nil {
		t.Fatalf("decode nodes: %v", err)
	}
	if len(nodes) != 1 || nodes[0].Name != "主节点" {
		t.Fatalf("expected synthetic main node named 主节点, got %+v", nodes)
	}
}

// F-1: handleGetSettings falls back to the config-file admin user when no
// admin_username row exists, and fails closed when the table is unreadable.
func TestGetSettingsAdminUsernameFallbackAndFailure(t *testing.T) {
	srv := newDBErrorServer(t)
	if err := srv.db.Where("`key` = ?", "admin_username").Delete(&database.Config{}).Error; err != nil {
		t.Fatalf("delete admin_username: %v", err)
	}

	response := performJSON(srv, srv.handleGetSettings, http.MethodGet, "/settings", nil)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var settings map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &settings); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	if settings["admin_username"] != "config-admin" {
		t.Fatalf("admin_username = %q, want config-admin", settings["admin_username"])
	}

	if err := srv.db.Migrator().DropTable(&database.Config{}); err != nil {
		t.Fatalf("drop configs table: %v", err)
	}
	response = performJSON(srv, srv.handleGetSettings, http.MethodGet, "/settings", nil)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
}

// F-2: a failure on one key must roll back the keys already written in the
// same request instead of leaving a half-applied settings set.
func TestUpdateSettingsIsAtomic(t *testing.T) {
	srv := newDBErrorServer(t)
	if err := srv.db.Save(&database.Config{Key: "site_title", Value: "original"}).Error; err != nil {
		t.Fatalf("seed site_title: %v", err)
	}
	// InitDb seeds a default clash_rules row, so capture the value that must
	// still be in place after the rollback.
	var originalRules database.Config
	if err := srv.db.Where("`key` = ?", "clash_rules").First(&originalRules).Error; err != nil &&
		!errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("read clash_rules: %v", err)
	}
	poisonWrites(t, srv.db, func(dest any) bool {
		cfg, ok := dest.(*database.Config)
		return ok && cfg.Key == "clash_rules"
	})

	response := performJSON(srv, srv.handleUpdateSettings, http.MethodPost, "/settings", map[string]string{
		"site_title":  "updated",
		"clash_rules": "- MATCH,DIRECT",
	})
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}

	var stored database.Config
	if err := srv.db.Where("`key` = ?", "site_title").First(&stored).Error; err != nil {
		t.Fatalf("read site_title: %v", err)
	}
	if stored.Value != "original" {
		t.Fatalf("site_title = %q, want original (partial commit leaked)", stored.Value)
	}
	var rules database.Config
	switch err := srv.db.Where("`key` = ?", "clash_rules").First(&rules).Error; {
	case errors.Is(err, gorm.ErrRecordNotFound):
		if originalRules.Value != "" {
			t.Fatalf("clash_rules row disappeared, want value %q", originalRules.Value)
		}
	case err != nil:
		t.Fatalf("read clash_rules: %v", err)
	case rules.Value != originalRules.Value:
		t.Fatalf("clash_rules = %q, want unchanged %q", rules.Value, originalRules.Value)
	}
}

// F-2: a rejected key is refused before anything is written.
func TestUpdateSettingsRejectsProtectedKeyWithoutWriting(t *testing.T) {
	srv := newDBErrorServer(t)

	response := performJSON(srv, srv.handleUpdateSettings, http.MethodPost, "/settings", map[string]string{
		"site_title":     "updated",
		"admin_username": "attacker",
	})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var count int64
	if err := srv.db.Model(&database.Config{}).Where("`key` = ? AND value = ?", "site_title", "updated").Count(&count).Error; err != nil {
		t.Fatalf("count site_title: %v", err)
	}
	if count != 0 {
		t.Fatalf("site_title was written despite a rejected key in the same request")
	}
}

// F-3: a restore that fails partway must leave no users behind, so the
// operator can simply retry the same backup file.
func TestRestoreRollsBackOnFailure(t *testing.T) {
	srv := newDBErrorServer(t)
	poisonWrites(t, srv.db, func(dest any) bool {
		user, ok := dest.(*database.User)
		return ok && user.Username == "second"
	})

	body, err := json.Marshal(map[string]any{"version": 1, "users": []map[string]any{
		{"username": "first", "hash": "hash-first", "quota": -1},
		{"username": "second", "hash": "hash-second", "quota": -1},
	}})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}

	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodPost, "/restore", bytes.NewReader(body))
	srv.handleRestore(ginContext)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
	var users int64
	if err := srv.db.Model(&database.User{}).Count(&users).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 0 {
		t.Fatalf("user rows = %d, want 0 after rollback", users)
	}
}

// F-3: the happy path still restores every new user exactly once and skips
// entries that already exist.
func TestRestoreCommitsAllUsersAndSkipsExisting(t *testing.T) {
	srv := newDBErrorServer(t)
	if err := srv.db.Create(&database.User{Username: "existing", Hash: "hash-existing", Quota: -1}).Error; err != nil {
		t.Fatalf("seed user: %v", err)
	}

	body, err := json.Marshal([]map[string]any{
		{"username": "existing", "hash": "hash-existing", "quota": -1},
		{"username": "fresh", "hash": "hash-fresh", "quota": -1},
	})
	if err != nil {
		t.Fatalf("marshal backup: %v", err)
	}

	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodPost, "/restore", bytes.NewReader(body))
	srv.handleRestore(ginContext)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusOK, response.Body.String())
	}
	var payload struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Message != "恢复成功: 1 个用户" {
		t.Fatalf("message = %q, want 恢复成功: 1 个用户", payload.Message)
	}
	var users int64
	if err := srv.db.Model(&database.User{}).Count(&users).Error; err != nil {
		t.Fatalf("count users: %v", err)
	}
	if users != 2 {
		t.Fatalf("user rows = %d, want 2", users)
	}
}
