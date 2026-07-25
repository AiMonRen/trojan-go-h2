package webserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/voidluo/trojan-go/internal/database"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func openTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	path := "file:" + t.TempDir() + "/test.db?cache=shared"
	db, err := gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	db.AutoMigrate(&database.Config{}, &database.User{})
	return db
}

func TestHandleUpdateAdminCommitsUsernameAndPasswordAtomically(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDB(t)

	srv := &AdminServer{db: db, cachedAdminUser: "old-admin", cachedAdminPass: "old-pass", cacheValid: true}

	if err := database.SetAdminPassword(db, "old-pass"); err != nil {
		t.Fatalf("set initial password: %v", err)
	}
	router := gin.New()
	router.POST("/admin", srv.handleUpdateAdmin)

	body := `{"username":"new-admin","password":"new-password"}`
	request := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update admin: expected 200, got %d: %s", response.Code, response.Body.String())
	}

	// Verify both are updated.
	var cfg database.Config
	if err := db.Where("key = ?", "admin_username").First(&cfg).Error; err != nil || cfg.Value != "new-admin" {
		t.Fatalf("admin_username not persisted: err=%v, value=%q", err, cfg.Value)
	}
	cfg = database.Config{}
	if err := db.Where("key = ?", "admin_password").First(&cfg).Error; err != nil || cfg.Value == "" {
		t.Fatalf("admin_password not persisted: err=%v, value=%q", err, cfg.Value)
	}
	cfg = database.Config{}
	if err := db.Where("key = ?", "jwt_secret").First(&cfg).Error; err != nil || cfg.Value == "" {
		t.Fatalf("jwt_secret was not rotated: err=%v, value=%q", err, cfg.Value)
	}
}

func TestHandleUpdateAdminPasswordOnlyRotatesJWT(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDB(t)

	if err := database.SetAdminPassword(db, "before"); err != nil {
		t.Fatalf("set initial password: %v", err)
	}

	var jwtBefore database.Config
	db.Where("key = ?", "jwt_secret").First(&jwtBefore)

	srv := &AdminServer{db: db}
	router := gin.New()
	router.POST("/admin", srv.handleUpdateAdmin)

	body := `{"password":"after"}`
	request := httptest.NewRequest(http.MethodPost, "/admin", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("password-only update: expected 200, got %d: %s", response.Code, response.Body.String())
	}

	var jwtAfter database.Config
	db.Where("key = ?", "jwt_secret").First(&jwtAfter)

	if jwtBefore.Value == jwtAfter.Value {
		t.Fatal("jwt_secret was not rotated after password change")
	}
	if srv.getJWTSecret() == nil {
		t.Fatal("in-memory jwtSecret not updated")
	}
}

func TestHandleUpdateUserPasswordUpdateIsAtomic(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := openTestDB(t)

	user := database.User{Username: "test-user", Hash: "old-hash-value-28bytes-of-it!", Status: 0}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	srv := &AdminServer{db: db, isNode: false}
	router := gin.New()
	router.PUT("/user/:id", srv.handleUpdateUser)

	body, _ := json.Marshal(map[string]interface{}{
		"password": "new-secret",
		"quota":    int64(1024 * 1024 * 1024),
	})
	request := httptest.NewRequest(http.MethodPut, "/user/"+string(rune('0'+user.ID)), strings.NewReader(string(body)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("update user: expected 200, got %d: %s", response.Code, response.Body.String())
	}

	var reloaded database.User
	if err := db.First(&reloaded, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if reloaded.Hash == "old-hash-value-28bytes-of-it!" {
		t.Fatal("hash was not updated")
	}
	if reloaded.PasswordCiphertext == "" {
		t.Fatal("password ciphertext was not persisted")
	}
	if reloaded.PasswordKeyID != "default" {
		t.Fatalf("password key id = %q, want default", reloaded.PasswordKeyID)
	}
}
