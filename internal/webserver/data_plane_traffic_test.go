package webserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
)

func TestDataPlaneTrafficEndpointIsIdempotent(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	user := database.User{Username: "traffic", Hash: "traffic-hash", Quota: -1, Status: 0}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)
	srv.internalToken = "" // bypass internal auth for unit tests
	router := gin.New()
	srv.registerRoutesForMode(router, "/admin/", RouteModeAdmin)

	body, _ := json.Marshal(dataPlaneTrafficRequest{
		SyncID: "batch-1",
		Traffic: map[string]dataPlaneTrafficValue{
			"traffic-hash": {Up: 10, Down: 20},
		},
	})
	for i := 0; i < 2; i++ {
		request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/data-plane/traffic", bytes.NewReader(body))
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d, body=%s", i+1, response.Code, response.Body.String())
		}
	}
	if err := db.First(&user, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.Upload != 10 || user.Download != 20 || user.Used != 30 {
		t.Fatalf("traffic was not idempotent: upload=%d download=%d used=%d", user.Upload, user.Download, user.Used)
	}
	var receipts int64
	if err := db.Model(&database.DataPlaneSyncReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 1 {
		t.Fatalf("receipts = %d, want 1", receipts)
	}
}

func TestDataPlaneTrafficEndpointRejectsNonLoopback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "traffic.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)
	srv.internalToken = "" // bypass internal auth for unit tests
	router := gin.New()
	srv.registerRoutesForMode(router, "/admin/", RouteModeAdmin)
	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/data-plane/traffic", bytes.NewBufferString(`{"sync_id":"batch","traffic":{"hash":{"up":1,"down":2}}}`))
	request.RemoteAddr = "192.0.2.10:12345"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}
