package webserver

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
)

func TestServiceRouteModesSeparateAdminAndControlBoundaries(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(t.TempDir() + "/cold-migration.db")
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)

	adminRouter := gin.New()
	srv.registerRoutesForMode(adminRouter, "/admin/", RouteModeAdmin)
	if hasRoute(adminRouter, http.MethodPost, "/control/v1/nodes/heartbeat") {
		t.Fatal("admin-service must not register public control routes")
	}
	if !hasRoute(adminRouter, http.MethodGet, "/admin/api/status") {
		t.Fatal("admin-service must register management routes")
	}

	controlRouter := gin.New()
	srv.registerRoutesForMode(controlRouter, "/admin/", RouteModeControl)
	if hasRoute(controlRouter, http.MethodGet, "/admin/api/status") {
		t.Fatal("control-service must not register management routes")
	}
	if !hasRoute(controlRouter, http.MethodPost, "/control/v1/nodes/heartbeat") {
		t.Fatal("control-service must register public control routes")
	}
}

func hasRoute(router *gin.Engine, method, path string) bool {
	for _, route := range router.Routes() {
		if route.Method == method && route.Path == path {
			return true
		}
	}
	return false
}
