package webserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireInternalControlDeniesNonLoopback(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{internalToken: "secret-token"}
	router := gin.New()
	router.Use(srv.requireInternalControl())
	router.POST("/internal/control/v1/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/test", nil)
	request.RemoteAddr = "192.0.2.10:12345"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("non-loopback origin: expected 403, got %d", response.Code)
	}
}

func TestRequireInternalControlDeniesWrongToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{internalToken: "secret-token"}
	router := gin.New()
	router.Use(srv.requireInternalControl())
	router.POST("/internal/control/v1/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/test", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("X-Internal-Token", "wrong-token")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("wrong token: expected 403, got %d", response.Code)
	}
}

func TestRequireInternalControlAcceptsValidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{internalToken: "secret-token"}
	router := gin.New()
	router.Use(srv.requireInternalControl())
	router.POST("/internal/control/v1/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/test", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("X-Internal-Token", "secret-token")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("valid token: expected 200, got %d: %s", response.Code, response.Body.String())
	}
}

func TestRequireInternalControlSkipsTokenWhenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{internalToken: ""}
	router := gin.New()
	router.Use(srv.requireInternalControl())
	router.POST("/internal/control/v1/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/test", nil)
	request.RemoteAddr = "127.0.0.1:12345"
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("empty token + loopback: expected 200, got %d", response.Code)
	}
}
