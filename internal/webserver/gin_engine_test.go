package webserver

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestTrustedGinEngineRejectsForwardedIPFromRemoteClient(t *testing.T) {
	engine := newTrustedGinEngine()
	engine.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	request := httptest.NewRequest(http.MethodGet, "/ip", nil)
	request.RemoteAddr = "203.0.113.10:4567"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	request.Header.Set("X-Real-IP", "198.51.100.21")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Body.String() != "203.0.113.10" {
		t.Fatalf("ClientIP = %q, want direct peer", response.Body.String())
	}
}

func TestTrustedGinEngineAcceptsForwardedIPFromLoopbackGateway(t *testing.T) {
	engine := newTrustedGinEngine()
	engine.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})

	request := httptest.NewRequest(http.MethodGet, "/ip", nil)
	request.RemoteAddr = "127.0.0.1:4567"
	request.Header.Set("X-Forwarded-For", "198.51.100.20")
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if response.Body.String() != "198.51.100.20" {
		t.Fatalf("ClientIP = %q, want forwarded client", response.Body.String())
	}
}
