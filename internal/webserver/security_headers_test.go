package webserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// S-05: the panel and its API must carry the full browser hardening set.
func TestSecurityHeadersFull(t *testing.T) {
	engine := newTrustedGinEngine()
	engine.GET("/panel", securityHeaders(true), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	request := httptest.NewRequest(http.MethodGet, "/panel", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
		"X-Frame-Options":        "DENY",
	} {
		if got := response.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}

	csp := response.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("Content-Security-Policy missing")
	}
	for _, directive := range []string{
		"default-src 'self'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"object-src 'none'",
		"form-action 'self'",
	} {
		if !strings.Contains(csp, directive) {
			t.Errorf("CSP missing %q: %s", directive, csp)
		}
	}
}

// The subscription endpoint is fetched by proxy clients, so it gets the
// transport-level headers but must not advertise a CSP or framing policy.
func TestSecurityHeadersClientFacing(t *testing.T) {
	engine := newTrustedGinEngine()
	engine.GET("/sub", securityHeaders(false), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	request := httptest.NewRequest(http.MethodGet, "/sub", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	if got := response.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}
	if got := response.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	if got := response.Header().Get("Content-Security-Policy"); got != "" {
		t.Errorf("Content-Security-Policy = %q, want empty for client-facing route", got)
	}
}

// HSTS is only valid on an HTTPS response; a plaintext loopback response must
// not carry it, and the loopback-trusted forwarded scheme must be honoured.
func TestSecurityHeadersHSTSOnlyOverTLS(t *testing.T) {
	engine := newTrustedGinEngine()
	engine.GET("/panel", securityHeaders(true), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	plain := httptest.NewRequest(http.MethodGet, "/panel", nil)
	plain.RemoteAddr = "127.0.0.1:5000"
	plainResponse := httptest.NewRecorder()
	engine.ServeHTTP(plainResponse, plain)
	if got := plainResponse.Header().Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS set on plaintext response: %q", got)
	}

	forwarded := httptest.NewRequest(http.MethodGet, "/panel", nil)
	forwarded.RemoteAddr = "127.0.0.1:5000"
	forwarded.Header.Set("X-Forwarded-Proto", "https")
	forwardedResponse := httptest.NewRecorder()
	engine.ServeHTTP(forwardedResponse, forwarded)
	if got := forwardedResponse.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=") {
		t.Errorf("HSTS = %q, want a max-age directive behind the TLS gateway", got)
	}
}

// The mask page must stay header-identical to a plain static site so active
// probing cannot fingerprint the panel by its response headers.
func TestMaskPageHasNoSecurityHeaders(t *testing.T) {
	srv := newDBErrorServer(t)
	engine := newTrustedGinEngine()
	srv.registerRoutesForMode(engine, "/admin/", RouteModeAdmin)

	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	engine.ServeHTTP(response, request)

	for _, header := range []string{
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
	} {
		if got := response.Header().Get(header); got != "" {
			t.Errorf("mask page leaks %s = %q", header, got)
		}
	}
}
