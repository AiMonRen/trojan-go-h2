package webserver

import (
	cryptorand "crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	jwtgo "github.com/golang-jwt/jwt/v5"
)

func TestGetSetJWTSecretThreadSafe(t *testing.T) {
	srv := &AdminServer{}
	secret := []byte("test-secret-32-bytes-xxxxxxxxxxxx")
	srv.setJWTSecret(secret)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := srv.getJWTSecret()
			if got == nil {
				t.Errorf("getJWTSecret returned nil")
			}
		}()
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			s := make([]byte, 16)
			cryptorand.Read(s)
			srv.setJWTSecret([]byte(hex.EncodeToString(s)))
		}(i)
	}
	wg.Wait()
	// Verify the final secret is non-nil.
	if srv.getJWTSecret() == nil {
		t.Fatal("final jwtSecret is nil")
	}
}

func TestSessionTimeoutIsPerSession(t *testing.T) {
	srv := &AdminServer{}
	srv.updateSessionActivity("session-A")
	srv.updateSessionActivity("session-B")

	// Neither should be expired immediately.
	if srv.isSessionExpired("session-A", 30*time.Minute) {
		t.Fatal("session-A should not be expired")
	}
	if srv.isSessionExpired("session-B", 30*time.Minute) {
		t.Fatal("session-B should not be expired")
	}
}

func TestSessionTimeoutExpiresAfterIdleLimit(t *testing.T) {
	srv := &AdminServer{}
	// Manually set a stale timestamp.
	srv.sessionTimes.Store("stale-session", time.Now().Add(-time.Hour))
	if !srv.isSessionExpired("stale-session", 30*time.Minute) {
		t.Fatal("stale session should be expired")
	}
}

func TestSessionTimeoutNeverSeenIsNotExpired(t *testing.T) {
	srv := &AdminServer{}
	if srv.isSessionExpired("unknown-jti", 30*time.Minute) {
		t.Fatal("never-seen session should not be expired")
	}
}

func TestSetJWTSecretClearsSessionTimes(t *testing.T) {
	srv := &AdminServer{}
	srv.updateSessionActivity("old-session")
	if _, ok := srv.sessionTimes.Load("old-session"); !ok {
		t.Fatal("session should be tracked")
	}
	srv.setJWTSecret([]byte("new-secret"))
	if _, ok := srv.sessionTimes.Load("old-session"); ok {
		t.Fatal("old session should be cleared after JWT rotation")
	}
}

func TestRequireAdminOrNodeRejectsExpiredSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	jtiBytes := make([]byte, 16)
	cryptorand.Read(jtiBytes)
	jti := hex.EncodeToString(jtiBytes)

	srv := &AdminServer{}
	srv.setJWTSecret([]byte("shared-secret-for-testing-purposes"))

	// Mark the session as stale.
	srv.sessionTimes.Store(jti, time.Now().Add(-time.Hour))

	// Issue a token with a stale jti.
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, jwtgo.MapClaims{
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts, err := token.SignedString(srv.getJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	router := gin.New()
	router.Use(srv.requireAdminOrNode())
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Header.Set("Authorization", "Bearer "+ts)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("expired session: expected 401, got %d: %s", response.Code, response.Body.String())
	}
}

func TestRequireAdminOrNodeAcceptsActiveSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := &AdminServer{}
	srv.setJWTSecret([]byte("shared-secret-for-testing-purposes"))

	jtiBytes := make([]byte, 16)
	cryptorand.Read(jtiBytes)
	jti := hex.EncodeToString(jtiBytes)
	srv.updateSessionActivity(jti)

	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, jwtgo.MapClaims{
		"jti": jti,
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	ts, err := token.SignedString(srv.getJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	router := gin.New()
	router.Use(srv.requireAdminOrNode())
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Header.Set("Authorization", "Bearer "+ts)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("active session: expected 200, got %d: %s", response.Code, response.Body.String())
	}
}

// signSessionToken issues a validly signed HS256 token carrying the supplied
// claims so tests can exercise middleware behaviour for malformed sessions.
func signSessionToken(t *testing.T, srv *AdminServer, claims jwtgo.MapClaims) string {
	t.Helper()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS256, claims)
	ts, err := token.SignedString(srv.getJWTSecret())
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return ts
}

// TestSessionMiddlewareRejectsTokenWithoutJTI guards the P1-⑦ fix: a token
// that carries no jti claim cannot be tracked for idle timeout, so both
// session middlewares must refuse it instead of granting a free 24h window.
func TestSessionMiddlewareRejectsTokenWithoutJTI(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := &AdminServer{}
	srv.setJWTSecret([]byte("shared-secret-for-testing-purposes"))

	cases := []struct {
		name   string
		claims jwtgo.MapClaims
	}{
		{
			name:   "missing jti",
			claims: jwtgo.MapClaims{"user": "admin", "exp": time.Now().Add(time.Hour).Unix()},
		},
		{
			name:   "empty jti",
			claims: jwtgo.MapClaims{"user": "admin", "jti": "", "exp": time.Now().Add(time.Hour).Unix()},
		},
		{
			name:   "non-string jti",
			claims: jwtgo.MapClaims{"user": "admin", "jti": 12345, "exp": time.Now().Add(time.Hour).Unix()},
		},
	}

	middlewares := map[string]gin.HandlerFunc{
		"requireAdminOrNode":  srv.requireAdminOrNode(),
		"requireAdminSession": srv.requireAdminSession(),
	}

	for mwName, mw := range middlewares {
		for _, tc := range cases {
			t.Run(mwName+"/"+tc.name, func(t *testing.T) {
				ts := signSessionToken(t, srv, tc.claims)

				router := gin.New()
				router.Use(mw)
				router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

				request := httptest.NewRequest(http.MethodGet, "/test", nil)
				request.Header.Set("Authorization", "Bearer "+ts)
				response := httptest.NewRecorder()
				router.ServeHTTP(response, request)

				if response.Code != http.StatusUnauthorized {
					t.Fatalf("expected 401 for token without usable jti, got %d: %s",
						response.Code, response.Body.String())
				}
			})
		}
	}
}

// TestRequireAdminSessionTracksActivityOnFirstUse verifies that a valid jti
// which has never been seen is admitted once and then tracked, so the idle
// timer starts counting from that first request.
func TestRequireAdminSessionTracksActivityOnFirstUse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	srv := &AdminServer{}
	srv.setJWTSecret([]byte("shared-secret-for-testing-purposes"))

	jti := "fresh-session-identifier"
	ts := signSessionToken(t, srv, jwtgo.MapClaims{
		"user": "admin",
		"jti":  jti,
		"exp":  time.Now().Add(time.Hour).Unix(),
	})

	router := gin.New()
	router.Use(srv.requireAdminSession())
	router.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	request := httptest.NewRequest(http.MethodGet, "/test", nil)
	request.Header.Set("Authorization", "Bearer "+ts)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("first use of a valid session: expected 200, got %d: %s",
			response.Code, response.Body.String())
	}
	if _, ok := srv.sessionTimes.Load(jti); !ok {
		t.Fatal("session activity should be recorded after the first authorized request")
	}
}
