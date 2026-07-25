package webserver

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
)

// S-09: a broken uniqueness precheck must surface as 500 rather than being
// treated as "this password is free" and falling through to Create.
func TestAddUserReportsUniquenessPrecheckFailure(t *testing.T) {
	srv := newDBErrorServer(t)
	if err := srv.db.Migrator().DropTable(&database.User{}); err != nil {
		t.Fatalf("drop users table: %v", err)
	}

	response := performJSON(srv, srv.handleAddUser, http.MethodPost, "/users", map[string]any{
		"username": "alice",
		"password": "a-strong-password",
		"quota":    -1,
	})
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusInternalServerError, response.Body.String())
	}
}

// A genuinely duplicate password still has to be reported as a 409 conflict,
// so the new default branch must not swallow the conflict case.
func TestAddUserStillDetectsDuplicatePassword(t *testing.T) {
	srv := newDBErrorServer(t)

	first := performJSON(srv, srv.handleAddUser, http.MethodPost, "/users", map[string]any{
		"username": "alice",
		"password": "shared-password",
		"quota":    -1,
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first create status = %d, want 200: %s", first.Code, first.Body.String())
	}

	second := performJSON(srv, srv.handleAddUser, http.MethodPost, "/users", map[string]any{
		"username": "bob",
		"password": "shared-password",
		"quota":    -1,
	})
	if second.Code != http.StatusConflict {
		t.Fatalf("duplicate create status = %d, want %d: %s", second.Code, http.StatusConflict, second.Body.String())
	}
}

// S-09: same requirement on the update path.
func TestUpdateUserStillDetectsDuplicatePassword(t *testing.T) {
	srv := newDBErrorServer(t)
	for _, spec := range []struct{ username, password string }{
		{"alice", "alice-password"},
		{"bob", "bob-password"},
	} {
		response := performJSON(srv, srv.handleAddUser, http.MethodPost, "/users", map[string]any{
			"username": spec.username,
			"password": spec.password,
			"quota":    -1,
		})
		if response.Code != http.StatusOK {
			t.Fatalf("create %s status = %d: %s", spec.username, response.Code, response.Body.String())
		}
	}

	var bob database.User
	if err := srv.db.Where("username = ?", "bob").First(&bob).Error; err != nil {
		t.Fatalf("read bob: %v", err)
	}

	bobID := strconv.FormatUint(uint64(bob.ID), 10)
	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	payload, _ := json.Marshal(map[string]any{"password": "alice-password"})
	ginContext.Request = httptest.NewRequest(http.MethodPut, "/users/"+bobID, bytes.NewReader(payload))
	ginContext.Request.Header.Set("Content-Type", "application/json")
	ginContext.Params = gin.Params{{Key: "id", Value: bobID}}
	srv.handleUpdateUser(ginContext)
	if response.Code != http.StatusConflict {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusConflict, response.Body.String())
	}
}

// S-06: a non-numeric or out-of-range line count must fall back to the default
// instead of reaching journalctl and producing a usage error.
func TestNormalizeLogLines(t *testing.T) {
	defaultValue := strconv.Itoa(defaultLogLines)
	for input, want := range map[string]string{
		"500":                     "500",
		"1":                       "1",
		strconv.Itoa(maxLogLines): strconv.Itoa(maxLogLines),
		"":                        defaultValue,
		"abc":                     defaultValue,
		"0":                       defaultValue,
		"-5":                      defaultValue,
		"99999999":                defaultValue,
		"300; rm -rf /":           defaultValue,
		"1e6":                     defaultValue,
	} {
		if got := normalizeLogLines(input); got != want {
			t.Errorf("normalizeLogLines(%q) = %q, want %q", input, got, want)
		}
	}
}

// S-04: the internal control token must be rejected when it does not match and
// accepted when it does, now that the comparison goes through crypto/subtle.
func TestInternalControlTokenComparison(t *testing.T) {
	srv := newDBErrorServer(t)
	srv.internalToken = "correct-horse-battery-staple"

	engine := newTrustedGinEngine()
	engine.POST("/internal/probe", srv.requireInternalControl(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	for _, tc := range []struct {
		name  string
		token string
		want  int
	}{
		{"correct", "correct-horse-battery-staple", http.StatusOK},
		{"wrong", "wrong-token", http.StatusForbidden},
		{"prefix", "correct-horse", http.StatusForbidden},
		{"empty", "", http.StatusForbidden},
	} {
		request := httptest.NewRequest(http.MethodPost, "/internal/probe", nil)
		request.RemoteAddr = "127.0.0.1:5000"
		if tc.token != "" {
			request.Header.Set("X-Internal-Token", tc.token)
		}
		response := httptest.NewRecorder()
		engine.ServeHTTP(response, request)
		if response.Code != tc.want {
			t.Errorf("%s token: status = %d, want %d", tc.name, response.Code, tc.want)
		}
	}
}
