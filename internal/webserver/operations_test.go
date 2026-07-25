package webserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// withoutHysteriaUnit points the optional hysteria unit lookup at a path that
// does not exist, so unit-list expectations are independent of the host.
func withoutHysteriaUnit(t *testing.T) {
	t.Helper()
	original := hysteriaUnitPath
	hysteriaUnitPath = filepath.Join(t.TempDir(), "absent-hysteria.service")
	t.Cleanup(func() { hysteriaUnitPath = original })
}

// withHysteriaUnit creates a stand-in hysteria unit file so the optional unit
// is detected as installed.
func withHysteriaUnit(t *testing.T) {
	t.Helper()
	original := hysteriaUnitPath
	path := filepath.Join(t.TempDir(), "hysteria.service")
	if err := os.WriteFile(path, []byte("[Unit]\n"), 0o600); err != nil {
		t.Fatalf("write stub unit: %v", err)
	}
	hysteriaUnitPath = path
	t.Cleanup(func() { hysteriaUnitPath = original })
}

func TestServiceUnitsMasterReturnsFourUnits(t *testing.T) {
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: false}
	units := srv.serviceUnits()
	if len(units) != 4 {
		t.Fatalf("master units: got %d, want 4: %v", len(units), units)
	}
	expected := []string{"trojan-data-plane", "admin-service", "control-service", "gateway-service"}
	for i, u := range expected {
		if units[i] != u {
			t.Fatalf("master unit[%d] = %q, want %q", i, units[i], u)
		}
	}
}

func TestServiceUnitsWorkerReturnsThreeUnits(t *testing.T) {
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: true}
	units := srv.serviceUnits()
	if len(units) != 3 {
		t.Fatalf("worker units: got %d, want 3: %v", len(units), units)
	}
	expected := []string{"trojan-data-plane", "control-service", "gateway-service"}
	for i, u := range expected {
		if units[i] != u {
			t.Fatalf("worker unit[%d] = %q, want %q", i, units[i], u)
		}
	}
}

func TestServiceUnitDescriptionReturnsChineseLabels(t *testing.T) {
	tests := map[string]string{
		"trojan-data-plane": "Trojan 数据面",
		"admin-service":     "管理服务",
		"control-service":   "控制服务",
		"gateway-service":   "公网网关",
		"unknown-unit":      "unknown-unit",
	}
	for unit, want := range tests {
		if got := serviceUnitDescription(unit); got != want {
			t.Errorf("%q: got %q, want %q", unit, got, want)
		}
	}
}

// TestServiceUnitsIncludesHysteriaWhenInstalled covers M-05: the optional
// hysteria unit must appear in the managed list (and therefore in status, logs
// and restart) whenever the installer has provisioned it.
func TestServiceUnitsIncludesHysteriaWhenInstalled(t *testing.T) {
	withHysteriaUnit(t)

	for _, isNode := range []bool{false, true} {
		srv := &AdminServer{isNode: isNode}
		units := srv.serviceUnits()
		found := false
		for _, u := range units {
			if u == "hysteria" {
				found = true
			}
		}
		if !found {
			t.Fatalf("isNode=%v: hysteria missing from %v", isNode, units)
		}
		if !srv.isAllowedUnit("hysteria") || !srv.isAllowedUnit("hysteria.service") {
			t.Fatalf("isNode=%v: hysteria must be an allowed unit for control and log APIs", isNode)
		}
	}

	if got, want := serviceUnitDescription("hysteria"), "Hysteria2 服务"; got != want {
		t.Fatalf("hysteria description = %q, want %q", got, want)
	}
}

// TestServiceUnitsOmitsHysteriaWhenNotInstalled ensures deployments without
// Hysteria2 do not advertise a unit that cannot be controlled.
func TestServiceUnitsOmitsHysteriaWhenNotInstalled(t *testing.T) {
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: false}
	for _, u := range srv.serviceUnits() {
		if u == "hysteria" {
			t.Fatal("hysteria must not be listed when its unit file is absent")
		}
	}
	if srv.isAllowedUnit("hysteria") {
		t.Fatal("hysteria must not be an allowed unit when its unit file is absent")
	}
}

func TestHandleServiceControlListReturnsUnitInfo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: true}
	router := gin.New()
	router.POST("/service", srv.handleServiceControl)

	body := `{"action":"list"}`
	request := httptest.NewRequest(http.MethodPost, "/service", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("list action: expected 200, got %d: %s", response.Code, response.Body.String())
	}
	var infos []struct {
		Unit        string `json:"unit"`
		Description string `json:"description"`
		Status      string `json:"status"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &infos); err != nil {
		t.Fatalf("unmarshal list response: %v", err)
	}
	if len(infos) != 3 {
		t.Fatalf("worker list: got %d units, want 3", len(infos))
	}
	if infos[0].Unit != "trojan-data-plane" || infos[0].Description != "Trojan 数据面" {
		t.Fatalf("unexpected unit info[0]: %+v", infos[0])
	}
}

func TestHandleServiceControlRejectsUnrecognizedService(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{isNode: false}
	router := gin.New()
	router.POST("/service", srv.handleServiceControl)

	body := `{"service":"evil.service","action":"restart"}`
	request := httptest.NewRequest(http.MethodPost, "/service", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("unrecognized service: expected 400, got %d: %s", response.Code, response.Body.String())
	}
}

func TestHandleServiceControlRejectsUnknownAction(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{isNode: false}
	router := gin.New()
	router.POST("/service", srv.handleServiceControl)

	body := `{"action":"hack"}`
	request := httptest.NewRequest(http.MethodPost, "/service", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("unknown action: expected 400, got %d", response.Code)
	}
}

func TestHandleRestartReturnsAcceptedMessage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	srv := &AdminServer{isNode: false}
	router := gin.New()
	router.POST("/restart", srv.handleRestart)

	request := httptest.NewRequest(http.MethodPost, "/restart", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("restart: expected 200, got %d", response.Code)
	}
	// M-05: the acknowledgement now names the units so operators can correlate
	// it with the aggregated result written to the journal.
	var payload struct {
		Message string   `json:"message"`
		Units   []string `json:"units"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal restart response: %v", err)
	}
	if len(payload.Units) == 0 {
		t.Fatal("restart response must list the units being restarted")
	}
}

// stubControlUnit replaces the systemctl invocation with a deterministic
// function for the duration of a test.
//
// Design note: this overrides a package-level function variable, which couples
// tests to the internal representation of controlUnit. When the control
// abstraction grows beyond the current two units (trojan-go + hysteria), an
// interface-based approach (e.g., UnitController interface with
// Start/Stop/Restart methods) would allow tests to pass mocks without touching
// package-level variables.
func stubControlUnit(t *testing.T, fn func(unit, action string) ([]byte, error)) {
	t.Helper()
	original := controlUnit
	controlUnit = fn
	t.Cleanup(func() { controlUnit = original })
}

// TestRestartAllUnitsAggregatesFailures covers M-05: every failing unit is
// collected into a single error instead of only being logged.
func TestRestartAllUnitsAggregatesFailures(t *testing.T) {
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: true}

	var attempted []string
	stubControlUnit(t, func(unit, action string) ([]byte, error) {
		attempted = append(attempted, unit+"/"+action)
		if unit == "control-service" {
			return nil, nil
		}
		return []byte("Job for " + unit + " failed"), errors.New("exit status 1")
	})

	err := srv.restartAllUnits()
	if err == nil {
		t.Fatal("restartAllUnits must return an aggregated error when units fail")
	}
	if !strings.Contains(err.Error(), "2/3 个服务单元失败") {
		t.Fatalf("aggregate must summarize the failure count, got %v", err)
	}
	for _, unit := range []string{"trojan-data-plane", "gateway-service"} {
		if !strings.Contains(err.Error(), unit) {
			t.Fatalf("aggregate must name failing unit %q, got %v", unit, err)
		}
	}
	if strings.Contains(err.Error(), "control-service:") {
		t.Fatalf("successful unit must not appear as a failure, got %v", err)
	}
	// A failure must not stop the remaining units from being attempted.
	if len(attempted) != 3 {
		t.Fatalf("expected all 3 units to be attempted, got %v", attempted)
	}
}

// TestRestartAllUnitsSucceedsWhenAllUnitsRestart is the positive counterpart.
func TestRestartAllUnitsSucceedsWhenAllUnitsRestart(t *testing.T) {
	withoutHysteriaUnit(t)
	srv := &AdminServer{isNode: true}
	stubControlUnit(t, func(unit, action string) ([]byte, error) { return nil, nil })

	if err := srv.restartAllUnits(); err != nil {
		t.Fatalf("restartAllUnits = %v, want nil", err)
	}
}

// TestHandleServiceControlReportsSystemctlFailure covers M-05: a failing
// systemctl action must surface as an error response rather than "已提交".
func TestHandleServiceControlReportsSystemctlFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)
	withoutHysteriaUnit(t)
	if !hasSystemctl() {
		// The handler only reports the failure when systemctl exists; otherwise
		// it takes the in-process fallback path, which is covered separately.
		t.Skip("systemctl unavailable on this host")
	}
	stubControlUnit(t, func(unit, action string) ([]byte, error) {
		return []byte("Unit not found"), errors.New("exit status 5")
	})

	srv := &AdminServer{isNode: false}
	router := gin.New()
	router.POST("/service", srv.handleServiceControl)

	body := `{"service":"gateway-service","action":"start"}`
	request := httptest.NewRequest(http.MethodPost, "/service", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("failed start must not report success: got %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Unit not found") {
		t.Fatalf("response should include the systemctl detail, got %s", response.Body.String())
	}
}
