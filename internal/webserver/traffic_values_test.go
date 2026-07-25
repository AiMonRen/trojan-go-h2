package webserver

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/statistic"
	"github.com/voidluo/trojan-go/statistic/memory"
)

func TestNewTrafficIncrementRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		up   uint64
		down uint64
		rate float64
	}{
		{name: "upload exceeds int64", up: uint64(maxTrafficCounter) + 1, rate: 1},
		{name: "download exceeds int64", down: uint64(maxTrafficCounter) + 1, rate: 1},
		{name: "sum exceeds int64", up: uint64(maxTrafficCounter), down: 1, rate: 1},
		{name: "zero rate", up: 1, rate: 0},
		{name: "negative rate", up: 1, rate: -1},
		{name: "nan rate", up: 1, rate: math.NaN()},
		{name: "infinite rate", up: 1, rate: math.Inf(1)},
		{name: "rate exceeds business limit", up: 1, rate: database.MaxTrafficRate + 1},
		{name: "scaled total exceeds int64", up: uint64(maxTrafficCounter/2) + 1, rate: 2},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := newTrafficIncrement(test.up, test.down, test.rate); err == nil {
				t.Fatal("invalid traffic values were accepted")
			}
		})
	}
}

func TestNewTrafficIncrementAcceptsBoundaries(t *testing.T) {
	increment, err := newTrafficIncrement(uint64(maxTrafficCounter), 0, 1)
	if err != nil {
		t.Fatalf("max int64 traffic rejected: %v", err)
	}
	if increment.Upload != maxTrafficCounter || increment.Download != 0 || increment.Used != maxTrafficCounter {
		t.Fatalf("unexpected boundary increment: %+v", increment)
	}

	increment, err = newTrafficIncrement(3, 2, 1.5)
	if err != nil {
		t.Fatalf("valid scaled traffic rejected: %v", err)
	}
	if increment.Upload != 3 || increment.Download != 2 || increment.Used != 7 {
		t.Fatalf("unexpected scaled increment: %+v", increment)
	}
}

func TestDataPlaneTrafficRejectsOverflowWithoutReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "traffic-overflow.db"))
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

	body, err := json.Marshal(dataPlaneTrafficRequest{
		SyncID: "overflow-batch",
		Traffic: map[string]dataPlaneTrafficValue{
			user.Hash: {Up: uint64(maxTrafficCounter), Down: 1},
		},
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/data-plane/traffic", strings.NewReader(string(body)))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}

	if err := db.First(&user, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.Upload != 0 || user.Download != 0 || user.Used != 0 {
		t.Fatalf("invalid traffic changed counters: %+v", user)
	}
	var receipts int64
	if err := db.Model(&database.DataPlaneSyncReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 0 {
		t.Fatalf("invalid batch created %d receipts", receipts)
	}
}

func TestDataPlaneTrafficRejectsStoredCounterOverflow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "traffic-counter-overflow.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	user := database.User{
		Username: "traffic",
		Hash:     "traffic-hash",
		Quota:    -1,
		Status:   0,
		Upload:   maxTrafficCounter,
		Used:     maxTrafficCounter,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)
	srv.internalToken = "" // bypass internal auth for unit tests
	router := gin.New()
	srv.registerRoutesForMode(router, "/admin/", RouteModeAdmin)

	request := httptest.NewRequest(http.MethodPost, "/internal/control/v1/data-plane/traffic", strings.NewReader(`{"sync_id":"stored-overflow","traffic":{"traffic-hash":{"up":1,"down":0}}}`))
	request.RemoteAddr = "127.0.0.1:12345"
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}

	if err := db.First(&user, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.Upload != maxTrafficCounter || user.Download != 0 || user.Used != maxTrafficCounter {
		t.Fatalf("overflowing update changed counters: %+v", user)
	}
}

func TestAddNodeRejectsExplicitZeroTrafficRate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "node-create-rate.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)
	response := httptest.NewRecorder()
	ginContext, _ := gin.CreateTestContext(response)
	ginContext.Request = httptest.NewRequest(http.MethodPost, "/admin/api/nodes", strings.NewReader(`{"name":"worker","address":"worker.example.com","traffic_rate":0}`))
	ginContext.Request.Header.Set("Content-Type", "application/json")
	srv.handleAddNode(ginContext)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}
	var count int64
	if err := db.Model(&database.Node{}).Count(&count).Error; err != nil {
		t.Fatalf("count nodes: %v", err)
	}
	if count != 0 {
		t.Fatalf("invalid zero rate created %d nodes", count)
	}
}

func TestNodeSyncRejectsInvalidRateWithoutReceipt(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db, err := database.InitDb(filepath.Join(t.TempDir(), "node-rate.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	user := database.User{Username: "traffic", Hash: "traffic-hash", Quota: -1, Status: 0}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}
	node := database.Node{Name: "worker", Address: "worker.example.com", Port: 443, TrafficRate: -1, Secret: "initial"}
	if err := db.Create(&node).Error; err != nil {
		t.Fatalf("create node: %v", err)
	}
	if err := database.SetNodeSecret(db, &node, "worker-secret"); err != nil {
		t.Fatalf("set node secret: %v", err)
	}
	srv := newAdminServer(db, "admin", "test-password", "/admin/", 0, false, "", false, false, "", "/sub", "", false)
	router := newTrustedGinEngine()
	srv.registerRoutesForMode(router, "/admin/", RouteModeControl)

	request := httptest.NewRequest(http.MethodPost, "/control/v1/nodes/sync", strings.NewReader(`{"traffic":{"traffic-hash":{"up":1,"down":2}}}`))
	request.RemoteAddr = "203.0.113.20:12345"
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Node-Secret", "worker-secret")
	request.Header.Set("X-Node-Sync-ID", "invalid-rate-batch")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusBadRequest, response.Body.String())
	}

	if err := db.First(&user, user.ID).Error; err != nil {
		t.Fatalf("reload user: %v", err)
	}
	if user.Upload != 0 || user.Download != 0 || user.Used != 0 {
		t.Fatalf("invalid rate changed counters: %+v", user)
	}
	var receipts int64
	if err := db.Model(&database.NodeSyncReceipt{}).Count(&receipts).Error; err != nil {
		t.Fatalf("count receipts: %v", err)
	}
	if receipts != 0 {
		t.Fatalf("invalid node batch created %d receipts", receipts)
	}
}

func TestEmbeddedTrafficRestoredWhenPersistenceFails(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "embedded-overflow.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	const hash = "embedded-hash"
	user := database.User{
		Username: "embedded",
		Hash:     hash,
		Quota:    -1,
		Status:   0,
		Upload:   maxTrafficCounter,
		Used:     maxTrafficCounter,
	}
	if err := db.Create(&user).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	auth, err := memory.NewAuthenticator(config.WithConfig(context.Background(), memory.Name, &memory.Config{}))
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	defer auth.Close()
	if err := auth.AddUser(hash); err != nil {
		t.Fatalf("add auth user: %v", err)
	}
	valid, runtimeUser := auth.AuthUser(hash)
	if !valid {
		t.Fatal("runtime user not found")
	}
	runtimeUser.AddTraffic64(0, 1)

	srv := &AdminServer{db: db, auths: []statistic.Authenticator{auth}}
	if err := srv.syncEmbeddedTrafficOnce(); err == nil {
		t.Fatal("stored counter overflow was not rejected")
	}
	if sent, recv := runtimeUser.GetTraffic(); sent != 0 || recv != 1 {
		t.Fatalf("failed persistence did not restore counters: sent=%d recv=%d", sent, recv)
	}
}

// TestEmbeddedTrafficPerAuthenticatorSubtraction covers the case where the same
// user hash is tracked by two authenticators. The database must receive the
// aggregate, while each counter must have only its own reading subtracted —
// subtracting the aggregate from both would over-deduct and underflow.
func TestEmbeddedTrafficPerAuthenticatorSubtraction(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "embedded-multi.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	const hash = "shared-hash"
	if err := db.Create(&database.User{Username: "shared", Hash: hash, Quota: -1, Status: 0}).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	newAuthWithUser := func(sent, recv uint64) (statistic.Authenticator, statistic.User) {
		auth, err := memory.NewAuthenticator(config.WithConfig(context.Background(), memory.Name, &memory.Config{}))
		if err != nil {
			t.Fatalf("create authenticator: %v", err)
		}
		t.Cleanup(func() { auth.Close() })
		if err := auth.AddUser(hash); err != nil {
			t.Fatalf("add auth user: %v", err)
		}
		valid, runtimeUser := auth.AuthUser(hash)
		if !valid {
			t.Fatal("runtime user not found")
		}
		runtimeUser.AddTraffic64(sent, recv)
		return auth, runtimeUser
	}

	auth1, user1 := newAuthWithUser(100, 200)
	auth2, user2 := newAuthWithUser(30, 40)

	srv := &AdminServer{db: db, auths: []statistic.Authenticator{auth1, auth2}}
	if err := srv.syncEmbeddedTrafficOnce(); err != nil {
		t.Fatalf("syncEmbeddedTrafficOnce: %v", err)
	}

	// Each counter must be fully drained (its own reading subtracted exactly).
	if sent, recv := user1.GetTraffic(); sent != 0 || recv != 0 {
		t.Fatalf("authenticator 1 counter not drained exactly: sent=%d recv=%d", sent, recv)
	}
	if sent, recv := user2.GetTraffic(); sent != 0 || recv != 0 {
		t.Fatalf("authenticator 2 counter not drained exactly: sent=%d recv=%d", sent, recv)
	}

	// The database must hold the aggregate of both authenticators:
	// upload = recv total = 200 + 40 = 240, download = sent total = 100 + 30 = 130.
	var stored database.User
	if err := db.Where("hash = ?", hash).First(&stored).Error; err != nil {
		t.Fatalf("read stored user: %v", err)
	}
	if stored.Upload != 240 {
		t.Fatalf("stored upload = %d, want 240 (aggregate of both authenticators)", stored.Upload)
	}
	if stored.Download != 130 {
		t.Fatalf("stored download = %d, want 130 (aggregate of both authenticators)", stored.Download)
	}
}

func TestMemoryTrafficRejectsNegativeIntUpdates(t *testing.T) {
	auth, err := memory.NewAuthenticator(config.WithConfig(context.Background(), memory.Name, &memory.Config{}))
	if err != nil {
		t.Fatalf("create authenticator: %v", err)
	}
	defer auth.Close()
	if err := auth.AddUser("negative"); err != nil {
		t.Fatalf("add user: %v", err)
	}
	_, user := auth.AuthUser("negative")
	user.AddTraffic(-1, -1)
	if sent, recv := user.GetTraffic(); sent != 0 || recv != 0 {
		t.Fatalf("negative int update wrapped counters: sent=%d recv=%d", sent, recv)
	}
}
