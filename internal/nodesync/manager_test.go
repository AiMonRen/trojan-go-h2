package nodesync

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/statistic"
)

type testUser struct {
	mu   sync.Mutex
	hash string
	sent uint64
	recv uint64
}

func (u *testUser) Close() error { return nil }
func (u *testUser) Hash() string { return u.hash }
func (u *testUser) AddTraffic(sent, recv int) {
	u.mu.Lock()
	u.sent += uint64(sent)
	u.recv += uint64(recv)
	u.mu.Unlock()
}
func (u *testUser) GetTraffic() (uint64, uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sent, u.recv
}
func (u *testUser) SetTraffic(sent, recv uint64) {
	u.mu.Lock()
	u.sent, u.recv = sent, recv
	u.mu.Unlock()
}
func (u *testUser) ResetTraffic() (uint64, uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	sent, recv := u.sent, u.recv
	u.sent, u.recv = 0, 0
	return sent, recv
}
func (u *testUser) GetSpeed() (uint64, uint64) { return 0, 0 }
func (u *testUser) GetSpeedLimit() (int, int)  { return 0, 0 }
func (u *testUser) SetSpeedLimit(int, int)     {}
func (u *testUser) AddIP(string) bool          { return true }
func (u *testUser) DelIP(string) bool          { return true }
func (u *testUser) GetIP() int                 { return 0 }
func (u *testUser) SetIPLimit(int)             {}
func (u *testUser) GetIPLimit() int            { return 0 }

type testAuthenticator struct{ users []statistic.User }

func (a *testAuthenticator) Close() error { return nil }
func (a *testAuthenticator) AuthUser(hash string) (bool, statistic.User) {
	for _, user := range a.users {
		if user.Hash() == hash {
			return true, user
		}
	}
	return false, nil
}
func (a *testAuthenticator) AddUser(string) error        { return nil }
func (a *testAuthenticator) DelUser(string) error        { return nil }
func (a *testAuthenticator) ListUsers() []statistic.User { return a.users }

func TestPerformSyncRetainsTrafficUntilMasterAcknowledges(t *testing.T) {
	user := &testUser{hash: "test-hash", sent: 120, recv: 80}
	auth := &testAuthenticator{users: []statistic.User{user}}
	status := http.StatusServiceUnavailable
	var syncIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncIDs = append(syncIDs, r.Header.Get("X-Node-Sync-ID"))
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"users":["test-hash"]}`))
		}
	}))
	defer server.Close()

	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		auths:          []statistic.Authenticator{auth},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
	}

	manager.performSync()
	if got := manager.pendingTraffic["test-hash"]; got.Up != 80 || got.Down != 120 {
		t.Fatalf("failed sync must retain traffic, got %+v", got)
	}
	if manager.pendingSyncID == "" {
		t.Fatal("failed sync must retain an idempotency key")
	}

	status = http.StatusOK
	manager.performSync()
	if len(manager.pendingTraffic) != 0 {
		t.Fatalf("successful sync must acknowledge the fixed traffic batch, got %+v", manager.pendingTraffic)
	}
	if len(syncIDs) != 2 || syncIDs[0] == "" || syncIDs[0] != syncIDs[1] {
		t.Fatalf("retry must reuse the same idempotency key, got %v", syncIDs)
	}
}

func TestSyncFailureBackoffAndSharedClients(t *testing.T) {
	manager := &NodeSyncManager{syncInterval: time.Second}
	if manager.getSyncClient() != manager.getSyncClient() {
		t.Fatal("sync client must be reused")
	}
	if manager.getHeartbeatClient() != manager.getHeartbeatClient() {
		t.Fatal("heartbeat client must be reused")
	}

	manager.recordSyncFailure("test failure")
	if manager.failureCount != 1 || manager.nextSyncAt.IsZero() {
		t.Fatalf("failure must schedule retry, count=%d next=%s", manager.failureCount, manager.nextSyncAt)
	}
	if manager.syncReady(time.Now()) {
		t.Fatal("sync must respect retry backoff")
	}
	manager.recordSyncSuccess()
	if manager.failureCount != 0 || !manager.nextSyncAt.IsZero() {
		t.Fatalf("success must reset retry state, count=%d next=%s", manager.failureCount, manager.nextSyncAt)
	}
}

func TestSyncIDGenerationFailureRetainsTrafficWithoutSending(t *testing.T) {
	original := readCryptoRandom
	readCryptoRandom = func([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
	t.Cleanup(func() { readCryptoRandom = original })

	user := &testUser{hash: "test-hash", sent: 120, recv: 80}
	auth := &testAuthenticator{users: []statistic.User{user}}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["test-hash"]}`))
	}))
	defer server.Close()

	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		syncInterval:   time.Second,
		auths:          []statistic.Authenticator{auth},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
	}
	manager.performSync()
	if requests != 0 {
		t.Fatalf("random source failure must not send an unkeyed report, got %d requests", requests)
	}
	if got := manager.queuedTraffic["test-hash"]; got.Up != 80 || got.Down != 120 {
		t.Fatalf("random source failure must retain traffic for retry, got %+v", got)
	}
	if manager.pendingSyncID != "" {
		t.Fatalf("random source failure must not create an empty pending batch, got %q", manager.pendingSyncID)
	}
}

func TestNormalizedSyncInterval(t *testing.T) {
	if got := normalizedSyncInterval(0); got != defaultSyncInterval {
		t.Fatalf("zero interval = %s, want default %s", got, defaultSyncInterval)
	}
	if got := normalizedSyncInterval(-5); got != defaultSyncInterval {
		t.Fatalf("negative interval = %s, want default %s", got, defaultSyncInterval)
	}
	if got := normalizedSyncInterval(15); got.String() != "15s" {
		t.Fatalf("valid interval = %s, want 15s", got)
	}
}

func TestHeartbeatURLValidation(t *testing.T) {
	valid, err := heartbeatURL("https://master.example/admin/api/node/sync")
	if err != nil || valid != "https://master.example/admin/api/node/heartbeat" {
		t.Fatalf("valid sync URL generated heartbeat URL %q, err=%v", valid, err)
	}
	for _, input := range []string{"", "https://master.example/short", "/admin/api/node/sync"} {
		if _, err := heartbeatURL(input); err == nil {
			t.Errorf("invalid sync URL %q must be rejected", input)
		}
	}
}
