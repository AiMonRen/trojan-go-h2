package nodesync

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/trafficoutbox"
	"github.com/voidluo/trojan-go/statistic"
)

const validTestHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type testUser struct {
	mu   sync.Mutex
	hash string
	sent uint64
	recv uint64
}

func (u *testUser) Close() error { return nil }
func (u *testUser) Hash() string { return u.hash }
func (u *testUser) AddTraffic(sent, recv int) {
	if sent < 0 || recv < 0 {
		return
	}
	u.AddTraffic64(uint64(sent), uint64(recv))
}
func (u *testUser) AddTraffic64(sent, recv uint64) {
	u.mu.Lock()
	u.sent += sent
	u.recv += recv
	u.mu.Unlock()
}
func (u *testUser) TakeTraffic(checkpoint func(sent, recv uint64) error) (uint64, uint64, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	sent, recv := u.sent, u.recv
	if sent == 0 && recv == 0 {
		return 0, 0, nil
	}
	if checkpoint != nil {
		if err := checkpoint(sent, recv); err != nil {
			return sent, recv, err
		}
	}
	u.sent, u.recv = 0, 0
	return sent, recv, nil
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
	sent, recv, _ := u.TakeTraffic(nil)
	return sent, recv
}
func (u *testUser) SubtractTraffic(sent, recv uint64) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.sent >= sent {
		u.sent -= sent
	} else {
		u.sent = 0
	}
	if u.recv >= recv {
		u.recv -= recv
	} else {
		u.recv = 0
	}
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

func TestPerformSyncTimeoutRetriesPersistedBatchWithSameID(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker-traffic.json")
	outbox, err := trafficoutbox.NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})
	var mu sync.Mutex
	var syncIDs []string
	attempt := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		attempt++
		current := attempt
		syncIDs = append(syncIDs, r.Header.Get("X-Node-Sync-ID"))
		mu.Unlock()
		if current == 1 {
			close(entered)
			<-release
			close(firstDone)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["` + validTestHash + `"]}`))
	}))
	defer server.Close()
	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		syncInterval:   time.Millisecond,
		auths:          []statistic.Authenticator{&testAuthenticator{users: []statistic.User{user}}},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
		outbox:         outbox,
		syncClient:     newSyncHTTPClient(25 * time.Millisecond),
	}
	completed := make(chan struct{})
	go func() {
		manager.performSync()
		close(completed)
	}()
	<-entered
	<-completed
	close(release)
	<-firstDone
	if manager.pendingSyncID == "" {
		t.Fatal("timed-out batch must remain pending")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("timed-out batch must remain persisted: %v", err)
	}
	manager.mu.Lock()
	manager.nextSyncAt = time.Time{}
	manager.mu.Unlock()
	manager.performSync()
	mu.Lock()
	defer mu.Unlock()
	if len(syncIDs) != 2 || syncIDs[0] == "" || syncIDs[0] != syncIDs[1] {
		t.Fatalf("timeout retry must preserve Sync-ID, got %v", syncIDs)
	}
}

func TestPerformSyncRecoversPendingBatchFromOutbox(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker-traffic.json")
	outbox, err := trafficoutbox.NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := outbox.Save(trafficoutbox.State{
		PendingSyncID: "persisted-sync",
		Pending: map[string]trafficoutbox.Traffic{
			validTestHash: {Up: 80, Down: 120},
		},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var gotID string
	var gotTraffic trafficStats
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = r.Header.Get("X-Node-Sync-ID")
		var body struct {
			Traffic map[string]trafficStats `json:"traffic"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		gotTraffic = body.Traffic[validTestHash]
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["` + validTestHash + `"]}`))
	}))
	defer server.Close()

	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		syncInterval:   time.Second,
		auths:          []statistic.Authenticator{&testAuthenticator{}},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
		outbox:         outbox,
	}
	if err := manager.loadOutbox(); err != nil {
		t.Fatalf("loadOutbox: %v", err)
	}
	manager.performSync()
	if gotID != "persisted-sync" || gotTraffic != (trafficStats{Up: 80, Down: 120}) {
		t.Fatalf("recovered request id=%q traffic=%+v", gotID, gotTraffic)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("acknowledged outbox must be removed, stat err=%v", err)
	}
}

func TestPerformSyncCheckpointFailureLeavesRuntimeTraffic(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	outbox, err := trafficoutbox.NewFile(filepath.Join(parentFile, "traffic.json"))
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		syncInterval:   time.Second,
		auths:          []statistic.Authenticator{&testAuthenticator{users: []statistic.User{user}}},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
		outbox:         outbox,
	}
	manager.performSync()
	if sent, recv := user.GetTraffic(); sent != 120 || recv != 80 {
		t.Fatalf("checkpoint failure lost runtime traffic: sent=%d recv=%d", sent, recv)
	}
	if requests != 0 {
		t.Fatalf("checkpoint failure must not send, got %d requests", requests)
	}
}

func TestPerformSyncRejectsCorruptOutboxWithoutCollecting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "worker-traffic.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("write corrupt outbox: %v", err)
	}
	outbox, err := trafficoutbox.NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	manager := &NodeSyncManager{
		syncInterval:   time.Second,
		auths:          []statistic.Authenticator{&testAuthenticator{users: []statistic.User{user}}},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
		outbox:         outbox,
	}
	manager.outboxLoadError = manager.loadOutbox()
	if manager.outboxLoadError == nil {
		t.Fatal("corrupt outbox must fail to load")
	}
	manager.performSync()
	if sent, recv := user.GetTraffic(); sent != 120 || recv != 80 {
		t.Fatalf("corrupt outbox must leave runtime traffic untouched: sent=%d recv=%d", sent, recv)
	}
}

func TestPerformSyncRetainsTrafficUntilMasterAcknowledges(t *testing.T) {
	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	auth := &testAuthenticator{users: []statistic.User{user}}
	status := http.StatusServiceUnavailable
	var syncIDs []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		syncIDs = append(syncIDs, r.Header.Get("X-Node-Sync-ID"))
		w.WriteHeader(status)
		if status == http.StatusOK {
			_, _ = w.Write([]byte(`{"users":["` + validTestHash + `"]}`))
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
	if got := manager.pendingTraffic[validTestHash]; got.Up != 80 || got.Down != 120 {
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

func TestPerformSyncRejectsMalformedUserHash(t *testing.T) {
	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	auth := &testAuthenticator{users: []statistic.User{user}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["short"]}`))
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
	if got := manager.pendingTraffic[validTestHash]; got.Up != 80 || got.Down != 120 {
		t.Fatalf("malformed response must retain traffic, got %+v", got)
	}
	if manager.failureCount != 1 {
		t.Fatalf("malformed response must count as sync failure, got %d", manager.failureCount)
	}
}

func TestValidateUserHashes(t *testing.T) {
	valid := strings.Repeat("a", 56)
	if err := validateUserHashes([]string{valid}); err != nil {
		t.Fatalf("valid hash rejected: %v", err)
	}
	for _, hashes := range [][]string{{"short"}, {strings.Repeat("g", 56)}, {valid, valid}} {
		if err := validateUserHashes(hashes); err == nil {
			t.Fatalf("invalid hashes %v accepted", hashes)
		}
	}
}

func TestPerformSyncPropagatesLocalCacheTransactionFailure(t *testing.T) {
	db, err := database.InitDb(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatalf("InitDb: %v", err)
	}
	user := &testUser{hash: strings.Repeat("b", 56)}
	auth := &testAuthenticator{users: []statistic.User{user}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["` + user.hash + `"]}`))
	}))
	defer server.Close()

	manager := &NodeSyncManager{
		masterURL:      server.URL + syncEndpointPath,
		secret:         "test-secret",
		db:             db,
		auths:          []statistic.Authenticator{auth},
		pendingTraffic: make(map[string]trafficStats),
		queuedTraffic:  make(map[string]trafficStats),
	}
	if err := db.Exec("DROP TABLE users").Error; err != nil {
		t.Fatalf("drop users table: %v", err)
	}
	manager.performSync()
	if manager.failureCount != 1 {
		t.Fatalf("cache transaction failure must count as sync failure, got %d", manager.failureCount)
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

	user := &testUser{hash: validTestHash, sent: 120, recv: 80}
	auth := &testAuthenticator{users: []statistic.User{user}}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"users":["` + validTestHash + `"]}`))
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
	if got := manager.queuedTraffic[validTestHash]; got.Up != 80 || got.Down != 120 {
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
