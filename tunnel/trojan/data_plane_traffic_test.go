package trojan

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/trafficoutbox"
	"github.com/voidluo/trojan-go/statistic/memory"
)

func TestDataPlaneTrafficReporterRecoversPendingOutbox(t *testing.T) {
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	path := filepath.Join(t.TempDir(), "data-plane-traffic.json")
	outbox, err := trafficoutbox.NewFile(path)
	if err != nil {
		t.Fatalf("NewFile: %v", err)
	}
	if err := outbox.Save(trafficoutbox.State{
		PendingSyncID: "persisted-sync",
		Pending: map[string]trafficoutbox.Traffic{
			"traffic-hash": {Up: 10, Down: 20},
		},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	var got dataPlaneTrafficBatch
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	reporter, err := newDataPlaneTrafficReporter(auth, server.URL, "", path)
	if err != nil {
		t.Fatalf("newDataPlaneTrafficReporter: %v", err)
	}
	if err := reporter.flush(context.Background()); err != nil {
		t.Fatalf("flush recovered batch: %v", err)
	}
	if got.SyncID != "persisted-sync" || got.Traffic["traffic-hash"] != (dataPlaneTraffic{Up: 10, Down: 20}) {
		t.Fatalf("unexpected recovered batch: %+v", got)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("acknowledged outbox must be removed, stat err=%v", err)
	}
}

func TestDataPlaneTrafficCheckpointFailureLeavesRuntimeTraffic(t *testing.T) {
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.AddUser("traffic-hash"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := auth.AuthUser("traffic-hash")
	user.AddTraffic(20, 10)
	parentFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatalf("write parent file: %v", err)
	}
	reporter, err := newDataPlaneTrafficReporter(auth, "http://127.0.0.1:1", "", filepath.Join(parentFile, "traffic.json"))
	if err != nil {
		t.Fatalf("newDataPlaneTrafficReporter: %v", err)
	}
	if err := reporter.flush(context.Background()); err == nil {
		t.Fatal("checkpoint failure must be reported")
	}
	if sent, recv := user.GetTraffic(); sent != 20 || recv != 10 {
		t.Fatalf("checkpoint failure lost runtime traffic: sent=%d recv=%d", sent, recv)
	}
}

func TestDataPlaneTrafficReporterFailsClosedOnCorruptOutbox(t *testing.T) {
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.AddUser("traffic-hash"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	_, user := auth.AuthUser("traffic-hash")
	user.AddTraffic(20, 10)
	path := filepath.Join(t.TempDir(), "data-plane-traffic.json")
	if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
		t.Fatalf("write corrupt outbox: %v", err)
	}
	reporter, err := newDataPlaneTrafficReporter(auth, "http://127.0.0.1:1", "", path)
	if err != nil {
		t.Fatalf("newDataPlaneTrafficReporter: %v", err)
	}
	if reporter.loadErr == nil {
		t.Fatal("corrupt outbox must be retained as a load error")
	}
	if err := reporter.flush(context.Background()); err == nil {
		t.Fatal("corrupt outbox must block reporting")
	}
	if sent, recv := user.GetTraffic(); sent != 20 || recv != 10 {
		t.Fatalf("corrupt outbox must leave runtime traffic untouched: sent=%d recv=%d", sent, recv)
	}
}

func TestDataPlaneTrafficReporterRetriesSameBatch(t *testing.T) {
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if err := auth.AddUser("traffic-hash"); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	ok, user := auth.AuthUser("traffic-hash")
	if !ok {
		t.Fatal("added user not found")
	}
	user.AddTraffic(20, 10)

	var syncIDs []string
	attempt := 0
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch dataPlaneTrafficBatch
		if err := json.NewDecoder(r.Body).Decode(&batch); err != nil {
			t.Errorf("decode batch: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		syncIDs = append(syncIDs, batch.SyncID)
		attempt++
		if attempt == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	reporter, err := newDataPlaneTrafficReporter(auth, server.URL, "")
	if err != nil {
		t.Fatalf("newDataPlaneTrafficReporter: %v", err)
	}
	if err := reporter.flush(context.Background()); err == nil {
		t.Fatal("first failed HTTP response should return an error")
	}
	if reporter.pending == nil {
		t.Fatal("failed batch must remain pending")
	}
	if err := reporter.flush(context.Background()); err != nil {
		t.Fatalf("retry flush: %v", err)
	}
	if reporter.pending != nil {
		t.Fatal("accepted batch must be cleared")
	}
	if len(syncIDs) != 2 || syncIDs[0] == "" || syncIDs[0] != syncIDs[1] {
		t.Fatalf("retry must preserve Sync-ID, got %v", syncIDs)
	}
}

func TestDataPlaneTrafficReporterRejectsNonLoopback(t *testing.T) {
	ctx := config.WithConfig(context.Background(), memory.Name, &memory.Config{})
	auth, err := memory.NewAuthenticator(ctx)
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	if _, err := newDataPlaneTrafficReporter(auth, "http://192.0.2.10:8081/internal/control/v1/data-plane/traffic", ""); err == nil {
		t.Fatal("non-loopback traffic endpoint should be rejected")
	}
}
