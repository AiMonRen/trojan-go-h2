package trojan

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/statistic/memory"
)

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

	reporter, err := newDataPlaneTrafficReporter(auth, server.URL)
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
	if _, err := newDataPlaneTrafficReporter(auth, "http://192.0.2.10:8081/internal/control/v1/data-plane/traffic"); err == nil {
		t.Fatal("non-loopback traffic endpoint should be rejected")
	}
}
