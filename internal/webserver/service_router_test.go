package webserver

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestServiceRouterMatchesControlPlanePaths(t *testing.T) {
	router, err := NewServiceRouter("127.0.0.1:18081", "127.0.0.1:18082", "/admin/", "/sub-token")
	if err != nil {
		t.Fatalf("NewServiceRouter: %v", err)
	}
	defer router.Close()
	for _, path := range []string{"/admin", "/admin/", "/admin/api/login", "/control/v1/nodes/sync", "/sub", "/sub-token"} {
		if !router.Matches(path) {
			t.Errorf("router should match %q", path)
		}
	}
	for _, path := range []string{"/", "/control/v2/nodes/sync", "/not-found"} {
		if router.Matches(path) {
			t.Errorf("router should not match %q", path)
		}
	}
}

func TestServiceRouterCanDisableAdminRoutes(t *testing.T) {
	router, err := NewServiceRouter("", "127.0.0.1:18082", "/admin/", "/sub-token")
	if err != nil {
		t.Fatalf("NewServiceRouter: %v", err)
	}
	defer router.Close()
	if router.Matches("/admin/") || router.Matches("/sub-token") || router.Matches("/sub") {
		t.Fatal("admin and subscription routes must be disabled")
	}
	if !router.Matches("/control/v1/hysteria/auth") {
		t.Fatal("control routes must remain enabled")
	}
}

func TestServiceRouterRejectsNonLoopbackUpstreams(t *testing.T) {
	if _, err := NewServiceRouter("192.0.2.10:8081", "127.0.0.1:8082", "/admin/", "/sub"); err == nil {
		t.Fatal("admin-service non-loopback upstream should be rejected")
	}
	if _, err := NewServiceRouter("127.0.0.1:8081", "192.0.2.10:8082", "/admin/", "/sub"); err == nil {
		t.Fatal("control-service non-loopback upstream should be rejected")
	}
}

func TestServiceRouterForwardsRecognizedPathsToCorrectService(t *testing.T) {
	admin := newLoopbackTestServer(t, "admin")
	defer admin.Close()
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	router, err := NewServiceRouter(admin.Listener.Addr().String(), control.Listener.Addr().String(), "/ops", "/sub-token")
	if err != nil {
		t.Fatalf("NewServiceRouter: %v", err)
	}
	defer router.Close()

	for _, test := range []struct {
		path string
		want string
	}{
		{path: "/ops/api/login", want: "admin:/ops/api/login"},
		{path: "/sub-token", want: "admin:/sub-token"},
		{path: "/control/v1/nodes/heartbeat", want: "control:/control/v1/nodes/heartbeat"},
	} {
		t.Run(test.path, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			router.ServeConn(server)
			if _, err := fmt.Fprintf(client, "GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", test.path); err != nil {
				t.Fatalf("write request: %v", err)
			}
			_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
			resp, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			defer resp.Body.Close()
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}
			if got := string(body); got != test.want {
				t.Errorf("unexpected upstream response: got %q, want %q", got, test.want)
			}
		})
	}
}

func newLoopbackTestServer(t *testing.T, service string) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, service+":"+r.URL.Path)
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen test backend: %v", err)
	}
	server.Listener = listener
	server.Start()
	if !strings.HasPrefix(server.Listener.Addr().String(), "127.0.0.1:") {
		t.Fatalf("test backend must be loopback, got %s", server.Listener.Addr())
	}
	return server
}
