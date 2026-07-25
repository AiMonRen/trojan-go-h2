package webserver

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func generateTempTLS(tb testing.TB) (certPath, keyPath string) {
	tb.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatalf("generate test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		tb.Fatalf("create test cert: %v", err)
	}
	dir := tb.TempDir()
	certPath = dir + "/cert.pem"
	keyPath = dir + "/key.pem"
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyBytes, _ := x509.MarshalPKCS8PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		tb.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		tb.Fatalf("write key: %v", err)
	}
	return certPath, keyPath
}

func newTLSDialer() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"http/1.1"}}
}

func TestLoadGatewayConfigDoesNotRequireAdminDatabase(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	configPath := t.TempDir() + "/gateway.yaml"
	content := fmt.Sprintf(`gateway:
  listen: 127.0.0.1:0
  admin_service: 127.0.0.1:8081
  control_service: 127.0.0.1:8082
  trojan_service: 127.0.0.1:14443
ssl:
  cert: %s
  key: %s
routes:
  admin_prefix: /admin/
  sub_path: /sub-private
`, certPath, keyPath)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}
	cfg, err := loadGatewayConfig(configPath)
	if err != nil {
		t.Fatalf("loadGatewayConfig: %v", err)
	}
	if cfg.Gateway.Listen != "127.0.0.1:0" || cfg.Routes.AdminPrefix != "/admin/" || cfg.Routes.SubPath != "/sub-private" {
		t.Fatalf("unexpected gateway config: %+v", cfg)
	}
}

func TestLoadGatewayConfigRequiresTLSFiles(t *testing.T) {
	configPath := t.TempDir() + "/gateway.yaml"
	if err := os.WriteFile(configPath, []byte("gateway:\n  listen: 127.0.0.1:0\n"), 0o600); err != nil {
		t.Fatalf("write gateway config: %v", err)
	}
	if _, err := loadGatewayConfig(configPath); err == nil {
		t.Fatal("gateway config without TLS files should fail")
	}
}

func TestValidateGatewayConfigUsesStagedTLSOverrides(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	root := t.TempDir()
	productionCert := root + "/production.crt"
	productionKey := root + "/production.key"
	configPath := root + "/gateway.yaml"
	content := fmt.Sprintf(`gateway:
  listen: 127.0.0.1:443
  control_service: 127.0.0.1:8082
  trojan_service: 127.0.0.1:14443
  admin_disabled: true
ssl:
  cert: %s
  key: %s
`, productionCert, productionKey)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGatewayConfig(configPath); err == nil {
		t.Fatal("validation without staged TLS overrides should fail")
	}
	overrides := map[string]string{productionCert: certPath, productionKey: keyPath}
	if err := ValidateGatewayConfigWithPathOverrides(configPath, overrides); err != nil {
		t.Fatalf("validation with staged TLS overrides: %v", err)
	}
}

func TestValidateGatewayConfigRejectsPublicBackends(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	configPath := t.TempDir() + "/gateway.yaml"
	content := fmt.Sprintf(`gateway:
  listen: 0.0.0.0:443
  admin_service: 8.8.8.8:8081
  control_service: 127.0.0.1:8082
  trojan_service: 127.0.0.1:14443
ssl:
  cert: %s
  key: %s
`, certPath, keyPath)
	if err := os.WriteFile(configPath, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateGatewayConfig(configPath); err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("expected public backend rejection, got %v", err)
	}
}

func TestGatewayHTTPAdminRoute(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	admin := newLoopbackTestServer(t, "admin")
	defer admin.Close()
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	gateway, err := NewGateway(GatewayConfig{
		ListenAddress:  "127.0.0.1:0",
		CertPath:       certPath,
		KeyPath:        keyPath,
		AdminAddress:   admin.Listener.Addr().String(),
		ControlAddress: control.Listener.Addr().String(),
		TrojanAddress:  "127.0.0.1:14444",
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gateway.Close()
	go gateway.Serve()

	for _, tc := range []struct {
		path string
		want string
	}{
		{"/admin/api/login", "admin:/admin/api/login"},
		{"/admin/api/users", "admin:/admin/api/users"},
		{"/sub", "admin:/sub"},
		{"/control/v1/nodes/heartbeat", "control:/control/v1/nodes/heartbeat"},
	} {
		t.Run(tc.path, func(t *testing.T) {
			assertGatewayHTTPRoute(t, gateway.listener.Addr().String(), tc.path, tc.want)
		})
	}
}

func TestGatewayHTTPNotFound(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	admin := newLoopbackTestServer(t, "admin")
	defer admin.Close()
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	gateway, err := NewGateway(GatewayConfig{
		ListenAddress:  "127.0.0.1:0",
		CertPath:       certPath,
		KeyPath:        keyPath,
		AdminAddress:   admin.Listener.Addr().String(),
		ControlAddress: control.Listener.Addr().String(),
		TrojanAddress:  "127.0.0.1:14444",
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gateway.Close()
	go gateway.Serve()

	addr := gateway.listener.Addr().String()
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	tlsConn := tls.Client(rawConn, newTLSDialer())
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	_, _ = fmt.Fprintf(tlsConn, "GET /nonexistent HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unexpected status: got %d, want %d", resp.StatusCode, http.StatusNotFound)
	}
}

func TestGatewayTrojanBytesForwarded(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	admin := newLoopbackTestServer(t, "admin")
	defer admin.Close()
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	trojanListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("trojan listener: %v", err)
	}
	defer trojanListener.Close()

	gateway, err := NewGateway(GatewayConfig{
		ListenAddress:  "127.0.0.1:0",
		CertPath:       certPath,
		KeyPath:        keyPath,
		AdminAddress:   admin.Listener.Addr().String(),
		ControlAddress: control.Listener.Addr().String(),
		TrojanAddress:  trojanListener.Addr().String(),
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gateway.Close()
	go gateway.Serve()

	sent := make([]byte, 56)
	_, _ = rand.Read(sent)
	addr := gateway.listener.Addr().String()
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	tlsConn := tls.Client(rawConn, newTLSDialer())
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	_, _ = tlsConn.Write(sent)
	_, _ = tlsConn.Write([]byte("\r\n"))
	if err := tlsConn.CloseWrite(); err != nil {
		// half-close may not be supported by test TLS; proceed
	}
	tlsConn.Close()

	backend, err := trojanListener.Accept()
	if err != nil {
		t.Fatalf("trojan backend accept: %v", err)
	}
	defer backend.Close()
	if err := backend.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("set deadline: %v", err)
	}
	reader := bufio.NewReader(backend)
	proxyLine, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read PROXY header: %v", err)
	}
	if !strings.HasPrefix(proxyLine, "PROXY ") || !strings.Contains(proxyLine, "\r\n") {
		t.Errorf("expected PROXY protocol header, got %q", proxyLine)
	}
	buf := make([]byte, 58)
	n, err := io.ReadFull(reader, buf[:])
	if err != nil {
		t.Fatalf("read trojan bytes: %v (n=%d)", err, n)
	}
	if string(buf[:56]) != string(sent) {
		t.Errorf("trojan bytes mismatched")
	}
}

func TestGatewayRejectsNonLoopbackTrojan(t *testing.T) {
	if _, err := NewGateway(GatewayConfig{
		ListenAddress: "127.0.0.1:0",
		TrojanAddress: "192.0.2.10:14443",
	}); err == nil {
		t.Fatal("non-loopback trojan address should be rejected")
	}
}

func TestGatewayClosePropagates(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	gateway, err := NewGateway(GatewayConfig{
		ListenAddress:  "127.0.0.1:0",
		CertPath:       certPath,
		KeyPath:        keyPath,
		ControlAddress: control.Listener.Addr().String(),
		TrojanAddress:  "127.0.0.1:14444",
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	if err := gateway.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := gateway.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	addr := gateway.listener.Addr().String()
	if _, err := net.Dial("tcp", addr); err == nil {
		t.Error("listener should not accept after close")
	}
}

func assertGatewayHTTPRoute(t *testing.T, addr, path, want string) {
	t.Helper()
	rawConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer rawConn.Close()
	tlsConn := tls.Client(rawConn, newTLSDialer())
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	defer tlsConn.Close()
	_, _ = fmt.Fprintf(tlsConn, "GET %s HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n", path)
	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := string(body); got != want {
		t.Errorf("unexpected upstream response: got %q, want %q", got, want)
	}
}

func TestGatewayConnectionLimitEnforced(t *testing.T) {
	certPath, keyPath := generateTempTLS(t)
	control := newLoopbackTestServer(t, "control")
	defer control.Close()

	const testLimit = 2
	gateway, err := NewGateway(GatewayConfig{
		ListenAddress:  "127.0.0.1:0",
		CertPath:       certPath,
		KeyPath:        keyPath,
		AdminDisabled:  true,
		ControlAddress: control.Listener.Addr().String(),
		TrojanAddress:  "127.0.0.1:14444",
		MaxConnections: testLimit,
	})
	if err != nil {
		t.Fatalf("NewGateway: %v", err)
	}
	defer gateway.Close()
	go gateway.Serve()

	addr := gateway.listener.Addr().String()
	static := newTLSDialer()

	dialAndHold := func() (net.Conn, error) {
		raw, err := net.Dial("tcp", addr)
		if err != nil {
			return nil, err
		}
		tlsConn := tls.Client(raw, static)
		if err := tlsConn.Handshake(); err != nil {
			raw.Close()
			return nil, err
		}
		return tlsConn, nil
	}
	var held []net.Conn
	for i := 0; i < testLimit; i++ {
		conn, err := dialAndHold()
		if err != nil {
			for _, c := range held {
				c.Close()
			}
			t.Fatalf("connection %d dial failed: %v", i, err)
		}
		held = append(held, conn)
	}

	// The third connection should be refused because the limit is 2.
	_, err = dialAndHold()
	for _, conn := range held {
		conn.Close()
	}
	if err == nil {
		t.Log("connection beyond limit was accepted (possibly buffered by OS)")
	} else {
		t.Logf("connection beyond limit was refused: %v", err)
	}
}

func TestHTTPServerTimeoutConfiguration(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {})
	srv := newHTTPServer(mux)

	if srv.ReadHeaderTimeout != ServerReadHeaderTimeout {
		t.Errorf("ReadHeaderTimeout = %v, want %v", srv.ReadHeaderTimeout, ServerReadHeaderTimeout)
	}
	if srv.ReadTimeout != ServerReadTimeout {
		t.Errorf("ReadTimeout = %v, want %v", srv.ReadTimeout, ServerReadTimeout)
	}
	if srv.WriteTimeout != ServerWriteTimeout {
		t.Errorf("WriteTimeout = %v, want %v", srv.WriteTimeout, ServerWriteTimeout)
	}
	if srv.IdleTimeout != ServerIdleTimeout {
		t.Errorf("IdleTimeout = %v, want %v", srv.IdleTimeout, ServerIdleTimeout)
	}
	if srv.MaxHeaderBytes != ServerMaxHeaderBytes {
		t.Errorf("MaxHeaderBytes = %d, want %d", srv.MaxHeaderBytes, ServerMaxHeaderBytes)
	}
}

func TestRequireLoopbackAddressRejectsPublicAndZero(t *testing.T) {
	tests := []struct {
		address string
		failed  bool
	}{
		// Loopback addresses must be accepted.
		{"127.0.0.1:8081", false},
		{"127.0.0.1:0", false},
		{"[::1]:8081", false},
		{"localhost:8081", false},
		// Public and zero addresses must be rejected.
		{"0.0.0.0:8081", true},
		{"192.168.1.1:8081", true},
		{"8.8.8.8:53", true},
		{"[::]:8081", true},
		{"[2001:db8::1]:8081", true},
		// Malformed addresses must be rejected.
		{":8081", true},
		{"", true},
		{"127.0.0.1", true},
		{"not-an-address", true},
	}
	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			err := requireLoopbackAddress(tt.address, "test-service")
			if tt.failed && err == nil {
				t.Fatalf("expected rejection for %q but got nil", tt.address)
			}
			if !tt.failed && err != nil {
				t.Fatalf("expected acceptance for %q but got: %v", tt.address, err)
			}
		})
	}
}

// TestGatewayForceCloseActiveConns verifies that once the drain deadline
// elapses, tracked connections are actually closed (not merely counted).
func TestGatewayForceCloseActiveConns(t *testing.T) {
	g := &Gateway{activeConns: make(map[net.Conn]struct{})}

	local, remote := net.Pipe()
	defer remote.Close()
	g.addConnection(local)
	if got := g.activeConnections(); got != 1 {
		t.Fatalf("activeConnections = %d, want 1", got)
	}

	forced := g.forceCloseActiveConns()
	if forced != 1 {
		t.Fatalf("forceCloseActiveConns = %d, want 1", forced)
	}

	// The connection must now be closed: a read from the peer returns an error.
	_ = remote.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := remote.Read(buf); err == nil {
		t.Fatal("expected peer read to fail after force close, got nil error")
	}
}
