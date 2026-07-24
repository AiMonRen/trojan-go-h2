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
