package webserver

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// captureClientHello opens a real TLS client handshake against a raw TCP
// listener and returns the first TLS record the client sent (the ClientHello).
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	recordCh := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			recordCh <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		var header [5]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			recordCh <- nil
			return
		}
		recordLen := int(header[3])<<8 | int(header[4])
		body := make([]byte, recordLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			recordCh <- nil
			return
		}
		full := make([]byte, 0, 5+recordLen)
		full = append(full, header[:]...)
		full = append(full, body...)
		recordCh <- full
	}()

	// The handshake is expected to fail (no server certificate); we only need
	// the ClientHello bytes that the client emits first.
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	tlsConn := tls.Client(conn, &tls.Config{ServerName: serverName})
	_ = tlsConn.SetDeadline(time.Now().Add(3 * time.Second))
	_ = tlsConn.Handshake() // error is expected and ignored

	select {
	case record := <-recordCh:
		if record == nil {
			t.Fatal("failed to capture ClientHello")
		}
		return record
	case <-time.After(5 * time.Second):
		t.Fatal("timeout capturing ClientHello")
		return nil
	}
}

// TestExtractSNIFromRealClientHello guards the contract that extractSNI takes a
// complete TLS record *including* the 5-byte record header. Passing only the
// record body silently broke SNI-based relay routing before.
func TestExtractSNIFromRealClientHello(t *testing.T) {
	for _, want := range []string{
		"xjp.liteops.top",
		"jp.liteops.top",
		"a.example.com",
	} {
		record := captureClientHello(t, want)

		if got := extractSNI(record); got != want {
			t.Errorf("extractSNI(full record) = %q, want %q", got, want)
		}

		// Regression guard: the body-only slice must NOT parse, which is
		// exactly the mistake that disabled relay routing.
		if got := extractSNI(record[5:]); got == want {
			t.Errorf("extractSNI(body only) unexpectedly returned %q; "+
				"callers must pass the full record including the header", got)
		}
	}
}

func TestExtractSNIRejectsMalformedInput(t *testing.T) {
	cases := map[string][]byte{
		"empty":            {},
		"short":            {0x16, 0x03, 0x01},
		"not handshake":    {0x17, 0x03, 0x01, 0x00, 0x05, 1, 2, 3, 4, 5},
		"truncated record": {0x16, 0x03, 0x01, 0xff, 0xff, 0x01},
	}
	for name, data := range cases {
		if got := extractSNI(data); got != "" {
			t.Errorf("%s: extractSNI = %q, want empty", name, got)
		}
	}
}

// TestPrefixConnReplaysBytes verifies the buffered ClientHello is handed back to
// the normal (non-relay) code path instead of being swallowed.
func TestPrefixConnReplaysBytes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	prefix := []byte("HELLO-PREFIX")
	tail := []byte("-TAIL")

	go func() {
		_, _ = client.Write(tail)
		_ = client.Close()
	}()

	pc := &prefixConn{Conn: server, prefix: append([]byte(nil), prefix...)}
	got, err := io.ReadAll(pc)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := string(prefix) + string(tail)
	if string(got) != want {
		t.Errorf("prefixConn read = %q, want %q", got, want)
	}
}
