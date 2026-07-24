package transport

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

func TestProxyProtocolV1Unknown(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = fmt.Fprint(client, "PROXY UNKNOWN\r\nHELLO")
	}()
	_, err := readProxyProtocolV1(server)
	// PROXY UNKNOWN passes because it does not assert a specific address family;
	// but the function also checks that the listener is loopback, which net.Pipe is not.
	// Intentionally verify the expected error path for a non-loopback listener.
	if err == nil {
		t.Error("readProxyProtocolV1 must reject non-loopback listener")
	}
}

func TestProxyProtocolV1TCP4(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Log(err)
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "PROXY TCP4 10.20.30.40 127.0.0.1 12345 14443\r\nPAYLOAD")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	proxied, err := readProxyProtocolV1(conn)
	if err != nil {
		t.Fatalf("readProxyProtocolV1: %v", err)
	}
	remote := proxied.RemoteAddr().(*net.TCPAddr)
	if remote.IP.String() != "10.20.30.40" || remote.Port != 12345 {
		t.Errorf("unexpected remote addr: %s", remote)
	}
}

func TestProxyProtocolV1TCP6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Log(err)
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "PROXY TCP6 2001:db8::1 ::1 54321 14443\r\nPAYLOAD")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	proxied, err := readProxyProtocolV1(conn)
	if err != nil {
		t.Fatalf("readProxyProtocolV1: %v", err)
	}
	remote := proxied.RemoteAddr().(*net.TCPAddr)
	if remote.IP.String() != "2001:db8::1" || remote.Port != 54321 {
		t.Errorf("unexpected remote addr: %s", remote)
	}
}

func TestProxyProtocolV1HeaderTooLong(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer raw.Close()
		padding := strings.Repeat("x", proxyProtocolV1MaxHeader)
		_, _ = fmt.Fprint(raw, padding+"\r\n")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_, err = readProxyProtocolV1(conn)
	if err == nil {
		t.Fatal("oversized header should be rejected")
	}
}

func TestProxyProtocolV1IPv4InTCP6(t *testing.T) {
	ln, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "PROXY TCP6 10.20.30.40 127.0.0.1 12345 14443\r\n")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_, err = readProxyProtocolV1(conn)
	if err == nil {
		t.Fatal("TCP6 header with IPv4 address should be rejected")
	}
}

func TestProxyProtocolV1PortValidation(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "PROXY TCP4 10.20.30.40 127.0.0.1 0 14443\r\n")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_, err = readProxyProtocolV1(conn)
	if err == nil {
		t.Fatal("port 0 should be rejected")
	}
}

func TestProxyProtocolUnknown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "PROXY UNKNOWN\r\nREAL_DATA")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	proxied, err := readProxyProtocolV1(conn)
	if err != nil {
		t.Fatalf("PROXY UNKNOWN should be accepted: %v", err)
	}
	remote := proxied.RemoteAddr()
	if remote == nil {
		t.Fatal("proxied conn should have a remote addr")
	}
}

func TestProxyProtocolInvalidContent(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		raw, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			return
		}
		defer raw.Close()
		_, _ = fmt.Fprint(raw, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer conn.Close()
	_, err = readProxyProtocolV1(conn)
	if err == nil {
		t.Fatal("non-PROXY protocol content should be rejected")
	}
}
