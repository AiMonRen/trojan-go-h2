package transport

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	proxyProtocolV1MaxHeader = 108
	proxyProtocolTimeout     = 5 * time.Second
)

type proxyProtocolConn struct {
	net.Conn
	reader     *bufio.Reader
	remoteAddr net.Addr
	localAddr  net.Addr
}

func (c *proxyProtocolConn) Read(p []byte) (int, error) { return c.reader.Read(p) }
func (c *proxyProtocolConn) RemoteAddr() net.Addr       { return c.remoteAddr }
func (c *proxyProtocolConn) LocalAddr() net.Addr        { return c.localAddr }

// readProxyProtocolV1 accepts only the private gateway's explicit PROXY v1
// header. The listener must be bound to loopback when this mode is enabled.
func readProxyProtocolV1(conn net.Conn) (net.Conn, error) {
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); !ok || tcp.IP == nil || !tcp.IP.IsLoopback() {
		return nil, fmt.Errorf("PROXY protocol listener must bind to loopback, got %s", conn.LocalAddr())
	}
	if tcp, ok := conn.RemoteAddr().(*net.TCPAddr); !ok || tcp.IP == nil || !tcp.IP.IsLoopback() {
		return nil, fmt.Errorf("PROXY protocol connection must originate from loopback, got %s", conn.RemoteAddr())
	}
	_ = conn.SetReadDeadline(time.Now().Add(proxyProtocolTimeout))
	reader := bufio.NewReaderSize(conn, proxyProtocolV1MaxHeader)
	line, err := reader.ReadString('\n')
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("read PROXY protocol header: %w", err)
	}
	if len(line) > proxyProtocolV1MaxHeader || !strings.HasSuffix(line, "\r\n") {
		return nil, fmt.Errorf("invalid PROXY protocol header length or terminator")
	}
	fields := strings.Fields(strings.TrimSuffix(line, "\r\n"))
	if len(fields) == 2 && fields[0] == "PROXY" && fields[1] == "UNKNOWN" {
		return &proxyProtocolConn{Conn: conn, reader: reader, remoteAddr: conn.RemoteAddr(), localAddr: conn.LocalAddr()}, nil
	}
	if len(fields) != 6 || fields[0] != "PROXY" || (fields[1] != "TCP4" && fields[1] != "TCP6") {
		return nil, fmt.Errorf("unsupported PROXY protocol header")
	}
	sourceIP := net.ParseIP(fields[2])
	destinationIP := net.ParseIP(fields[3])
	if sourceIP == nil || destinationIP == nil {
		return nil, fmt.Errorf("invalid PROXY protocol IP address")
	}
	if fields[1] == "TCP4" && (sourceIP.To4() == nil || destinationIP.To4() == nil) {
		return nil, fmt.Errorf("PROXY TCP4 header contains a non-IPv4 address")
	}
	if fields[1] == "TCP6" && (sourceIP.To4() != nil || destinationIP.To4() != nil) {
		return nil, fmt.Errorf("PROXY TCP6 header contains a non-IPv6 address")
	}
	sourcePort, err := proxyProtocolPort(fields[4])
	if err != nil {
		return nil, fmt.Errorf("invalid PROXY source port: %w", err)
	}
	destinationPort, err := proxyProtocolPort(fields[5])
	if err != nil {
		return nil, fmt.Errorf("invalid PROXY destination port: %w", err)
	}
	return &proxyProtocolConn{
		Conn:       conn,
		reader:     reader,
		remoteAddr: &net.TCPAddr{IP: sourceIP, Port: sourcePort},
		localAddr:  &net.TCPAddr{IP: destinationIP, Port: destinationPort},
	}, nil
}

func proxyProtocolPort(raw string) (int, error) {
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %q is out of range", raw)
	}
	return port, nil
}
