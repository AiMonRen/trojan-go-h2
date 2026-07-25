package freedom

import (
	"context"
	"net"
	"syscall"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/tunnel"
)

type Client struct {
	preferIPv4   bool
	noDelay      bool
	keepAlive    bool
	fastOpen     bool
	socketBuffer int
	dialTimeout  time.Duration
	ctx          context.Context
	cancel       context.CancelFunc
	forwardProxy bool
	proxyAddr    *tunnel.Address
	username     string
	password     string
}

func (c *Client) DialConn(addr *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	// forward proxy
	if c.forwardProxy {
		var auth *proxy.Auth
		if c.username != "" {
			auth = &proxy.Auth{
				User:     c.username,
				Password: c.password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", c.proxyAddr.String(), auth, proxy.Direct)
		if err != nil {
			return nil, common.NewError("freedom failed to init socks dialer")
		}
		conn, err := dialer.Dial("tcp", addr.String())
		if err != nil {
			return nil, common.NewError("freedom failed to dial target address via socks proxy " + addr.String()).Base(err)
		}
		return &Conn{
			Conn: conn,
		}, nil
	}
	network := "tcp"
	if c.preferIPv4 {
		network = "tcp4"
	}
	dialer := &net.Dialer{
		Timeout: c.dialTimeout,
		Control: func(network, address string, rawConn syscall.RawConn) error {
			var operr error
			err := rawConn.Control(func(fd uintptr) {
				if c.fastOpen {
					// Enable TCP_FASTOPEN_CONNECT on Linux.
					// This allows the kernel to send data in the SYN packet,
					// saving one full RTT on reconnections to known hosts.
					// Silently ignored on non-Linux or kernels < 4.11.
					operr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, 23, 1) // TCP_FASTOPEN_CONNECT=23
				}
			})
			if err != nil {
				return err
			}
			return operr
		},
	}
	tcpConn, err := dialer.DialContext(c.ctx, network, addr.String())
	if err != nil {
		return nil, common.NewError("freedom failed to dial " + addr.String()).Base(err)
	}

	tcpConn.(*net.TCPConn).SetKeepAlive(c.keepAlive)
	tcpConn.(*net.TCPConn).SetNoDelay(c.noDelay)
	// Configurable socket buffer size.
	// On high-BDP links (e.g. cross-ISP), larger buffers improve throughput.
	// Values above the OS limit (net.core.rmem_max/wmem_max) are silently clamped.
	bufSize := c.socketBuffer * 1024
	if bufSize <= 0 {
		bufSize = 256 * 1024
	}
	tcpConn.(*net.TCPConn).SetReadBuffer(bufSize)
	tcpConn.(*net.TCPConn).SetWriteBuffer(bufSize)
	return &Conn{
		Conn: tcpConn,
	}, nil
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	if c.forwardProxy {
		socksClient, err := socks5.NewClient(c.proxyAddr.String(), c.username, c.password, 0, 0)
		common.Must(err)
		if err := socksClient.Negotiate(&net.TCPAddr{}); err != nil {
			return nil, common.NewError("freedom failed to negotiate socks").Base(err)
		}
		a, addr, port, err := socks5.ParseAddress("1.1.1.1:53") // useless address
		common.Must(err)
		resp, err := socksClient.Request(socks5.NewRequest(socks5.CmdUDP, a, addr, port))
		if err != nil {
			return nil, common.NewError("freedom failed to dial udp to socks").Base(err)
		}
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, common.NewError("freedom failed to listen udp").Base(err)
		}
		socksAddr, err := net.ResolveUDPAddr("udp", resp.Address())
		if err != nil {
			return nil, common.NewError("freedom recv invalid socks bind addr").Base(err)
		}
		return &SocksPacketConn{
			PacketConn:  packetConn,
			socksAddr:   socksAddr,
			socksClient: socksClient,
		}, nil
	}
	network := "udp"
	if c.preferIPv4 {
		network = "udp4"
	}
	udpConn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, common.NewError("freedom failed to listen udp socket").Base(err)
	}
	return &PacketConn{
		UDPConn: udpConn.(*net.UDPConn),
	}, nil
}

func (c *Client) Close() error {
	c.cancel()
	return nil
}

func NewClient(ctx context.Context, _ tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	addr := tunnel.NewAddressFromHostPort("tcp", cfg.ForwardProxy.ProxyHost, cfg.ForwardProxy.ProxyPort)
	ctx, cancel := context.WithCancel(ctx)
	return &Client{
		ctx:          ctx,
		cancel:       cancel,
		noDelay:      cfg.TCP.NoDelay,
		keepAlive:    cfg.TCP.KeepAlive,
		preferIPv4:   cfg.TCP.PreferIPV4,
		fastOpen:     cfg.TCP.FastOpen,
		socketBuffer: cfg.TCP.SocketBuffer,
		dialTimeout:  time.Duration(cfg.TCP.DialTimeout) * time.Second,
		forwardProxy: cfg.ForwardProxy.Enabled,
		proxyAddr:    addr,
		username:     cfg.ForwardProxy.Username,
		password:     cfg.ForwardProxy.Password,
	}, nil
}
