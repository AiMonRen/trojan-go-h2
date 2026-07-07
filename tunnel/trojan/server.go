package trojan

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"

	"github.com/voidluo/trojan-go/api"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/redirector"
	"github.com/voidluo/trojan-go/statistic"
	"github.com/voidluo/trojan-go/statistic/memory"
	"github.com/voidluo/trojan-go/statistic/mysql"
	"github.com/voidluo/trojan-go/tunnel"
	"github.com/voidluo/trojan-go/tunnel/mux"
)

// InboundConn is a trojan inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth     statistic.Authenticator
	user     statistic.User
	hash     string
	metadata *tunnel.Metadata
	ip       string
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddTraffic(n, 0)
	return n, err
}

func (c *InboundConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddTraffic(0, n)
	return n, err
}

func (c *InboundConn) Close() error {
	log.Info("user", c.hash, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address, "closed",
		"sent:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

func (c *InboundConn) Auth() error {
	userHash := [56]byte{}
	n, err := c.Conn.Read(userHash[:])
	if err != nil || n != 56 {
		return common.NewError("failed to read hash").Base(err)
	}

	valid, user := c.auth.AuthUser(string(userHash[:]))
	if !valid {
		return common.NewError("invalid hash:" + string(userHash[:]))
	}
	c.hash = string(userHash[:])
	c.user = user

	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}

	c.ip = ip
	ok := user.AddIP(ip)
	if !ok {
		return common.NewError("ip limit reached")
	}

	crlf := [2]byte{}
	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}

	c.metadata = &tunnel.Metadata{}
	if err := c.metadata.ReadFrom(c.Conn); err != nil {
		return err
	}

	_, err = io.ReadFull(c.Conn, crlf[:])
	if err != nil {
		return err
	}
	return nil
}

// Server is a trojan tunnel server
type Server struct {
	auth       statistic.Authenticator
	redir      *redirector.Redirector
	redirAddr  *tunnel.Address
	underlay   tunnel.Server
	connChan   chan tunnel.Conn
	muxChan    chan tunnel.Conn
	packetChan chan tunnel.PacketConn
	ctx        context.Context
	cancel     context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("trojan failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(128)
			defer rewindConn.StopBuffering()

			inboundConn := &InboundConn{
				Conn: rewindConn,
				auth: s.auth,
			}

			if err := inboundConn.Auth(); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("connection with invalid trojan header from " + rewindConn.RemoteAddr().String()).Base(err))
				if s.redirAddr.Port != 0 {
					s.redir.Redirect(&redirector.Redirection{
						RedirectTo:  s.redirAddr,
						InboundConn: rewindConn,
					})
				} else {
					rewindConn.Close()
				}
				return
			}

			rewindConn.StopBuffering()
			switch inboundConn.metadata.Command {
			case Connect:
				if inboundConn.metadata.DomainName == "MUX_CONN" {
					s.muxChan <- inboundConn
					log.Debug("mux(r) connection")
				} else {
					s.connChan <- inboundConn
					log.Info("user", inboundConn.hash, "from", inboundConn.Conn.RemoteAddr(), "proxied to", inboundConn.metadata.Address)
				}

			case Associate:
				s.packetChan <- &PacketConn{
					Conn: inboundConn,
				}
				log.Info("user", inboundConn.hash, "from", inboundConn.Conn.RemoteAddr(), "proxied(udp) to", inboundConn.metadata.Address)
			case Mux:
				s.muxChan <- inboundConn
				log.Info("user", inboundConn.hash, "from", inboundConn.Conn.RemoteAddr(), "mux connection")
			default:
				log.Error(common.NewError(fmt.Sprintf("unknown trojan command %d", inboundConn.metadata.Command)))
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(nextTunnel tunnel.Tunnel) (tunnel.Conn, error) {
	switch nextTunnel.(type) {
	case *mux.Tunnel:
		select {
		case t := <-s.muxChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	default:
		select {
		case t := <-s.connChan:
			return t, nil
		case <-s.ctx.Done():
			return nil, common.NewError("trojan client closed")
		}
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	select {
	case t := <-s.packetChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("trojan client closed")
	}
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)

	// TODO replace this dirty code
	var auth statistic.Authenticator
	var err error
	if cfg.MySQL.Enabled {
		log.Debug("mysql enabled")
		auth, err = statistic.NewAuthenticator(ctx, mysql.Name)
	} else {
		log.Debug("auth by config file")
		auth, err = statistic.NewAuthenticator(ctx, memory.Name)
	}
	if err != nil {
		cancel()
		return nil, common.NewError("trojan failed to create authenticator")
	}

	// 尝试从 underlay 链中获取 AdminServer，将数据库用户同步到认证器
	// underlay 可能是 TLS Server（直接），也可能是 WebSocket Server（间接）
	syncAdminAuth(underlay, auth)

	// 如果开启了多节点从节点模式，将 authenticator 注册到节点同步管理器中
	if nodeCfgAny := config.FromContext(ctx, nodesync.Name); nodeCfgAny != nil {
		nodeCfg := nodeCfgAny.(*nodesync.Config)
		if nodeCfg.Node.Enabled {
			if mgr := nodesync.GetManager(); mgr != nil {
				mgr.AddAuthenticator(auth)
				log.Info("node sync manager: registered proxy authenticator")
			}
		}
	}

	if cfg.API.Enabled {
		go api.RunService(ctx, Name+"_SERVER", auth)
	}

	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	s := &Server{
		underlay:   underlay,
		auth:       auth,
		redirAddr:  redirAddr,
		connChan:   make(chan tunnel.Conn, 32),
		muxChan:    make(chan tunnel.Conn, 32),
		packetChan: make(chan tunnel.PacketConn, 32),
		ctx:        ctx,
		cancel:     cancel,
		redir:      redirector.NewRedirector(ctx),
	}

	if !cfg.DisableHTTPCheck && cfg.RemotePort > 0 {
		redirConn, err := net.Dial("tcp", redirAddr.String())
		if err != nil {
			cancel()
			return nil, common.NewError("invalid redirect address. check your http server: " + redirAddr.String()).Base(err)
		}
		redirConn.Close()
	}

	go s.acceptLoop()
	log.Debug("trojan server created")
	return s, nil
}

// adminServerProvider 定义了提供 AdminServer 访问能力的接口。
// TLS Server 实现了此接口。
type adminServerProvider interface {
	GetAdminServer() *webserver.AdminServer
}

// underlayProvider 定义了获取下层 Server 的接口，用于穿透 WebSocket 等中间层。
type underlayProvider interface {
	GetUnderlay() tunnel.Server
}

// syncAdminAuth 尝试从 underlay 链中找到 AdminServer 并绑定认证器。
func syncAdminAuth(underlay tunnel.Server, auth statistic.Authenticator) {
	// 直接检查 underlay 是否提供 AdminServer（TLS Server）
	if p, ok := underlay.(adminServerProvider); ok {
		if admin := p.GetAdminServer(); admin != nil {
			admin.SetAuth(auth)
			log.Info("admin server auth sync: bound to proxy authenticator")
			return
		}
	}
	// 如果 underlay 是中间层（如 WebSocket），尝试穿透获取下层
	if p, ok := underlay.(underlayProvider); ok {
		syncAdminAuth(p.GetUnderlay(), auth)
	}
}
