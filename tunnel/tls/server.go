package tls

import (
	"bufio"
	"bytes"
	"context"
	stdtls "crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/redirector"
	"github.com/voidluo/trojan-go/tunnel"
	"github.com/voidluo/trojan-go/tunnel/mux"
	"github.com/voidluo/trojan-go/tunnel/tls/fingerprint"
	"github.com/voidluo/trojan-go/tunnel/transport"
	"github.com/voidluo/trojan-go/tunnel/websocket"
)

// Server is a tls server
type Server struct {
	fallbackAddress    *tunnel.Address
	verifySNI          bool
	sni                string
	alpn               []string
	PreferServerCipher bool
	keyPair            []stdtls.Certificate
	keyPairLock        sync.RWMutex
	httpResp           []byte
	cipherSuite        []uint16
	sessionTicket      bool
	curve              []stdtls.CurveID
	keyLogger          io.WriteCloser
	connChan           chan tunnel.Conn
	wsChan             chan tunnel.Conn
	adminServer        *webserver.AdminServer
	adminPath          string
	subPath            string
	unauthRedirect     string
	redir              *redirector.Redirector
	ctx                context.Context
	cancel             context.CancelFunc
	underlay           tunnel.Server
	nextHTTP           int32
	portOverrider      map[string]int
}

func (s *Server) Close() error {
	s.cancel()
	if s.keyLogger != nil {
		s.keyLogger.Close()
	}
	return s.underlay.Close()
}

// GetAdminServer 返回管理面板服务器实例（如果已启用），
// 供上层（如 Trojan 协议层）绑定认证器。
func (s *Server) GetAdminServer() *webserver.AdminServer {
	return s.adminServer
}

func isDomainNameMatched(pattern string, domainName string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		domainPrefixLen := len(domainName) - len(suffix) - 1
		return strings.HasSuffix(domainName, suffix) && domainPrefixLen > 0 && !strings.Contains(domainName[:domainPrefixLen], ".")
	}
	return pattern == domainName
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Error(common.NewError("transport accept error").Base(err))
			}
			return
		}
		go func(conn net.Conn) {
			// 证书热重载协程会替换 keyPair；先在同一把锁下复制默认值，
			// 再交给 tls.Config，避免并发读写切片导致数据竞争。
			s.keyPairLock.RLock()
			certificates := append([]stdtls.Certificate(nil), s.keyPair...)
			s.keyPairLock.RUnlock()
			tlsConfig := &stdtls.Config{
				CipherSuites:             s.cipherSuite,
				PreferServerCipherSuites: s.PreferServerCipher,
				SessionTicketsDisabled:   !s.sessionTicket,
				NextProtos:               []string{"http/1.1"}, // 强制回退到 http/1.1 以匹配本地管理后台的解析能力
				KeyLogWriter:             s.keyLogger,
				Certificates:             certificates, // 注入默认证书作为绕过 SNI 匹配的兜底
				GetCertificate: func(hello *stdtls.ClientHelloInfo) (*stdtls.Certificate, error) {
					s.keyPairLock.RLock()
					defer s.keyPairLock.RUnlock()
					if len(s.keyPair) == 0 || s.keyPair[0].Leaf == nil {
						return nil, fmt.Errorf("tls: no valid certificate configured")
					}
					sni := s.keyPair[0].Leaf.Subject.CommonName
					dnsNames := s.keyPair[0].Leaf.DNSNames
					if s.sni != "" {
						sni = s.sni
					}
					matched := isDomainNameMatched(sni, hello.ServerName)
					for _, name := range dnsNames {
						if isDomainNameMatched(name, hello.ServerName) {
							matched = true
							break
						}
					}
					if s.verifySNI && !matched {
						// 记录不匹配日志但不再返回 nil，而是返回默认证书修正协议错误
						log.Trace("sni mismatched: " + hello.ServerName + ", providing default certificate")
					}
					return &s.keyPair[0], nil
				},
			}

			// ------------------------ WAR ZONE ----------------------------

			handshakeRewindConn := common.NewRewindConn(conn)
			handshakeRewindConn.SetBufferSize(4096) // 稍微增大缓冲区以兼容复杂的 ClientHello

			tlsConn := stdtls.Server(handshakeRewindConn, tlsConfig)
			err = tlsConn.Handshake()

			if err != nil {
				// 核心回归：无论是“非 TLS 流量”还是“TLS 协商失败”，无条件回落
				handshakeRewindConn.Rewind()
				log.Error(common.NewError("failed to perform tls handshake with " + tlsConn.RemoteAddr().String() + ", redirecting").Base(err))
				switch {
				case s.fallbackAddress != nil:
					s.redir.Redirect(&redirector.Redirection{
						InboundConn: handshakeRewindConn,
						RedirectTo:  s.fallbackAddress,
					})
				case s.httpResp != nil:
					handshakeRewindConn.Write(s.httpResp)
					handshakeRewindConn.Close()
				default:
					handshakeRewindConn.Close()
				}
				return
			}

			// 握手结束后，必须停止 TLS 握手层缓冲以防内存泄露
			handshakeRewindConn.StopBuffering()

			log.Info("tls connection from", conn.RemoteAddr())
			state := tlsConn.ConnectionState()
			log.Trace("tls handshake", stdtls.CipherSuiteName(state.CipherSuite), state.DidResume, state.NegotiatedProtocol)

			// we use a real http header parser to mimic a real http server
			rewindConn := common.NewRewindConn(tlsConn)
			rewindConn.SetBufferSize(1024)
			r := bufio.NewReader(rewindConn)
			httpReq, err := http.ReadRequest(r)
			rewindConn.Rewind()
			// HTTP 嗅探后也必须停止缓冲，否则后续 Web 面板数据会塞满内存
			rewindConn.StopBuffering()

			if err != nil {
				// this is not a http request. pass it to trojan protocol layer for further inspection
				s.connChan <- &transport.Conn{
					Conn: rewindConn,
				}
			} else {
				if s.adminServer != nil && (s.subPath != "" && httpReq.URL.Path == s.subPath || s.adminPath != "" && strings.HasPrefix(httpReq.URL.Path, s.adminPath)) {
					log.Debug("incoming http request, routing to admin panel")
					s.adminServer.ServeConn(rewindConn)
					return
				}
				if atomic.LoadInt32(&s.nextHTTP) != 1 {
					// there is no websocket layer waiting for connections, redirect/camouflage it
					if s.unauthRedirect != "" {
						log.Debug("incoming http request, redirecting to unauth_redirect target:", s.unauthRedirect)
						resp := fmt.Sprintf("HTTP/1.1 302 Found\r\nLocation: %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", s.unauthRedirect)
						rewindConn.Write([]byte(resp))
						rewindConn.Close()
					} else if s.fallbackAddress != nil {
						log.Error("incoming http request, but no websocket server is listening, redirecting")
						s.redir.Redirect(&redirector.Redirection{
							InboundConn: rewindConn,
							RedirectTo:  s.fallbackAddress,
						})
					} else if s.httpResp != nil {
						log.Debug("incoming http request, handling with plain http response")
						rewindConn.Write(s.httpResp)
						rewindConn.Close()
					} else {
						log.Error("incoming http request, but no websocket server is listening and no fallback")
						rewindConn.Close()
					}
					return
				}
				// this is a http request, pass it to websocket protocol layer
				log.Debug("http req: ", httpReq)
				s.wsChan <- &transport.Conn{
					Conn: rewindConn,
				}
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	if _, ok := overlay.(*websocket.Tunnel); ok {
		atomic.StoreInt32(&s.nextHTTP, 1)
		log.Debug("next proto http")
		// websocket overlay
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	// trojan overlay
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) checkKeyPairLoop(checkRate time.Duration, keyPath string, certPath string, password string) {
	var lastKeyBytes, lastCertBytes []byte
	ticker := time.NewTicker(checkRate)

	for {
		log.Debug("checking cert...")
		keyBytes, err := os.ReadFile(keyPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check key").Base(err))
			continue
		}
		certBytes, err := os.ReadFile(certPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check cert").Base(err))
			continue
		}
		if !bytes.Equal(keyBytes, lastKeyBytes) || !bytes.Equal(lastCertBytes, certBytes) {
			log.Info("new key pair detected")
			keyPair, err := loadKeyPair(keyPath, certPath, password)
			if err != nil {
				log.Error(common.NewError("tls failed to load new key pair").Base(err))
				continue
			}
			s.keyPairLock.Lock()
			s.keyPair = []stdtls.Certificate{*keyPair}
			s.keyPairLock.Unlock()
			lastKeyBytes = keyBytes
			lastCertBytes = certBytes
		}

		select {
		case <-ticker.C:
			continue
		case <-s.ctx.Done():
			log.Debug("exiting")
			ticker.Stop()
			return
		}
	}
}

func loadKeyPair(keyPath string, certPath string, password string) (*stdtls.Certificate, error) {
	if password != "" {
		keyFile, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, common.NewError("failed to load key file").Base(err)
		}
		keyBlock, _ := pem.Decode(keyFile)
		if keyBlock == nil {
			return nil, common.NewError("failed to decode key file").Base(err)
		}
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err == nil {
			return nil, common.NewError("failed to decrypt key").Base(err)
		}

		certFile, err := os.ReadFile(certPath)
		certBlock, _ := pem.Decode(certFile)
		if certBlock == nil {
			return nil, common.NewError("failed to decode cert file").Base(err)
		}

		keyPair, err := stdtls.X509KeyPair(certBlock.Bytes, decryptedKey)
		if err != nil {
			return nil, err
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, common.NewError("failed to parse leaf certificate").Base(err)
		}

		return &keyPair, nil
	}
	keyPair, err := stdtls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, common.NewError("failed to load key pair").Base(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, common.NewError("failed to parse leaf certificate").Base(err)
	}
	return &keyPair, nil
}

// NewServer creates a tls layer server
func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfgAny := config.FromContext(ctx, Name)
	if cfgAny == nil {
		return nil, common.NewError("tls server configuration not found")
	}
	cfg, ok := cfgAny.(*Config)
	if !ok {
		return nil, common.NewError("invalid tls server configuration type")
	}

	var fallbackAddress *tunnel.Address
	var httpResp []byte
	if cfg.TLS.FallbackPort != 0 {
		if cfg.TLS.FallbackHost == "" {
			cfg.TLS.FallbackHost = cfg.RemoteHost
			log.Warn("empty tls fallback address")
		}
		fallbackAddress = tunnel.NewAddressFromHostPort("tcp", cfg.TLS.FallbackHost, cfg.TLS.FallbackPort)
		fallbackConn, err := net.Dial("tcp", fallbackAddress.String())
		if err != nil {
			log.Warn(common.NewError("fallback target is unreachable at startup, but proceeding anyway").Base(err))
		} else {
			fallbackConn.Close()
		}
	} else {
		log.Warn("empty tls fallback port")
		if cfg.TLS.HTTPResponseFileName != "" {
			httpRespBody, err := os.ReadFile(cfg.TLS.HTTPResponseFileName)
			if err != nil {
				return nil, common.NewError("invalid response file").Base(err)
			}
			httpResp = httpRespBody
		} else {
			log.Warn("empty tls http response")
		}
	}

	keyPair, err := loadKeyPair(cfg.TLS.KeyPath, cfg.TLS.CertPath, cfg.TLS.KeyPassword)
	if err != nil {
		return nil, common.NewError("tls failed to load key pair")
	}

	var keyLogger io.WriteCloser
	if cfg.TLS.KeyLogPath != "" {
		log.Warn("tls key logging activated. USE OF KEY LOGGING COMPROMISES SECURITY. IT SHOULD ONLY BE USED FOR DEBUGGING.")
		file, err := os.OpenFile(cfg.TLS.KeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, common.NewError("failed to open key log file").Base(err)
		}
		keyLogger = file
	}

	var cipherSuite []uint16
	if len(cfg.TLS.Cipher) != 0 {
		cipherSuite = fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":"))
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay:           underlay,
		fallbackAddress:    fallbackAddress,
		httpResp:           httpResp,
		verifySNI:          cfg.TLS.VerifyHostName,
		sni:                cfg.TLS.SNI,
		alpn:               cfg.TLS.ALPN,
		PreferServerCipher: cfg.TLS.PreferServerCipher,
		sessionTicket:      cfg.TLS.ReuseSession,
		connChan:           make(chan tunnel.Conn, 32),
		wsChan:             make(chan tunnel.Conn, 32),
		redir:              redirector.NewRedirector(ctx),
		keyPair:            []stdtls.Certificate{*keyPair},
		keyLogger:          keyLogger,
		cipherSuite:        cipherSuite,
		ctx:                ctx,
		cancel:             cancel,
		subPath:            cfg.Admin.SubPath,
		unauthRedirect:     cfg.Admin.UnauthRedirect,
	}

	if cfg.Admin.Enabled {
		if strings.TrimSpace(cfg.Admin.Password) == "" {
			return nil, common.NewError("admin panel is enabled but admin.password is empty")
		}
		db, err := database.InitDb(cfg.Admin.DbPath)
		if err != nil {
			log.Warn("admin panel: failed to init db:", err)
		} else {
			wsEnabled := false
			wsPath := "/"
			if wsCfgAny := config.FromContext(ctx, websocket.Name); wsCfgAny != nil {
				wsCfg := wsCfgAny.(*websocket.Config)
				wsEnabled = wsCfg.Websocket.Enabled
				wsPath = wsCfg.Websocket.Path
			}
			muxEnabled := false
			if muxCfgAny := config.FromContext(ctx, mux.Name); muxCfgAny != nil {
				muxCfg := muxCfgAny.(*mux.Config)
				muxEnabled = muxCfg.Mux.Enabled
			}

			isNode := false
			if nodeCfgAny := config.FromContext(ctx, nodesync.Name); nodeCfgAny != nil {
				nodeCfg := nodeCfgAny.(*nodesync.Config)
				isNode = nodeCfg.Node.Enabled
			}

			serverDomain := cfg.TLS.SNI
			if serverDomain == "" {
				serverDomain = cfg.RemoteHost
			}

			server.adminServer = webserver.New(db, cfg.Admin.Username, cfg.Admin.Password, cfg.Admin.Path, cfg.Admin.Port, wsEnabled, wsPath, muxEnabled, isNode, cfg.Admin.MaskHtmlPath, cfg.Admin.SubPath, serverDomain)
			server.adminPath = cfg.Admin.Path
			log.Infof("admin panel enabled on https://[domain]%s (user: %s)", cfg.Admin.Path, cfg.Admin.Username)
		}
	}

	go server.acceptLoop()
	if cfg.TLS.CertCheckRate > 0 {
		go server.checkKeyPairLoop(
			time.Second*time.Duration(cfg.TLS.CertCheckRate),
			cfg.TLS.KeyPath,
			cfg.TLS.CertPath,
			cfg.TLS.KeyPassword,
		)
	}

	log.Debug("tls server created")
	return server, nil
}
