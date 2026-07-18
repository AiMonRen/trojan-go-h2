package transport

import (
	"bufio"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/tunnel"
)

type Server struct {
	tcpListener net.Listener
	cmd         *exec.Cmd
	connChan    chan tunnel.Conn
	wsChan      chan tunnel.Conn
	httpLock    sync.RWMutex
	nextHTTP    bool
	ctx         context.Context
	cancel      context.CancelFunc
}

func (s *Server) Close() error {
	s.cancel()
	if s.cmd != nil && s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return s.tcpListener.Close()
}

func (s *Server) acceptLoop() {
	for {
		tcpConn, err := s.tcpListener.Accept()
		if err != nil {
			if s.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			log.Error(common.NewError("transport accept error").Base(err))
			return
		}
		go func(tcpConn net.Conn) {
			s.httpLock.RLock()
			plaintext := s.nextHTTP
			s.httpLock.RUnlock()
			if plaintext {
				rewindConn := common.NewRewindConn(tcpConn)
				rewindConn.SetBufferSize(512)
				defer rewindConn.StopBuffering()
				_, err := http.ReadRequest(bufio.NewReader(rewindConn))
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				if err != nil {
					select {
					case s.connChan <- &Conn{Conn: rewindConn}:
					case <-s.ctx.Done():
						_ = rewindConn.Close()
					}
				} else {
					select {
					case s.wsChan <- &Conn{Conn: rewindConn}:
					case <-s.ctx.Done():
						_ = rewindConn.Close()
					}
				}
				return
			}
			select {
			case s.connChan <- &Conn{Conn: tcpConn}:
			case <-s.ctx.Done():
				_ = tcpConn.Close()
			}
		}(tcpConn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	if overlay != nil && (overlay.Name() == "WEBSOCKET" || overlay.Name() == "HTTP") {
		s.httpLock.Lock()
		s.nextHTTP = true
		s.httpLock.Unlock()
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}
func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) { panic("not supported") }

func (s *Server) startPlugin(cfg *Config) (*exec.Cmd, error) {
	if !cfg.TransportPlugin.Enabled || cfg.TransportPlugin.Type == "plaintext" {
		return nil, nil
	}
	cmd := exec.Command(cfg.TransportPlugin.Command, cfg.TransportPlugin.Arg...)
	cmd.Env = append(os.Environ(), cfg.TransportPlugin.Env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	if err := cmd.Start(); err == nil {
		return cmd, nil
	} else if !strings.ContainsAny(cfg.TransportPlugin.Command, "$;&|<>") {
		return nil, common.NewError("failed to start transport plugin").Base(err)
	}
	shell, args := "sh", []string{"-c", cfg.TransportPlugin.Command}
	if runtime.GOOS == "windows" {
		shell, args = "cmd", []string{"/C", cfg.TransportPlugin.Command}
	}
	cmd = exec.Command(shell, args...)
	cmd.Env = append(os.Environ(), cfg.TransportPlugin.Env...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stdout
	if err := cmd.Start(); err != nil {
		return nil, common.NewError("failed to start transport plugin").Base(err)
	}
	return cmd, nil
}

func NewServer(ctx context.Context, _ tunnel.Server) (*Server, error) {
	cfgAny := config.FromContext(ctx, Name)
	cfg, ok := cfgAny.(*Config)
	if !ok || cfg == nil {
		return nil, common.NewError("transport server configuration not found")
	}
	listenAddress := tunnel.NewAddressFromHostPort("tcp", cfg.LocalHost, cfg.LocalPort)
	cmd, err := (&Server{}).startPlugin(cfg)
	if err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp", listenAddress.String())
	if err != nil {
		if cmd != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		return nil, common.NewError("failed to listen transport").Base(err)
	}
	childCtx, cancel := context.WithCancel(ctx)
	s := &Server{tcpListener: listener, cmd: cmd, connChan: make(chan tunnel.Conn, 32), wsChan: make(chan tunnel.Conn, 32), ctx: childCtx, cancel: cancel}
	go s.acceptLoop()
	return s, nil
}
