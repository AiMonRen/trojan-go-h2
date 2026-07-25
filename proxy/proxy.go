package proxy

import (
	"context"
	"io"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"github.com/voidluo/trojan-go/tunnel"
)

const Name = "PROXY"

const (
	MaxPacketSize = 1024 * 8
)

// Proxy relay connections and packets
type Proxy struct {
	sources []tunnel.Server
	sink    tunnel.Client
	ctx     context.Context
	cancel  context.CancelFunc

	authCtx   context.Context
	closeOnce sync.Once
	workers   sync.WaitGroup
}

func (p *Proxy) Run() error {
	p.relayConnLoop()
	p.relayPacketLoop()
	select {
	case <-p.ctx.Done():
	case <-common.ShutdownContext().Done():
		log.Info("proxy shutting down via global signal")
	}
	return p.Close()
}

func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		p.cancel()
		if p.sink != nil {
			_ = p.sink.Close()
		}
		for _, source := range p.sources {
			_ = source.Close()
		}
	})
	p.workers.Wait()
	if p.authCtx != nil {
		if err := statistic.CloseAuthenticator(p.authCtx); err != nil {
			log.Warn("failed to close proxy authenticator:", err)
		}
	}
	return nil
}

func (p *Proxy) relayConnLoop() {
	for _, source := range p.sources {
		p.workers.Add(1)
		go func(source tunnel.Server) {
			defer p.workers.Done()
			for {
				inbound, err := source.AcceptConn(nil)
				if err != nil {
					select {
					case <-p.ctx.Done():
						log.Debug("exiting")
						return
					default:
					}
					log.Error(common.NewError("failed to accept connection").Base(err))
					select {
					case <-time.After(100 * time.Millisecond):
					case <-p.ctx.Done():
						return
					}
					continue
				}
				go func(inbound tunnel.Conn) {
					defer inbound.Close()
					outbound, err := p.sink.DialConn(inbound.Metadata().Address, nil)
					if err != nil {
						log.Error(common.NewError("proxy failed to dial connection").Base(err))
						return
					}
					defer outbound.Close()
					errChan := make(chan error, 2)
					var wg sync.WaitGroup
					wg.Add(2)
					copyConn := func(a, b net.Conn) {
						defer wg.Done()
						buf := common.GetBuffer()
						defer common.PutBuffer(buf)
						_, err := io.CopyBuffer(a, b, buf)
						errChan <- err
					}
					go copyConn(inbound, outbound)
					go copyConn(outbound, inbound)
					select {
					case err = <-errChan:
						if err != nil {
							log.Error(err)
						}
					case <-p.ctx.Done():
						log.Debug("shutting down conn relay")
					}
					inbound.Close()
					outbound.Close()
					wg.Wait() // 确保 copyConn goroutine 完成 buffer 归还
					log.Debug("conn relay ends")
				}(inbound)
			}
		}(source)
	}
}

func (p *Proxy) relayPacketLoop() {
	for _, source := range p.sources {
		p.workers.Add(1)
		go func(source tunnel.Server) {
			defer p.workers.Done()
			for {
				inbound, err := source.AcceptPacket(nil)
				if err != nil {
					select {
					case <-p.ctx.Done():
						log.Debug("exiting")
						return
					default:
					}
					log.Error(common.NewError("failed to accept packet").Base(err))
					select {
					case <-time.After(100 * time.Millisecond):
					case <-p.ctx.Done():
						return
					}
					continue
				}
				go func(inbound tunnel.PacketConn) {
					defer inbound.Close()
					outbound, err := p.sink.DialPacket(nil)
					if err != nil {
						log.Error(common.NewError("proxy failed to dial packet").Base(err))
						return
					}
					defer outbound.Close()
					errChan := make(chan error, 2)
					var wg sync.WaitGroup
					wg.Add(2)
					copyPacket := func(a, b tunnel.PacketConn) {
						defer wg.Done()
						buf := common.GetBuffer()
						defer common.PutBuffer(buf)
						for {
							n, metadata, err := a.ReadWithMetadata(buf)
							if err != nil {
								errChan <- err
								return
							}
							if n == 0 {
								errChan <- nil
								return
							}
							_, err = b.WriteWithMetadata(buf[:n], metadata)
							if err != nil {
								errChan <- err
								return
							}
						}
					}
					go copyPacket(inbound, outbound)
					go copyPacket(outbound, inbound)
					select {
					case err = <-errChan:
						if err != nil {
							log.Error(err)
						}
					case <-p.ctx.Done():
						log.Debug("shutting down packet relay")
					}
					inbound.Close()
					outbound.Close()
					wg.Wait() // 确保 copyPacket goroutine 完成 buffer 归还
					log.Debug("packet relay ends")
				}(inbound)
			}
		}(source)
	}
}

func NewProxy(ctx context.Context, cancel context.CancelFunc, sources []tunnel.Server, sink tunnel.Client) *Proxy {
	return &Proxy{
		sources: sources,
		sink:    sink,
		ctx:     ctx,
		cancel:  cancel,
		authCtx: ctx,
	}
}

type Creator func(ctx context.Context) (*Proxy, error)

var creators = make(map[string]Creator)

func RegisterProxyCreator(name string, creator Creator) {
	creators[name] = creator
}

func NewProxyFromConfigData(data []byte, isJSON bool) (*Proxy, error) {
	// create a unique context for each proxy instance to avoid duplicated authenticator
	ctx := context.WithValue(context.Background(), Name+"_ID", rand.Int())
	var err error
	if isJSON {
		ctx, err = config.WithJSONConfig(ctx, data)
		if err != nil {
			return nil, err
		}
	} else {
		ctx, err = config.WithYAMLConfig(ctx, data)
		if err != nil {
			return nil, err
		}
	}
	cfgAny := config.FromContext(ctx, Name)
	if cfgAny == nil {
		return nil, common.NewError("proxy configuration not found in context")
	}
	cfg, ok := cfgAny.(*Config)
	if !ok {
		return nil, common.NewError("invalid proxy configuration type")
	}
	create, ok := creators[strings.ToUpper(cfg.RunType)]
	if !ok {
		return nil, common.NewError("unknown proxy type: " + cfg.RunType)
	}
	log.SetLogLevel(log.LogLevel(cfg.LogLevel))
	if cfg.LogFile != "" {
		file, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return nil, common.NewError("failed to open log file").Base(err)
		}
		log.SetOutput(file)
	}

	// 初始化从节点同步管理器
	if nodeCfgAny := config.FromContext(ctx, nodesync.Name); nodeCfgAny != nil {
		if nodeCfg, ok := nodeCfgAny.(*nodesync.Config); ok && nodeCfg.Node.Enabled {
			if nodeCfg.Node.TrafficOutbox == "" {
				return nil, common.NewError("worker node synchronization requires node.traffic_outbox")
			}
			nodesync.InitManager(nodeCfg.Node.MasterURL, nodeCfg.Node.Secret, nodeCfg.Node.SyncInterval, nodeCfg.Node.TrafficOutbox)
			if mgr := nodesync.GetManager(); mgr != nil {
				mgr.Start(ctx)
			}
		}
	}

	return create(ctx)
}
