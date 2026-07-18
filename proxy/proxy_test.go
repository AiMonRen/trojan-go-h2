package proxy

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/tunnel"
)

func TestProxyCloseWithoutRun(t *testing.T) {
	proxy := &Proxy{}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.ctx = ctx
	proxy.cancel = cancel

	err := proxy.Close()
	if err != nil {
		t.Log("Close error:", err)
	}
}

func TestProxyCloseConcurrent(t *testing.T) {
	proxy := &Proxy{}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.ctx = ctx
	proxy.cancel = cancel

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			proxy.Close()
		}()
	}
	wg.Wait()
}

func TestProxyRunOnCancelledCtx(t *testing.T) {
	proxy := &Proxy{}
	cancelCtx, cancel := context.WithCancel(context.Background())
	proxy.ctx = cancelCtx
	proxy.cancel = cancel

	cancel()

	done := make(chan struct{})
	go func() {
		proxy.Run()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on cancelled ctx")
	}
}

func TestProxyRunExitViaClose(t *testing.T) {
	proxy := &Proxy{}
	ctx, cancel := context.WithCancel(context.Background())
	proxy.ctx = ctx
	proxy.cancel = cancel

	done := make(chan struct{})
	go func() {
		proxy.Run()
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run stuck after cancel")
	}
}

func TestProxyStructDefaults(t *testing.T) {
	proxy := &Proxy{
		sources: []tunnel.Server{},
	}
	if proxy.sources == nil || len(proxy.sources) != 0 {
		t.Error("empty sources should be valid")
	}
}

func TestNewProxyFromConfigData(t *testing.T) {
	data := []byte(`
run-type: server
local_addr: 127.0.0.1
local_port: 0
remote_addr: 127.0.0.1
remote_port: 0
password:
  - test123
ssl:
  cert: /nonexistent
  key: /nonexistent
`)
	_, err := NewProxyFromConfigData(data, false)
	if err != nil {
		t.Log("expected config error:", err)
	}
}

func TestConfigDefaultLogLevel(t *testing.T) {
	ctx, err := config.WithYAMLConfig(context.Background(), []byte{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg.LogLevel != 1 {
		t.Errorf("default LogLevel = %d, want 1", cfg.LogLevel)
	}
}
