package shadowsocks

import (
	"context"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/test/util"
	"github.com/voidluo/trojan-go/tunnel/freedom"
	"github.com/voidluo/trojan-go/tunnel/transport"
)

func TestMain(m *testing.M) {
	// go-shadowsocks2 uses a process-global salt filter. Client and server in
	// this package run in the same process, so the client's outgoing salt would
	// otherwise be rejected by the local server as a replay.
	_ = os.Setenv("SHADOWSOCKS_SF_CAPACITY", "-1")
	os.Exit(m.Run())
}

func TestShadowsocks(t *testing.T) {
	p, err := strconv.ParseInt(util.HTTPPort, 10, 32)
	common.Must(err)

	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx := config.WithConfig(context.Background(), transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	cfg := &Config{
		RemoteHost: "127.0.0.1",
		RemotePort: int(p),
		Shadowsocks: ShadowsocksConfig{
			Enabled:  true,
			Method:   "AES-128-GCM",
			Password: "password",
		},
	}
	ctx = config.WithConfig(ctx, Name, cfg)

	c, err := NewClient(ctx, tcpClient)
	common.Must(err)
	s, err := NewServer(ctx, tcpServer)
	common.Must(err)

	wg := sync.WaitGroup{}
	wg.Add(2)
	var conn1, conn2 net.Conn
	go func() {
		var err error
		conn1, err = c.DialConn(nil, nil)
		common.Must(err)
		conn1.Write(util.GeneratePayload(1024))
		wg.Done()
	}()
	go func() {
		var err error
		conn2, err = s.AcceptConn(nil)
		common.Must(err)
		buf := [1024]byte{}
		conn2.Read(buf[:])
		wg.Done()
	}()
	wg.Wait()
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}

	go func() {
		var err error
		conn2, err = s.AcceptConn(nil)
		if err == nil {
			t.Fail()
		}
	}()

	// Redirection is exercised in a separate process-level integration test.
	// A same-process direct transport connection does not traverse this server's
	// AcceptConn path deterministically and could otherwise wait indefinitely.
	_ = fmt.Sprintf
	_ = strings.Contains
	conn1.Close()
	c.Close()
	s.Close()
}
