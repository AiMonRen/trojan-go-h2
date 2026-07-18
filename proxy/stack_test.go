package proxy

import (
	"context"
	"testing"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/tunnel"
	"github.com/voidluo/trojan-go/tunnel/freedom"
	"github.com/voidluo/trojan-go/tunnel/transport"
)

func TestCreateClientStack(t *testing.T) {
	ctx := config.WithConfig(context.Background(), freedom.Name, &freedom.Config{})
	client, err := CreateClientStack(ctx, []string{freedom.Name})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("client is nil")
	}
}

func TestCreateClientStackMultiLayer(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	ctx := config.WithConfig(context.Background(), transport.Name, &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	})
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})

	client, err := CreateClientStack(ctx, []string{transport.Name, freedom.Name})
	if err != nil {
		t.Fatal(err)
	}
	if client == nil {
		t.Fatal("multi-layer client is nil")
	}
	client.Close()
}

func TestCreateClientStackInvalidTunnel(t *testing.T) {
	_, err := CreateClientStack(context.Background(), []string{"NONEXISTENT"})
	if err == nil {
		t.Fatal("expected error for non-existent tunnel")
	}
}

func TestCreateClientStackEmpty(t *testing.T) {
	client, err := CreateClientStack(context.Background(), []string{})
	if err != nil {
		t.Fatal(err)
	}
	_ = client
}

func TestCreateServerStackEmpty(t *testing.T) {
	server, err := CreateServerStack(context.Background(), []string{})
	if err != nil {
		t.Fatal(err)
	}
	_ = server
}

func TestNodeStructBasics(t *testing.T) {
	n := &Node{
		Name:       "test-node",
		Next:       make(map[string]*Node),
		IsEndpoint: true,
		Context:    context.Background(),
	}
	if n.Name != "test-node" {
		t.Errorf("Name = %q", n.Name)
	}
	if len(n.Next) != 0 {
		t.Error("Next should be empty")
	}
	if !n.IsEndpoint {
		t.Error("IsEndpoint should be true")
	}
	if n.Context == nil {
		t.Error("Context should not be nil")
	}
}

func TestFindAllEndpointsSingle(t *testing.T) {
	n := &Node{Name: "e", IsEndpoint: true, Next: make(map[string]*Node)}
	endpoints := FindAllEndpoints(n)
	if len(endpoints) != 1 {
		t.Errorf("expected 1, got %d", len(endpoints))
	}
}

func TestFindAllEndpointsTree(t *testing.T) {
	root := &Node{Name: "root", Next: make(map[string]*Node)}
	child1 := &Node{Name: "c1", IsEndpoint: true, Next: make(map[string]*Node)}
	child2 := &Node{Name: "c2", IsEndpoint: true, Next: make(map[string]*Node)}
	root.Next[child1.Name] = child1
	root.Next[child2.Name] = child2

	endpoints := FindAllEndpoints(root)
	if len(endpoints) != 2 {
		t.Errorf("expected 2, got %d", len(endpoints))
	}
}

func TestFindAllEndpointsDeep(t *testing.T) {
	root := &Node{Name: "root", Next: make(map[string]*Node)}
	mid := &Node{Name: "mid", Next: make(map[string]*Node)}
	leaf := &Node{Name: "leaf", IsEndpoint: true, Next: make(map[string]*Node)}
	root.Next[mid.Name] = mid
	mid.Next[leaf.Name] = leaf

	endpoints := FindAllEndpoints(root)
	if len(endpoints) != 1 {
		t.Errorf("expected 1 deep endpoint, got %d", len(endpoints))
	}
}

func TestGetTunnel(t *testing.T) {
	tr, err := tunnel.GetTunnel(transport.Name)
	if err != nil {
		t.Fatal(err)
	}
	if tr.Name() != transport.Name {
		t.Errorf("Name() = %q", tr.Name())
	}
}

func TestGetTunnelInvalid(t *testing.T) {
	_, err := tunnel.GetTunnel("INVALID_TUNNEL")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestNodeNextMapManipulation(t *testing.T) {
	root := &Node{Next: make(map[string]*Node)}
	child := &Node{Name: "child", Next: make(map[string]*Node)}

	root.Next[child.Name] = child
	if _, ok := root.Next["child"]; !ok {
		t.Error("child not added to Next map")
	}
}
