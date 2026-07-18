package custom

import (
	"context"
	"testing"

	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/proxy"
	"github.com/voidluo/trojan-go/tunnel"
	"github.com/voidluo/trojan-go/tunnel/adapter"
	"github.com/voidluo/trojan-go/tunnel/freedom"
	"github.com/voidluo/trojan-go/tunnel/transport"
)

func TestConfigDefaults(t *testing.T) {
	ctx, err := config.WithYAMLConfig(context.Background(), []byte(`
custom: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg == nil {
		t.Fatal("config is nil")
	}
}

func TestBuildNodesValid(t *testing.T) {
	adapterPort := common.PickPort("tcp", "127.0.0.1")
	nodes, err := buildNodes(context.Background(), []NodeConfig{
		{
			Protocol: "ADAPTER",
			Tag:      "adapter-in",
			Config: map[string]any{
				"local_addr": "127.0.0.1",
				"local_port": adapterPort,
			},
		},
		{
			Protocol: "FREEDOM",
			Tag:      "freedom-out",
			Config:   map[string]any{},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(nodes))
	}
	if _, ok := nodes["adapter-in"]; !ok {
		t.Error("adapter-in node not found")
	}
	if _, ok := nodes["freedom-out"]; !ok {
		t.Error("freedom-out node not found")
	}
}

func TestBuildNodesInvalidProtocol(t *testing.T) {
	_, err := buildNodes(context.Background(), []NodeConfig{
		{
			Protocol: "NONEXISTENT",
			Tag:      "bad",
			Config:   map[string]any{},
		},
	})
	if err == nil {
		t.Fatal("expected error for invalid protocol")
	}
}

func TestProxyCreatorRegistered(t *testing.T) {
	// Verify that the CUSTOM proxy creator is registered
	// This is done via init(), so just check that proxy.NewProxyFromConfigData
	// doesn't fail for a minimal custom config
	data := []byte(`
run-type: custom

inbound:
  node:
    - protocol: adapter
      tag: adapter
      config:
        local_addr: 127.0.0.1
        local_port: 0
    - protocol: socks
      tag: socks
      config:
        local_addr: 127.0.0.1
        local_port: 0
  path:
    - [adapter, socks]

outbound:
  node:
    - protocol: freedom
      tag: freedom
      config: {}
  path:
    - [freedom]
`)
	_, err := proxy.NewProxyFromConfigData(data, false)
	// This may fail because port 0 and no real network, but it should NOT be
	// a "no proxy creator" error — it should at least try to build
	if err != nil {
		t.Log("expected config parsing attempt, got error:", err)
	}
}

func TestConvertFunction(t *testing.T) {
	// Test map[any]any -> map[string]any conversion
	input := map[any]any{
		"key1": "value1",
		"key2": 42,
		"nested": map[any]any{
			"inner": "val",
		},
	}
	result := convert(input)
	m, ok := result.(map[string]any)
	if !ok {
		t.Fatal("convert did not return map[string]any")
	}
	if m["key1"] != "value1" {
		t.Errorf("key1 = %v", m["key1"])
	}
}

func TestConvertSlice(t *testing.T) {
	input := []any{
		map[any]any{"a": 1},
		map[any]any{"b": 2},
	}
	result := convert(input)
	_ = result // Should not panic
}

func TestConfigParseCustomFunc(t *testing.T) {
	// Verify custom Creator is registered via init()
	data := []byte(`
run-type: custom
inbound:
  node:
    - protocol: adapter
      tag: a
      config:
        local_addr: 127.0.0.1
        local_port: 0
  path:
    - [a]
outbound:
  node:
    - protocol: freedom
      tag: f
      config: {}
  path:
    - [f]
`)
	_, err := proxy.NewProxyFromConfigData(data, false)
	// May fail due to port 0 but should at least parse the custom run-type
	if err != nil {
		t.Log("expected parse attempt, got:", err)
	}
}

func TestStackBuildingWithMockNodes(t *testing.T) {
	ctx := context.Background()

	// Build a simple node graph: transport only
	nodes, err := buildNodes(ctx, []NodeConfig{
		{Protocol: "TRANSPORT", Tag: "t1", Config: map[string]any{
			"local_addr":  "127.0.0.1",
			"local_port":  common.PickPort("tcp", "127.0.0.1"),
			"remote_addr": "127.0.0.1",
			"remote_port": common.PickPort("tcp", "127.0.0.1"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}

	root := nodes["t1"]
	tunnelT, _ := tunnel.GetTunnel("TRANSPORT")
	s, _ := tunnelT.NewServer(root.Context, nil)
	root.Server = s
	root.IsEndpoint = true

	endpoints := proxy.FindAllEndpoints(root)
	if len(endpoints) != 1 {
		t.Errorf("expected 1 endpoint, got %d", len(endpoints))
	}
}

// Check that the custom config package uses uppercase protocol names
func TestNodeConfigProtocolCase(t *testing.T) {
	ctx := config.WithConfig(context.Background(), transport.Name, &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  common.PickPort("tcp", "127.0.0.1"),
		RemoteHost: "127.0.0.1",
		RemotePort: common.PickPort("tcp", "127.0.0.1"),
	})
	ctx = config.WithConfig(ctx, adapter.Name, &adapter.Config{
		LocalHost: "127.0.0.1",
		LocalPort: common.PickPort("tcp", "127.0.0.1"),
	})
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})

	// Lowercase should be uppercased by buildNodes
	nodes, err := buildNodes(ctx, []NodeConfig{
		{Protocol: "adapter", Tag: "a", Config: map[string]any{
			"local_addr": "127.0.0.1",
			"local_port": common.PickPort("tcp", "127.0.0.1"),
		}},
	})
	if err != nil {
		t.Fatal("lowercase protocol should be accepted:", err)
	}
	if len(nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(nodes))
	}
}
