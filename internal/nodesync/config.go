package nodesync

import "github.com/voidluo/trojan-go/config"

const Name = "NODE_SYNC"

type Config struct {
	Node NodeConfig `json:"node" yaml:"node"`
}

type NodeConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	MasterURL    string `json:"master_url" yaml:"master_url"`
	Secret       string `json:"secret" yaml:"secret"`
	SyncInterval int    `json:"sync_interval" yaml:"sync_interval"`
}

func init() {
	config.RegisterConfigCreator(Name, func() any {
		return &Config{
			Node: NodeConfig{
				SyncInterval: 30,
			},
		}
	})
}
