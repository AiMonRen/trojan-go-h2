package mux

import "github.com/voidluo/trojan-go/config"

type MuxConfig struct {
	Enabled     bool `json:"enabled" yaml:"enabled"`
	IdleTimeout int  `json:"idle_timeout" yaml:"idle_timeout"`
	Concurrency int  `json:"concurrency" yaml:"concurrency"`
}

type Config struct {
	Mux MuxConfig `json:"mux" yaml:"mux"`
}

func init() {
	config.RegisterConfigCreator(Name, func() any {
		return &Config{
			Mux: MuxConfig{
				Enabled:     false,
				IdleTimeout: 60, // was 30s — longer idle window reduces session churn
				Concurrency: 8,  // was 16 — fewer parallel streams reduce head-of-line blocking on lossy links
			},
		}
	})
}
