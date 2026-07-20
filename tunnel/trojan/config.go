package trojan

import "github.com/voidluo/trojan-go/config"

type Config struct {
	LocalHost        string      `json:"local_addr" yaml:"local_addr"`
	LocalPort        int         `json:"local_port" yaml:"local_port"`
	RemoteHost       string      `json:"remote_addr" yaml:"remote_addr"`
	RemotePort       int         `json:"remote_port" yaml:"remote_port"`
	DisableHTTPCheck bool        `json:"disable_http_check" yaml:"disable_http_check"`
	FlushTimeout     int         `json:"flush_timeout" yaml:"flush_timeout"` // ms, 0=disable auto-flush
	MySQL            MySQLConfig `json:"mysql" yaml:"mysql"`
	API              APIConfig   `json:"api" yaml:"api"`
}

type MySQLConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type APIConfig struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

func init() {
	config.RegisterConfigCreator(Name, func() any {
		return &Config{}
	})
}
