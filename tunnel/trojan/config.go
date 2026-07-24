package trojan

import "github.com/voidluo/trojan-go/config"

type Config struct {
	LocalHost        string      `json:"local_addr" yaml:"local_addr"`
	LocalPort        int         `json:"local_port" yaml:"local_port"`
	RemoteHost       string      `json:"remote_addr" yaml:"remote_addr"`
	RemotePort       int         `json:"remote_port" yaml:"remote_port"`
	DisableHTTPCheck bool        `json:"disable_http_check" yaml:"disable_http_check"`
	FlushTimeout     int         `json:"flush_timeout" yaml:"flush_timeout"` // ms, 0=disable auto-flush
	AuthDB           string      `json:"auth_db" yaml:"auth_db"`
	AuthRefresh      int         `json:"auth_refresh" yaml:"auth_refresh"` // seconds, defaults to 30
	TrafficReport    string      `json:"traffic_report" yaml:"traffic_report"`
	TrafficInterval  int         `json:"traffic_interval" yaml:"traffic_interval"` // seconds, defaults to 30
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
