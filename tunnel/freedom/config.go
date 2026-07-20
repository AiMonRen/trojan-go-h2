package freedom

import "github.com/voidluo/trojan-go/config"

type Config struct {
	LocalHost    string             `json:"local_addr" yaml:"local_addr"`
	LocalPort    int                `json:"local_port" yaml:"local_port"`
	TCP          TCPConfig          `json:"tcp" yaml:"tcp"`
	ForwardProxy ForwardProxyConfig `json:"forward_proxy" yaml:"forward_proxy"`
}

type TCPConfig struct {
	PreferIPV4   bool `json:"prefer_ipv4" yaml:"prefer_ipv4"`
	KeepAlive    bool `json:"keep_alive" yaml:"keep_alive"`
	NoDelay      bool `json:"no_delay" yaml:"no_delay"`
	FastOpen     bool `json:"fast_open" yaml:"fast_open"`
	SocketBuffer int  `json:"socket_buffer" yaml:"socket_buffer"` // KB, 0=use default(256)
	DialTimeout  int  `json:"dial_timeout" yaml:"dial_timeout"`   // seconds, 0=system default
}

type ForwardProxyConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	ProxyHost string `json:"proxy_addr" yaml:"proxy_addr"`
	ProxyPort int    `json:"proxy_port" yaml:"proxy_port"`
	Username  string `json:"username" yaml:"username"`
	Password  string `json:"password" yaml:"password"`
}

func init() {
	config.RegisterConfigCreator(Name, func() any {
		return &Config{
			TCP: TCPConfig{
				PreferIPV4:   false,
				NoDelay:      true,
				KeepAlive:    true,
				FastOpen:     false,
				SocketBuffer: 256,
				DialTimeout:  10,
			},
		}
	})
}
