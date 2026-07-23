package actions

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// deploymentProxyConfig is the installer-owned representation of config.yaml.
// It deliberately contains only fields the installer writes, so installation
// defaults remain explicit and are independently testable from runtime parsing.
type deploymentProxyConfig struct {
	RunType    string                `yaml:"run_type"`
	LocalAddr  string                `yaml:"local_addr"`
	LocalPort  int                   `yaml:"local_port"`
	RemoteAddr string                `yaml:"remote_addr"`
	RemotePort int                   `yaml:"remote_port"`
	SSL        deploymentSSLConfig   `yaml:"ssl"`
	Mux        deploymentMuxConfig   `yaml:"mux"`
	WebSocket  deploymentWebSocket   `yaml:"websocket"`
	Admin      deploymentAdminConfig `yaml:"admin"`
	Node       *deploymentNodeConfig `yaml:"node,omitempty"`
	Log        deploymentLogConfig   `yaml:"log"`
}

type deploymentSSLConfig struct {
	Cert              string `yaml:"cert"`
	Key               string `yaml:"key"`
	SNI               string `yaml:"sni"`
	Verify            bool   `yaml:"verify"`
	VerifyHostname    bool   `yaml:"verify_hostname"`
	FallbackAddr      string `yaml:"fallback_addr,omitempty"`
	FallbackPort      int    `yaml:"fallback_port,omitempty"`
	PlainHTTPResponse string `yaml:"plain_http_response"`
}

type deploymentMuxConfig struct {
	Enabled bool `yaml:"enabled"`
}

type deploymentWebSocket struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
	Host    string `yaml:"host"`
}

type deploymentAdminConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	Port     int    `yaml:"port"`
	DB       string `yaml:"db"`
	Path     string `yaml:"path"`
	SubPath  string `yaml:"sub_path"`
}

type deploymentNodeConfig struct {
	Enabled      bool   `yaml:"enabled"`
	MasterURL    string `yaml:"master_url"`
	Secret       string `yaml:"secret"`
	SyncInterval int    `yaml:"sync_interval"`
}

type deploymentLogConfig struct {
	Level  int    `yaml:"level"`
	Access string `yaml:"access"`
	Error  string `yaml:"error"`
}

type deploymentWebConfig struct {
	RunType string                `yaml:"run_type"`
	Admin   deploymentAdminConfig `yaml:"admin"`
	Node    *deploymentWebNode    `yaml:"node,omitempty"`
}

type deploymentWebNode struct {
	Enabled bool `yaml:"enabled"`
}

type deploymentHysteriaConfig struct {
	Listen     string                      `yaml:"listen"`
	TLS        deploymentHysteriaTLS       `yaml:"tls"`
	Auth       deploymentHysteriaAuth      `yaml:"auth"`
	Masquerade deploymentHysteriaMask      `yaml:"masquerade"`
	QUIC       deploymentHysteriaQUIC      `yaml:"quic"`
	Bandwidth  deploymentHysteriaBandwidth `yaml:"bandwidth"`
}

type deploymentHysteriaTLS struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type deploymentHysteriaAuth struct {
	Type string                     `yaml:"type"`
	HTTP deploymentHysteriaHTTPAuth `yaml:"http"`
}

type deploymentHysteriaHTTPAuth struct {
	URL      string `yaml:"url"`
	Insecure bool   `yaml:"insecure"`
}

type deploymentHysteriaMask struct {
	Type  string                      `yaml:"type"`
	Proxy deploymentHysteriaMaskProxy `yaml:"proxy"`
}

type deploymentHysteriaMaskProxy struct {
	URL         string `yaml:"url"`
	RewriteHost bool   `yaml:"rewriteHost"`
}

type deploymentHysteriaQUIC struct {
	InitStreamReceiveWindow int    `yaml:"initStreamReceiveWindow"`
	MaxStreamReceiveWindow  int    `yaml:"maxStreamReceiveWindow"`
	InitConnReceiveWindow   int    `yaml:"initConnReceiveWindow"`
	MaxConnReceiveWindow    int    `yaml:"maxConnReceiveWindow"`
	MaxIdleTimeout          string `yaml:"maxIdleTimeout"`
	KeepAliveInterval       string `yaml:"keepAliveInterval"`
}

type deploymentHysteriaBandwidth struct {
	Up   string `yaml:"up"`
	Down string `yaml:"down"`
}

type deploymentCoreConfigInput struct {
	DeployPath string
	Domain     string
	CertPath   string
	KeyPath    string
	LocalPort  int
	AdminPort  int
	WSPath     string
	WSEnabled  bool
	AdminUser  string
	AdminPass  string
	DBPath     string
	SubPath    string
	Node       *deploymentNodeConfig
	Fallback   bool
}

type deploymentHysteriaConfigInput struct {
	ListenPort int
	CertPath   string
	KeyPath    string
	AdminPort  int
	UpMbps     int
	DownMbps   int
}

func buildMasterProxyConfig(input deploymentCoreConfigInput) ([]byte, error) {
	return marshalDeploymentYAML(newDeploymentProxyConfig(input))
}

func buildWorkerProxyConfig(input deploymentCoreConfigInput) ([]byte, error) {
	if input.Node == nil {
		return nil, fmt.Errorf("worker proxy configuration requires node synchronization settings")
	}
	return marshalDeploymentYAML(newDeploymentProxyConfig(input))
}

func newDeploymentProxyConfig(input deploymentCoreConfigInput) deploymentProxyConfig {
	ssl := deploymentSSLConfig{
		Cert:              input.CertPath,
		Key:               input.KeyPath,
		SNI:               input.Domain,
		Verify:            false,
		VerifyHostname:    false,
		PlainHTTPResponse: filepath.Join(input.DeployPath, "index.html"),
	}
	if input.Fallback {
		ssl.FallbackAddr = "127.0.0.1"
		ssl.FallbackPort = input.AdminPort
	}

	return deploymentProxyConfig{
		RunType:    "server",
		LocalAddr:  "0.0.0.0",
		LocalPort:  input.LocalPort,
		RemoteAddr: "127.0.0.1",
		RemotePort: input.AdminPort,
		SSL:        ssl,
		Mux:        deploymentMuxConfig{Enabled: true},
		WebSocket: deploymentWebSocket{
			Enabled: input.WSEnabled,
			Path:    input.WSPath,
			Host:    input.Domain,
		},
		Admin: deploymentAdminConfig{
			Enabled:  true,
			Username: input.AdminUser,
			Password: input.AdminPass,
			Port:     0,
			DB:       input.DBPath,
			Path:     "/admin",
			SubPath:  input.SubPath,
		},
		Node: input.Node,
		Log: deploymentLogConfig{
			Level:  1,
			Access: filepath.Join(input.DeployPath, "log", "trojan-go", "access.log"),
			Error:  filepath.Join(input.DeployPath, "log", "trojan-go", "error.log"),
		},
	}
}

func buildMasterWebConfig(adminUser, adminPass string, adminPort int, dbPath, subPath string) ([]byte, error) {
	return marshalDeploymentYAML(deploymentWebConfig{
		RunType: "server",
		Admin: deploymentAdminConfig{
			Enabled: true, Username: adminUser, Password: adminPass, Port: adminPort,
			DB: dbPath, Path: "/admin/", SubPath: subPath,
		},
	})
}

func buildWorkerWebConfig(adminUser, adminPass string, adminPort int, dbPath, subPath string) ([]byte, error) {
	return marshalDeploymentYAML(deploymentWebConfig{
		RunType: "server",
		Admin: deploymentAdminConfig{
			Enabled: true, Username: adminUser, Password: adminPass, Port: adminPort,
			DB: dbPath, Path: "/admin/", SubPath: subPath,
		},
		Node: &deploymentWebNode{Enabled: true},
	})
}

func buildHysteriaConfig(input deploymentHysteriaConfigInput) ([]byte, error) {
	return marshalDeploymentYAML(deploymentHysteriaConfig{
		Listen: fmt.Sprintf(":%d", input.ListenPort),
		TLS:    deploymentHysteriaTLS{Cert: input.CertPath, Key: input.KeyPath},
		Auth: deploymentHysteriaAuth{
			Type: "http",
			HTTP: deploymentHysteriaHTTPAuth{
				URL: fmt.Sprintf("http://127.0.0.1:%d/admin/api/hysteria/auth", input.AdminPort), Insecure: true,
			},
		},
		Masquerade: deploymentHysteriaMask{
			Type:  "proxy",
			Proxy: deploymentHysteriaMaskProxy{URL: "https://www.bilibili.com", RewriteHost: true},
		},
		QUIC: deploymentHysteriaQUIC{
			InitStreamReceiveWindow: 8_388_608,
			MaxStreamReceiveWindow:  8_388_608,
			InitConnReceiveWindow:   20_971_520,
			MaxConnReceiveWindow:    20_971_520,
			MaxIdleTimeout:          "60s",
			KeepAliveInterval:       "10s",
		},
		Bandwidth: deploymentHysteriaBandwidth{
			Up: fmt.Sprintf("%d mbps", input.UpMbps), Down: fmt.Sprintf("%d mbps", input.DownMbps),
		},
	})
}

// marshalDeploymentYAML validates the exact serialized bytes before they are
// written to disk. This catches incompatible tags or unsupported values at the
// installer boundary rather than after a systemd service has been started.
func marshalDeploymentYAML(value any) ([]byte, error) {
	data, err := yaml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal deployment YAML: %w", err)
	}
	var parsed any
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("validate deployment YAML: %w", err)
	}
	return data, nil
}
