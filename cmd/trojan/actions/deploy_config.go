package actions

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

const (
	defaultGatewayPort        = 443
	defaultAdminServicePort   = 8081
	defaultControlServicePort = 8082
	defaultDataPlanePort      = 14443
)

// deploymentDataPlaneConfig is the installer-owned representation of the
// loopback-only Trojan data-plane config.yaml.
type deploymentDataPlaneConfig struct {
	RunType          string                    `yaml:"run_type"`
	LocalAddr        string                    `yaml:"local_addr"`
	LocalPort        int                       `yaml:"local_port"`
	RemoteAddr       string                    `yaml:"remote_addr"`
	RemotePort       int                       `yaml:"remote_port"`
	DisableHTTPCheck bool                      `yaml:"disable_http_check"`
	AuthDB           string                    `yaml:"auth_db"`
	AuthRefresh      int                       `yaml:"auth_refresh"`
	TrafficReport    string                    `yaml:"traffic_report,omitempty"`
	TrafficInterval  int                       `yaml:"traffic_interval,omitempty"`
	ProxyProtocol    bool                      `yaml:"proxy_protocol"`
	TransportPlugin  deploymentTransportPlugin `yaml:"transport_plugin"`
	Mux              deploymentMuxConfig       `yaml:"mux"`
	Node             *deploymentNodeConfig     `yaml:"node,omitempty"`
	Log              deploymentLogConfig       `yaml:"log"`
}

type deploymentTransportPlugin struct {
	Enabled bool   `yaml:"enabled"`
	Type    string `yaml:"type"`
}

type deploymentMuxConfig struct {
	Enabled bool `yaml:"enabled"`
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

type deploymentGatewayConfig struct {
	Gateway deploymentGatewayServiceConfig `yaml:"gateway"`
	SSL     deploymentGatewayTLSConfig     `yaml:"ssl"`
	Routes  deploymentGatewayRoutes        `yaml:"routes"`
}

type deploymentGatewayServiceConfig struct {
	Listen         string `yaml:"listen"`
	AdminService   string `yaml:"admin_service,omitempty"`
	ControlService string `yaml:"control_service"`
	TrojanService  string `yaml:"trojan_service"`
	AdminDisabled  bool   `yaml:"admin_disabled,omitempty"`
}

type deploymentGatewayTLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type deploymentGatewayRoutes struct {
	AdminPrefix string `yaml:"admin_prefix"`
	SubPath     string `yaml:"sub_path"`
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
	DeployPath       string
	Domain           string
	CertPath         string
	KeyPath          string
	GatewayPort      int
	DataPlanePort    int
	AdminPort        int
	ControlPort      int
	AdminUser        string
	AdminPass        string
	DBPath           string
	SubPath          string
	Node             *deploymentNodeConfig
	TrafficReporting bool
}

type deploymentHysteriaConfigInput struct {
	ListenPort  int
	CertPath    string
	KeyPath     string
	ControlPort int
	UpMbps      int
	DownMbps    int
}

func normalizeDeploymentPorts(input deploymentCoreConfigInput) deploymentCoreConfigInput {
	if input.GatewayPort <= 0 {
		input.GatewayPort = defaultGatewayPort
	}
	if input.DataPlanePort <= 0 {
		input.DataPlanePort = defaultDataPlanePort
	}
	if input.AdminPort <= 0 {
		input.AdminPort = defaultAdminServicePort
	}
	if input.ControlPort <= 0 {
		input.ControlPort = defaultControlServicePort
	}
	return input
}

func buildMasterProxyConfig(input deploymentCoreConfigInput) ([]byte, error) {
	input = normalizeDeploymentPorts(input)
	input.TrafficReporting = true
	return marshalDeploymentYAML(newDeploymentDataPlaneConfig(input))
}

func buildWorkerProxyConfig(input deploymentCoreConfigInput) ([]byte, error) {
	if input.Node == nil {
		return nil, fmt.Errorf("worker data-plane configuration requires node synchronization settings")
	}
	input = normalizeDeploymentPorts(input)
	input.TrafficReporting = false
	return marshalDeploymentYAML(newDeploymentDataPlaneConfig(input))
}

func newDeploymentDataPlaneConfig(input deploymentCoreConfigInput) deploymentDataPlaneConfig {
	cfg := deploymentDataPlaneConfig{
		RunType:          "server",
		LocalAddr:        "127.0.0.1",
		LocalPort:        input.DataPlanePort,
		RemoteAddr:       "127.0.0.1",
		RemotePort:       0,
		DisableHTTPCheck: true,
		AuthDB:           input.DBPath,
		AuthRefresh:      30,
		ProxyProtocol:    true,
		TransportPlugin:  deploymentTransportPlugin{Enabled: true, Type: "plaintext"},
		Mux:              deploymentMuxConfig{Enabled: true},
		Node:             input.Node,
		Log: deploymentLogConfig{
			Level:  1,
			Access: filepath.Join(input.DeployPath, "log", "trojan-data-plane", "access.log"),
			Error:  filepath.Join(input.DeployPath, "log", "trojan-data-plane", "error.log"),
		},
	}
	if input.TrafficReporting {
		cfg.TrafficReport = fmt.Sprintf("http://127.0.0.1:%d/internal/control/v1/data-plane/traffic", input.AdminPort)
		cfg.TrafficInterval = 30
	}
	return cfg
}

func buildGatewayConfig(input deploymentCoreConfigInput, adminDisabled bool) ([]byte, error) {
	input = normalizeDeploymentPorts(input)
	cfg := deploymentGatewayConfig{
		Gateway: deploymentGatewayServiceConfig{
			Listen:         fmt.Sprintf("0.0.0.0:%d", input.GatewayPort),
			ControlService: fmt.Sprintf("127.0.0.1:%d", input.ControlPort),
			TrojanService:  fmt.Sprintf("127.0.0.1:%d", input.DataPlanePort),
			AdminDisabled:  adminDisabled,
		},
		SSL:    deploymentGatewayTLSConfig{Cert: input.CertPath, Key: input.KeyPath},
		Routes: deploymentGatewayRoutes{AdminPrefix: "/admin/", SubPath: input.SubPath},
	}
	if !adminDisabled {
		cfg.Gateway.AdminService = fmt.Sprintf("127.0.0.1:%d", input.AdminPort)
	}
	return marshalDeploymentYAML(cfg)
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

func buildWorkerWebConfig(adminUser, adminPass string, controlPort int, dbPath, subPath string) ([]byte, error) {
	return marshalDeploymentYAML(deploymentWebConfig{
		RunType: "server",
		Admin: deploymentAdminConfig{
			Enabled: true, Username: adminUser, Password: adminPass, Port: controlPort,
			DB: dbPath, Path: "/admin/", SubPath: subPath,
		},
		Node: &deploymentWebNode{Enabled: true},
	})
}

func buildHysteriaConfig(input deploymentHysteriaConfigInput) ([]byte, error) {
	if input.ControlPort <= 0 {
		input.ControlPort = defaultControlServicePort
	}
	return marshalDeploymentYAML(deploymentHysteriaConfig{
		Listen: fmt.Sprintf(":%d", input.ListenPort),
		TLS:    deploymentHysteriaTLS{Cert: input.CertPath, Key: input.KeyPath},
		Auth: deploymentHysteriaAuth{
			Type: "http",
			HTTP: deploymentHysteriaHTTPAuth{
				URL: fmt.Sprintf("http://127.0.0.1:%d/control/v1/hysteria/auth", input.ControlPort), Insecure: true,
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
