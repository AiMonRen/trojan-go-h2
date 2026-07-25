package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/voidluo/trojan-go/component"
	"github.com/voidluo/trojan-go/config"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/internal/webserver"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/option"
	"github.com/voidluo/trojan-go/proxy"
	"github.com/voidluo/trojan-go/tunnel/transport"
	"github.com/voidluo/trojan-go/tunnel/trojan"
)

// serviceArgs extracts -config / -listen from a service argument list.
//
// KNOWN LIMITATION (#4): this is a hand-rolled scanner rather than a
// flag.FlagSet. It silently ignores unknown flags, a trailing flag with no
// value, and repeated flags (last one wins). That is acceptable today because
// callers are the installer-generated systemd units, which always emit exactly
// "-config <path> [-listen <addr>]". Migrating to flag.FlagSet would change the
// signature to return an error and force every caller to handle parse failure,
// so it is deferred to the v2 configuration format migration.
func serviceArgs(args []string, defaultListen string) (configPath, listenAddress string) {
	listenAddress = defaultListen
	for i := 0; i < len(args)-1; i++ {
		switch args[i] {
		case "-config":
			configPath = args[i+1]
		case "-listen":
			listenAddress = args[i+1]
		}
	}
	return configPath, listenAddress
}

func validateAddress(host string, port int, name string) error {
	if host == "" || port < 0 || port > 65535 {
		return fmt.Errorf("invalid %s address %q:%d", name, host, port)
	}
	if net.ParseIP(host) == nil && strings.ContainsAny(host, " /\\") {
		return fmt.Errorf("invalid %s host %q", name, host)
	}
	return nil
}

func validateDataPlaneConfig(configPath string) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("read data-plane config: %w", err)
	}
	ctx, err := config.WithYAMLConfig(context.Background(), data)
	if err != nil {
		return fmt.Errorf("parse data-plane config: %w", err)
	}
	proxyCfg, err := config.Require[proxy.Config](ctx, proxy.Name)
	if err != nil {
		return err
	}
	if strings.ToUpper(proxyCfg.RunType) != "SERVER" {
		return fmt.Errorf("data-plane run_type must be server, got %q", proxyCfg.RunType)
	}
	transportCfg, err := config.Require[transport.Config](ctx, transport.Name)
	if err != nil {
		return err
	}
	if err := validateAddress(transportCfg.LocalHost, transportCfg.LocalPort, "local"); err != nil {
		return err
	}
	if !net.ParseIP(transportCfg.LocalHost).IsLoopback() {
		return fmt.Errorf("data-plane local_addr must be a loopback IP, got %q", transportCfg.LocalHost)
	}
	if transportCfg.LocalPort == 0 {
		return errors.New("data-plane local_port must be non-zero")
	}
	if !transportCfg.TransportPlugin.Enabled || transportCfg.TransportPlugin.Type != "plaintext" {
		return errors.New("service data-plane requires transport_plugin.enabled=true and type=plaintext")
	}
	if !transportCfg.ProxyProtocol {
		return errors.New("service data-plane requires proxy_protocol=true")
	}
	trojanCfg, err := config.Require[trojan.Config](ctx, trojan.Name)
	if err != nil {
		return err
	}
	if trojanCfg.AuthDB == "" {
		return errors.New("data-plane auth_db is required")
	}
	if trojanCfg.TrafficReport != "" {
		reportURL, err := url.Parse(trojanCfg.TrafficReport)
		if err != nil || reportURL.Scheme != "http" || reportURL.Host == "" {
			return fmt.Errorf("invalid data-plane traffic_report %q", trojanCfg.TrafficReport)
		}
		host := reportURL.Hostname()
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("data-plane traffic_report must use a loopback IP, got %q", trojanCfg.TrafficReport)
		}
		if trojanCfg.TrafficOutbox == "" {
			return errors.New("trojan data-plane traffic reporting requires traffic_outbox")
		}
	}
	nodeCfg, err := config.Require[nodesync.Config](ctx, nodesync.Name)
	if err == nil && nodeCfg.Node.Enabled {
		if nodeCfg.Node.MasterURL == "" || nodeCfg.Node.Secret == "" || nodeCfg.Node.TrafficOutbox == "" {
			return errors.New("worker node synchronization requires master_url, secret and traffic_outbox")
		}
	}
	return nil
}

func validateServiceConfig(args []string) error {
	if len(args) < 4 || args[0] != "--service" || args[2] != "--config" || (len(args)-4)%3 != 0 {
		return errors.New("usage: trojan-go config-check --service <gateway|admin|worker-control|data-plane> --config <path> [--path-override <target> <staged-path>]...")
	}
	service, configPath := args[1], args[3]
	if configPath == "" {
		return errors.New("config path is required")
	}
	pathOverrides := make(map[string]string)
	for i := 4; i < len(args); i += 3 {
		if args[i] != "--path-override" {
			return fmt.Errorf("unsupported config-check option %q", args[i])
		}
		if args[i+1] == "" || args[i+2] == "" {
			return errors.New("path override requires non-empty target and staged path")
		}
		pathOverrides[filepath.Clean(args[i+1])] = args[i+2]
	}
	if service != "gateway" && len(pathOverrides) > 0 {
		return fmt.Errorf("path overrides are not supported for service %q", service)
	}
	switch service {
	case "gateway":
		return webserver.ValidateGatewayConfigWithPathOverrides(configPath, pathOverrides)
	case "admin":
		return webserver.ValidateAdminServiceConfig(configPath)
	case "worker-control":
		return webserver.ValidateWorkerControlServiceConfig(configPath)
	case "data-plane":
		return validateDataPlaneConfig(configPath)
	default:
		return fmt.Errorf("unsupported service %q", service)
	}
}

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "config-check" {
		if err := validateServiceConfig(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "config validation failed:", err)
			os.Exit(1)
		}
		return
	}
	// Service commands use the existing deployment database as cold data. The
	// legacy web command remains available only for the embedded compatibility runtime.
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "web", "admin-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "127.0.0.1:8081")
			if configPath == "" {
				log.Fatal("admin-service 模式需要指定 -config 参数")
			}
			var err error
			if os.Args[1] == "web" {
				err = webserver.RunStandalone(configPath)
			} else {
				err = webserver.RunAdminService(configPath, listenAddress)
			}
			if err != nil {
				log.Fatal("启动 admin-service 失败:", err)
			}
			return
		case "gateway-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "0.0.0.0:443")
			if configPath == "" {
				log.Fatal("gateway-service 模式需要指定 -config 参数")
			}
			if err := webserver.RunGatewayService(configPath, listenAddress); err != nil {
				log.Fatal("启动 gateway-service 失败:", err)
			}
			return
		case "control-service":
			configPath, listenAddress := serviceArgs(os.Args[2:], "127.0.0.1:8082")
			workerMode := false
			adminAddress := "127.0.0.1:8081"
			for i := 0; i < len(os.Args)-1; i++ {
				switch os.Args[i] {
				case "-admin":
					adminAddress = os.Args[i+1]
				case "-worker":
					workerMode = true
				}
			}
			var err error
			if workerMode {
				if configPath == "" {
					log.Fatal("Worker control-service 模式需要指定 -config 参数")
				}
				err = webserver.RunWorkerControlService(configPath, listenAddress)
			} else {
				err = webserver.RunControlService(listenAddress, adminAddress)
			}
			if err != nil {
				log.Fatal("启动 control-service 失败:", err)
			}
			return
		}
	}

	// 默认模式：遍历已注册的 option.Handler（-config / -server / -api / -version）
	// 按优先级从高到低逐一尝试，首次成功即阻塞运行代理服务器
	flag.Parse()
	for {
		h, err := option.PopOptionHandler()
		if err != nil {
			log.Fatal("invalid options")
		}
		err = h.Handle()
		if err == nil {
			break
		}
	}
}
