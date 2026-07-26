package webserver

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gopkg.in/yaml.v3"
)

type standaloneConfig struct {
	Admin struct {
		Enabled     bool   `yaml:"enabled"`
		Username    string `yaml:"username"`
		Password    string `yaml:"password"`
		DBPath      string `yaml:"db"`
		Path        string `yaml:"path"`
		SubPath     string `yaml:"sub_path"`
		ServerDomain string `yaml:"server_domain"`
	} `yaml:"admin"`
	Node struct {
		Enabled bool `yaml:"enabled"`
	} `yaml:"node"`
}

func loadStandaloneConfig(configPath string) (standaloneConfig, error) {
	var cfg standaloneConfig
	data, err := os.ReadFile(configPath)
	if err != nil {
		return cfg, fmt.Errorf("读取配置文件失败: %w", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析 YAML 失败: %w", err)
	}
	if !cfg.Admin.Enabled {
		return cfg, fmt.Errorf("配置文件中未启用 admin 模块")
	}
	if cfg.Admin.DBPath == "" {
		return cfg, fmt.Errorf("配置文件中缺少 admin.db")
	}
	if cfg.Admin.Username == "" || cfg.Admin.Password == "" {
		return cfg, fmt.Errorf("配置文件中缺少 admin.username 或 admin.password")
	}
	if cfg.Admin.Path == "" {
		return cfg, fmt.Errorf("配置文件中缺少 admin.path")
	}
	if cfg.Admin.SubPath == "" {
		return cfg, fmt.Errorf("配置文件中缺少 admin.sub_path")
	}
	return cfg, nil
}

func ValidateAdminServiceConfig(configPath string) error {
	_, err := loadStandaloneConfig(configPath)
	return err
}

func ValidateWorkerControlServiceConfig(configPath string) error {
	cfg, err := loadStandaloneConfig(configPath)
	if err != nil {
		return err
	}
	if !cfg.Node.Enabled {
		return fmt.Errorf("worker control-service requires node.enabled=true")
	}
	return nil
}

// RunAdminService starts the sole master-database writer. It reads the existing
// deployment database directly; no schema replacement or data export is used.
func RunAdminService(configPath, listenAddress string) error {
	if err := requireLoopbackAddress(listenAddress, "admin-service"); err != nil {
		return err
	}
	if err := ValidateAdminServiceConfig(configPath); err != nil {
		return err
	}
	if abs, err := filepath.Abs(configPath); err == nil {
		WebConfigPath = abs
	} else {
		WebConfigPath = configPath
	}
	cfg, err := loadStandaloneConfig(configPath)
	if err != nil {
		return err
	}
	db, err := database.InitDb(cfg.Admin.DBPath)
	if err != nil {
		return fmt.Errorf("初始化数据库失败: %w", err)
	}
	srv := newAdminServer(db, cfg.Admin.Username, cfg.Admin.Password, cfg.Admin.Path, 0, false, "", false, cfg.Node.Enabled, "", cfg.Admin.SubPath, cfg.Admin.ServerDomain, true)
	gin.SetMode(gin.ReleaseMode)
	r := newTrustedGinEngine()
	srv.registerRoutesForMode(r, cfg.Admin.Path, RouteModeAdmin)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("监听 admin-service 失败: %w", err)
	}
	httpServer := newHTTPServer(r)
	log.Infof("admin-service started on http://%s using existing database %s", listener.Addr(), cfg.Admin.DBPath)
	go func() {
		<-common.ShutdownContext().Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	return httpServer.Serve(listener)
}
