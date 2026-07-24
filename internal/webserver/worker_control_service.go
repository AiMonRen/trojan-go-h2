package webserver

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
)

// RunWorkerControlService starts the Worker-local control endpoint. Its only
// persistent store is the Worker cache database already present on that node;
// it never opens or writes the Master database.
func RunWorkerControlService(configPath, listenAddress string) error {
	if abs, err := filepath.Abs(configPath); err == nil {
		WebConfigPath = abs
	} else {
		WebConfigPath = configPath
	}
	cfg, err := loadStandaloneConfig(configPath)
	if err != nil {
		return err
	}
	if !cfg.Node.Enabled {
		return fmt.Errorf("worker control-service requires node.enabled=true")
	}
	db, err := database.InitDb(cfg.Admin.DBPath)
	if err != nil {
		return fmt.Errorf("初始化 Worker 缓存数据库失败: %w", err)
	}
	srv := newAdminServer(db, cfg.Admin.Username, cfg.Admin.Password, cfg.Admin.Path, 0, false, "", false, true, "", cfg.Admin.SubPath, "", false)
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	srv.registerRoutesForMode(r, cfg.Admin.Path, RouteModeControl)
	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("监听 Worker control-service 失败: %w", err)
	}
	httpServer := &http.Server{Handler: r}
	log.Infof("worker control-service started on http://%s using existing cache database %s", listener.Addr(), cfg.Admin.DBPath)
	go func() {
		<-common.ShutdownContext().Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	return httpServer.Serve(listener)
}
