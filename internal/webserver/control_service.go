package webserver

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/log"
)

// RunControlService exposes only machine-facing control routes. It deliberately
// does not open SQLite. All stateful work is forwarded to admin-service through
// its loopback-only internal API, making admin-service the sole master writer.
func RunControlService(listenAddress, adminAddress string) error {
	if err := requireLoopbackAddress(listenAddress, "control-service"); err != nil {
		return err
	}
	if err := requireLoopbackAddress(adminAddress, "control-service admin backend"); err != nil {
		return err
	}
	adminURL, err := url.Parse("http://" + adminAddress)
	if err != nil || adminURL.Host == "" {
		return fmt.Errorf("无效 admin-service 内部地址 %q", adminAddress)
	}
	// Fail closed: the internal token must exist before control-service starts.
	// Without it every forwarded call would be rejected by admin-service, so we
	// refuse to start rather than run in a permanently broken state.
	token, err := ReadInternalToken(DefaultInternalTokenPath)
	if err != nil {
		return fmt.Errorf("control-service 需要内部服务令牌但无法读取: %w", err)
	}
	gin.SetMode(gin.ReleaseMode)
	r := newTrustedGinEngine()
	r.Use(gin.Recovery())
	proxy := newInternalControlProxy(adminURL, token)
	control := r.Group("/control/v1")
	control.POST("/nodes/sync", proxy)
	control.POST("/nodes/heartbeat", proxy)
	control.POST("/hysteria/auth", proxy)

	listener, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return fmt.Errorf("监听 control-service 失败: %w", err)
	}
	httpServer := newHTTPServer(r)
	log.Infof("control-service started on http://%s forwarding stateful operations to %s", listener.Addr(), adminURL)
	go func() {
		<-common.ShutdownContext().Done()
		_ = httpServer.Shutdown(context.Background())
	}()
	return httpServer.Serve(listener)
}

func newInternalControlProxy(adminURL *url.URL, token string) gin.HandlerFunc {
	client := &http.Client{Timeout: controlRequestTimeout}
	return func(c *gin.Context) {
		path := strings.TrimPrefix(c.Request.URL.Path, "/control/v1")
		target := *adminURL
		target.Path = "/internal/control/v1" + path
		target.RawQuery = c.Request.URL.RawQuery

		req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target.String(), c.Request.Body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "创建内部控制请求失败"})
			return
		}
		req.Header.Set("X-Internal-Token", token)
		for key, values := range c.Request.Header {
			switch http.CanonicalHeaderKey(key) {
			case "Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto", "X-Real-Ip":
				continue
			}
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
		if clientIP := c.ClientIP(); clientIP != "" {
			req.Header.Set("X-Forwarded-For", clientIP)
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Warnf("control-service: internal admin request failed: %v", err)
			c.JSON(http.StatusBadGateway, gin.H{"error": "控制面内部服务不可用"})
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, value := range values {
				c.Header(key, value)
			}
		}
		c.Status(resp.StatusCode)
		_, _ = io.Copy(c.Writer, resp.Body)
	}
}

const controlRequestTimeout = 15 * time.Second
