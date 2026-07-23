package webserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/webui"
	"github.com/voidluo/trojan-go/log"
)

// registerRoutes registers the panel's public, node, and administrator routes.
// Route paths, methods, authentication rules, and handler bindings are kept
// compatible with the pre-refactor implementation.
func (s *AdminServer) registerRoutes(r *gin.Engine, mountPath string) {
	r.Use(gin.Recovery(), s.limitRequestBody())

	if mountPath == "" {
		mountPath = "/"
	}

	serveIndex := func(c *gin.Context) {
		data, _ := webui.ReadIndex()
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}

	if mountPath == "/" {
		r.GET("/", serveIndex)
	} else {
		r.GET(mountPath, serveIndex)
		trimmedPath := strings.TrimSuffix(mountPath, "/")
		if trimmedPath != mountPath && trimmedPath != "" {
			r.GET(trimmedPath, func(c *gin.Context) {
				c.Redirect(http.StatusFound, mountPath)
			})
		}
		r.GET("/", s.serveMaskPage)
	}

	r.NoRoute(s.serveMaskPage)

	apiGroup := r.Group("/admin/api")
	apiGroup.POST("/login", s.enforceLoginRateLimit(), s.handleLogin)
	apiGroup.POST("/node/sync", s.handleNodeSync)
	apiGroup.POST("/node/heartbeat", s.handleNodeHeartbeat)
	apiGroup.POST("/auth", s.handleHysteriaAuth)
	apiGroup.POST("/hysteria/auth", s.handleHysteriaAuth)

	auth := apiGroup.Group("/", s.enforceAdminRateLimit(), s.invalidateSubscriptionAfterMutation(), s.requireAdminOrNode())

	auth.GET("/settings", s.handleGetSettings)
	auth.POST("/settings", s.handleUpdateSettings)
	auth.POST("/settings/admin", s.handleUpdateAdmin)
	auth.GET("/settings/backup", s.handleBackup)
	auth.POST("/settings/restore", s.handleRestore)
	auth.GET("/settings/websocket", s.handleGetWebSocket)
	auth.POST("/settings/websocket", s.handleUpdateWebSocket)

	auth.GET("/status", s.handleGetStatus)
	auth.GET("/server-info", s.handleGetServerInfo)

	subRoute := "/sub"
	if s.subPath != "" {
		subRoute = s.subPath
	}
	r.GET(subRoute, s.handleSub)

	auth.GET("/users", s.handleListUsers)
	auth.POST("/users", s.handleAddUser)
	auth.PUT("/users/:id", s.handleUpdateUser)
	auth.DELETE("/users/:id", s.handleDeleteUser)
	auth.POST("/users/:id/quota", s.handleUpdateQuota)
	auth.DELETE("/users/:id/data", s.handleClearTraffic)
	auth.POST("/users/:id/expire", s.handleSetExpire)
	auth.DELETE("/users/:id/expire", s.handleCancelExpire)
	auth.GET("/users/:id/share", s.handleShare)

	auth.GET("/nodes", s.handleListNodes)
	auth.POST("/nodes", s.handleAddNode)
	auth.PUT("/nodes/:id", s.handleUpdateNode)
	auth.POST("/nodes/:id/secret/rotate", s.requireAdminSession(), s.handleRotateNodeSecret)
	auth.DELETE("/nodes/:id", s.handleDeleteNode)
	auth.POST("/nodes/:id/ping", s.handlePingNode)
	auth.GET("/node/master-config", s.handleGetMasterConfig)
	auth.POST("/node/test-sync", s.handleTestSync)

	auth.GET("/logs", s.handleGetLogs)
	auth.POST("/service", s.handleServiceControl)
	auth.POST("/restart", s.handleRestart)
	auth.GET("/settings/hysteria", s.handleGetHysteriaConfig)
	auth.POST("/settings/hysteria", s.handleSaveHysteriaConfig)
}

// requireAdminOrNode permits an authenticated management session or a known
// worker node carrying its communication secret.
func (s *AdminServer) requireAdminOrNode() gin.HandlerFunc {
	return func(c *gin.Context) {
		nodeSecret := c.GetHeader("X-Node-Secret")
		if nodeSecret != "" {
			if _, err := database.NodeBySecret(s.db, nodeSecret); err == nil {
				c.Next()
				return
			}
		}

		ts := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if ts == "" {
			ts = c.Query("token")
		}

		token, err := s.verifyJWT(ts)
		if err != nil {
			log.Warnf("Web panel JWT auth parse failed from %s: %v", c.ClientIP(), err)
		}
		if token == nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "身份凭证无效"})
			c.Abort()
			return
		}

		if lastNano := s.lastActiveNano.Load(); lastNano != 0 && time.Since(time.Unix(0, lastNano)) > 30*time.Minute {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已过期，请重新登录"})
			c.Abort()
			return
		}

		s.lastActiveNano.Store(time.Now().UnixNano())
		c.Next()
	}
}
