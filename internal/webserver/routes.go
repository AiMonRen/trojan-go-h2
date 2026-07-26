package webserver

import (
	"crypto/subtle"
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/webui"
	"github.com/voidluo/trojan-go/log"
)

// RouteMode identifies the public service boundary that is being started.
// The all mode is retained only for the legacy embedded runtime. New deployments
// run the admin and control modes as separate loopback services.
type RouteMode uint8

const (
	RouteModeAll RouteMode = iota
	RouteModeAdmin
	RouteModeControl
)

// registerRoutes keeps the embedded runtime compatible while sharing the exact
// same route definitions with the standalone admin/control service processes.
func (s *AdminServer) registerRoutes(r *gin.Engine, mountPath string) {
	s.registerRoutesForMode(r, mountPath, RouteModeAll)
}

func (s *AdminServer) registerRoutesForMode(r *gin.Engine, mountPath string, mode RouteMode) {
	r.Use(gin.Recovery(), s.limitRequestBody())
	if mode == RouteModeAll || mode == RouteModeAdmin {
		s.registerAdminRoutes(r, mountPath)
		// Internal control endpoints are only reachable through the loopback
		// admin-service listener. The public TLS router never exposes this prefix.
		s.registerInternalControlRoutes(r)
	}
	if mode == RouteModeAll || mode == RouteModeControl {
		s.registerControlRoutes(r, mode == RouteModeAll)
	}
}

func (s *AdminServer) registerAdminRoutes(r *gin.Engine, mountPath string) {
	if mountPath == "" {
		mountPath = "/"
	}

	// S-05: the panel HTML and its API get the full browser hardening set.
	// The mask page and NoRoute handler deliberately stay bare so their
	// response headers keep matching a plain nginx install.
	panelHeaders := securityHeaders(true)
	serveIndex := func(c *gin.Context) {
		data, _ := webui.ReadIndex()
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}
	if mountPath == "/" {
		r.GET("/", panelHeaders, serveIndex)
	} else {
		r.GET(mountPath, panelHeaders, serveIndex)
		trimmedPath := strings.TrimSuffix(mountPath, "/")
		if trimmedPath != mountPath && trimmedPath != "" {
			r.GET(trimmedPath, func(c *gin.Context) { c.Redirect(http.StatusFound, mountPath) })
		}
		r.GET("/", s.serveMaskPage)
	}

	apiGroup := r.Group("/admin/api", panelHeaders)
	apiGroup.POST("/login", s.enforceLoginRateLimit(), s.handleLogin)
	auth := apiGroup.Group("/", s.enforceAdminRateLimit(), s.invalidateSubscriptionAfterMutation(), s.requireAdminSession())
	auth.GET("/settings", s.handleGetSettings)
	auth.POST("/settings", s.handleUpdateSettings)
	auth.POST("/settings/admin", s.handleUpdateAdmin)
	auth.GET("/settings/backup", s.handleBackup)
	auth.POST("/settings/restore", s.handleRestore)
	auth.GET("/settings/websocket", s.handleGetWebSocket)
	auth.POST("/settings/websocket", s.handleUpdateWebSocket)
	auth.GET("/status", s.handleGetStatus)
	auth.GET("/server-info", s.handleGetServerInfo)
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
	auth.POST("/nodes/:id/secret/rotate", s.handleRotateNodeSecret)
	auth.DELETE("/nodes/:id", s.handleDeleteNode)
	auth.POST("/nodes/:id/ping", s.handlePingNode)
	auth.GET("/node/master-config", s.handleGetMasterConfig)
	auth.POST("/node/test-sync", s.handleTestSync)
	auth.GET("/logs", s.handleGetLogs)
	auth.POST("/service", s.handleServiceControl)
	auth.POST("/restart", s.handleRestart)
	auth.GET("/restart-status", s.handleRestartStatus)
	auth.GET("/settings/hysteria", s.handleGetHysteriaConfig)
	auth.POST("/settings/hysteria", s.handleSaveHysteriaConfig)

	subRoute := "/sub"
	if s.subPath != "" {
		subRoute = s.subPath
	}
	// The subscription endpoint is consumed by proxy clients rather than
	// browsers, so it only gets the sniffing/referrer/transport headers. A CSP
	// would be meaningless here and framing rules do not apply.
	r.GET(subRoute, securityHeaders(false), s.handleSub)
	r.NoRoute(s.serveMaskPage)
}

// securityHeaders sets the browser-side hardening response headers that were
// previously absent entirely (S-05).
//
// full=true is for the admin panel and its API: it adds Content-Security-Policy
// and anti-framing headers. full=false is for endpoints consumed by proxy
// clients, where only MIME sniffing, referrer leakage and transport downgrade
// are relevant.
//
// The CSP still allows 'unsafe-inline' because index.html carries its script
// and styles inline. Once those are split into separate assets the keyword can
// be dropped and the policy tightened; the header being present already blocks
// external script origins and inline event-handler injection is contained by
// the escaping added for S-01.
func securityHeaders(full bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		// HSTS is only meaningful on an HTTPS response. In split-service mode
		// the admin listener is plain HTTP on loopback behind the TLS gateway,
		// and SetTrustedProxies restricts X-Forwarded-* to loopback, so the
		// forwarded scheme can be trusted here.
		if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		if !full {
			c.Next()
			return
		}
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		// fonts.googleapis.com / fonts.gstatic.com are allowlisted because
		// index.html still @imports a Google Fonts stylesheet. Note that this
		// request also reveals panel usage to a third party and simply stalls
		// on networks where Google is unreachable; self-hosting the two font
		// families would let both entries be dropped.
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline'; "+
				"style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "+
				"img-src 'self' data:; "+
				"font-src 'self' data: https://fonts.gstatic.com; "+
				"connect-src 'self'; "+
				"form-action 'self'; "+
				"frame-ancestors 'none'; "+
				"base-uri 'none'; "+
				"object-src 'none'")
		c.Next()
	}
}

func (s *AdminServer) registerControlRoutes(r *gin.Engine, includeLegacy bool) {
	control := r.Group("/control/v1")
	control.POST("/nodes/sync", s.handleNodeSync)
	control.POST("/nodes/heartbeat", s.handleNodeHeartbeat)
	control.POST("/hysteria/auth", s.handleHysteriaAuth)
	if !includeLegacy {
		return
	}
	legacy := r.Group("/admin/api")
	legacy.POST("/node/sync", s.handleNodeSync)
	legacy.POST("/node/heartbeat", s.handleNodeHeartbeat)
	legacy.POST("/auth", s.handleHysteriaAuth)
	legacy.POST("/hysteria/auth", s.handleHysteriaAuth)
}

func (s *AdminServer) registerInternalControlRoutes(r *gin.Engine) {
	internal := r.Group("/internal/control/v1", s.requireInternalControl())
	internal.POST("/nodes/sync", s.handleNodeSync)
	internal.POST("/nodes/heartbeat", s.handleNodeHeartbeat)
	internal.POST("/hysteria/auth", s.handleHysteriaAuth)
	internal.POST("/data-plane/traffic", s.handleDataPlaneTraffic)
	internal.POST("/users", s.handleAddUser)
	internal.PUT("/settings/admin", s.handleUpdateAdmin)
}

// requireInternalControl verifies that the request originates from a
// loopback address AND carries the correct shared internal API token.
// The token is always provisioned during server startup; the empty-token
// fast path exists only for test fixtures that directly construct an
// AdminServer struct without going through newAdminServer.
func (s *AdminServer) requireInternalControl() gin.HandlerFunc {
	return func(c *gin.Context) {
		host, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil || (host != "127.0.0.1" && host != "::1") {
			c.JSON(http.StatusForbidden, gin.H{"error": "internal control endpoint requires loopback origin"})
			c.Abort()
			return
		}
		// S-04: compare in constant time. Go's string != short-circuits on the
		// first differing byte, which is a (theoretical, given the loopback
		// requirement above) timing oracle for a shared secret.
		if s.internalToken != "" {
			provided := c.GetHeader("X-Internal-Token")
			if subtle.ConstantTimeCompare([]byte(provided), []byte(s.internalToken)) != 1 {
				c.JSON(http.StatusForbidden, gin.H{"error": "invalid internal service token"})
				c.Abort()
				return
			}
		}
		c.Next()
	}
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
			c.JSON(http.StatusUnauthorized, gin.H{"error": "身份凭证无效"})
			c.Abort()
			return
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

		// Per-session idle timeout. The jti claim is mandatory; see
		// enforceSessionIdleTimeout for why tokens without it are rejected.
		if !s.enforceSessionIdleTimeout(c, token) {
			return
		}

		c.Next()
	}
}
