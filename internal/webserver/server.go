package webserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/internal/webui"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

var WebConfigPath string

// AdminServer 管理面板服务器，复用 TLS 层已建立的连接
type AdminServer struct {
	db       *gorm.DB
	handler  http.Handler
	connChan chan net.Conn
	done     chan struct{}

	lastActiveNano atomic.Int64 // 后端会话活动时间（Unix 纳秒），用于超时注销，原子操作防 Data Race

	// jwtSecret 启动时自动生成的 32 字节高熵随机密钥，专用于 JWT HS256 签名与验证
	jwtSecret []byte

	// 初始配置（当数据库未设置时作为回退）
	configUser string
	configPass string

	// 管理员凭据内存缓存，避免每次登录都查 SQLite
	credMu          sync.RWMutex
	cachedAdminUser string
	cachedAdminPass string
	cacheValid      bool

	// 代理核心认证器引用（支持多条代理链路聚合），用于同步面板用户到代理层
	auths []statistic.Authenticator

	// 传输层特性，用于订阅配置生成
	wsEnabled  bool
	wsPath     string
	muxEnabled bool

	isNode       bool   // 是否处于从节点模式
	maskHtmlPath string // 本地伪装页面文件路径
	subPath      string // 混淆订阅路径
	serverDomain string // 主代理域名，用于强制锁死订阅链接和节点的域名

	closeOnce          sync.Once
	httpServer         *http.Server
	standaloneServer   *http.Server
	standaloneListener net.Listener
	workers            sync.WaitGroup
}

// SetAuth 绑定代理核心认证器，并将数据库中已有的用户同步到认证器中。
// 这是连接 Web 面板（SQLite）与代理核心（内存认证）的关键桥梁。
func (s *AdminServer) SetAuth(auth statistic.Authenticator) {
	s.auths = append(s.auths, auth)
	// 从数据库加载所有用户，注入认证器
	var users []database.User
	// 只加载状态为正常 (Status=0) 且未过期的用户
	now := time.Now()
	s.db.Where("status = ?", 0).Find(&users)

	count := 0
	for _, u := range users {
		// 检查是否过期
		if u.ExpiryTime != nil && !u.ExpiryTime.IsZero() && u.ExpiryTime.Before(now) {
			continue
		}
		if u.Hash != "" {
			if err := auth.AddUser(u.Hash); err == nil {
				count++
			} else {
				log.Debugf("sync user %s to auth: %v (may already exist)", u.Username, err)
			}
		}
	}
	log.Infof("synced %d active users from database to proxy authenticator", count)
}

// New 创建管理面板服务器
func New(db *gorm.DB, username, password, mountPath string, port int, wsEnabled bool, wsPath string, muxEnabled bool, isNode bool, maskHtmlPath string, subPath string, serverDomain string) *AdminServer {
	srv := &AdminServer{
		db:           db,
		connChan:     make(chan net.Conn, 64),
		done:         make(chan struct{}),
		configUser:   username,
		configPass:   password,
		wsEnabled:    wsEnabled,
		wsPath:       wsPath,
		muxEnabled:   muxEnabled,
		isNode:       isNode,
		maskHtmlPath: maskHtmlPath,
		subPath:      subPath,
		serverDomain: serverDomain,
	}

	// 生成或加载 JWT 签名密钥
	var cfgJWT database.Config
	if db.Where("`key` = ?", "jwt_secret").First(&cfgJWT).Error == nil && cfgJWT.Value != "" {
		srv.jwtSecret = []byte(cfgJWT.Value)
	} else {
		srv.jwtSecret = make([]byte, 32)
		if _, err := rand.Read(srv.jwtSecret); err != nil {
			log.Fatal("admin panel: failed to generate random JWT secret:", err)
		}
		db.Save(&database.Config{Key: "jwt_secret", Value: string(srv.jwtSecret)})
	}

	// 初始化会话激活时间，登录后重新计时
	srv.lastActiveNano.Store(time.Now().UnixNano())

	if isNode {
		if mgr := nodesync.GetManager(); mgr != nil {
			mgr.SetDB(db)
		}
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	if mountPath == "" {
		mountPath = "/"
	}

	// 提供 index.html 的处理器
	serveIndex := func(c *gin.Context) {
		data, _ := webui.ReadIndex()
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
	}

	// 挂载首页（SPA 模式下，首页直接返回 HTML，路由由前端 #/ 处理）
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
		// 引导根目录到挂载点（安全伪装）
		r.GET("/", srv.serveMaskPage)
	}

	// 拦截并伪装所有未匹配路由，防探测
	r.NoRoute(srv.serveMaskPage)

	// ─── 统一 API 路由组 ───
	apiGroup := r.Group("/admin/api")

	// ─── 登录（无需鉴权） ──────────────────────────────
	apiGroup.POST("/login", srv.handleLogin)
	apiGroup.POST("/node/sync", srv.handleNodeSync)

	// ─── 需要鉴权的管理 API ──────────────────────────────
	auth := apiGroup.Group("/", func(c *gin.Context) {
		// 跳过登录接口
		if c.Request.URL.Path == "/admin/api/login" {
			c.Next()
			return
		}

		// 如果请求头带有合法的从节点 Secret，则直接放行
		nodeSecret := c.GetHeader("X-Node-Secret")
		if nodeSecret != "" {
			var node database.Node
			if srv.db.Where("secret = ?", nodeSecret).First(&node).Error == nil {
				c.Next()
				return
			}
		}

		// 检查 Token
		ts := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		// 如果 Header 里没有，尝试从 Query 里拿 (例如备份下载)
		if ts == "" {
			ts = c.Query("token")
		}

		token, err := srv.verifyJWT(ts)
		if err != nil {
			log.Warnf("Web panel JWT auth parse failed from %s: %v", c.ClientIP(), err)
		}

		if token == nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "身份凭证无效"})
			c.Abort()
			return
		}

		// 只有在成功解析 Token 后，才检查活动时间超时
		if lastNano := srv.lastActiveNano.Load(); lastNano != 0 && time.Since(time.Unix(0, lastNano)) > 30*time.Minute {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "会话已过期，请重新登录"})
			c.Abort()
			return
		}

		// 刷新活动时间
		srv.lastActiveNano.Store(time.Now().UnixNano())
		c.Next()
	})

	// ─── 系统设置 API ──────────────────────────────
	auth.GET("/settings", srv.handleGetSettings)
	auth.POST("/settings", srv.handleUpdateSettings)
	auth.POST("/settings/admin", srv.handleUpdateAdmin)

	auth.GET("/settings/backup", srv.handleBackup)
	auth.POST("/settings/restore", srv.handleRestore)
	auth.GET("/settings/websocket", srv.handleGetWebSocket)
	auth.POST("/settings/websocket", srv.handleUpdateWebSocket)
	{
		// ─── 系统运维与状态 ──────────────────────────────
		auth.GET("/status", srv.handleGetStatus)
		auth.GET("/server-info", srv.handleGetServerInfo)

		// ─── 公开订阅接口 (无需 JWT) ─────────────────────
		subRoute := "/sub"
		if srv.subPath != "" {
			subRoute = srv.subPath
		}
		r.GET(subRoute, srv.handleSub)

		// ─── 用户管理 ──────────────────────────────
		auth.GET("/users", srv.handleListUsers)
		auth.POST("/users", srv.handleAddUser)
		auth.PUT("/users/:id", srv.handleUpdateUser)
		auth.DELETE("/users/:id", srv.handleDeleteUser)

		// ─── 节点管理 ──────────────────────────────
		auth.GET("/nodes", srv.handleListNodes)
		auth.POST("/nodes", srv.handleAddNode)
		auth.PUT("/nodes/:id", srv.handleUpdateNode)
		auth.DELETE("/nodes/:id", srv.handleDeleteNode)
		auth.POST("/nodes/:id/ping", srv.handlePingNode)

		// ─── 流量限额 ──────────────────────────────
		auth.POST("/users/:id/quota", srv.handleUpdateQuota)
		auth.DELETE("/users/:id/data", srv.handleClearTraffic)

		// ─── 过期管理 ──────────────────────────────
		auth.POST("/users/:id/expire", srv.handleSetExpire)
		auth.DELETE("/users/:id/expire", srv.handleCancelExpire)

		// ─── 分享链接 ──────────────────────────────
		auth.GET("/users/:id/share", srv.handleShare)

		// ─── 从节点测试与配置接口 ─────────────────────
		auth.GET("/node/master-config", srv.handleGetMasterConfig)
		auth.POST("/node/test-sync", srv.handleTestSync)
		auth.GET("/logs", srv.handleGetLogs)
		auth.POST("/service", srv.handleServiceControl)
		auth.POST("/restart", srv.handleRestart)
	}

	srv.handler = r

	srv.workers.Add(2)
	go func() {
		defer srv.workers.Done()
		srv.resetTrafficWorker()
	}()
	go func() {
		defer srv.workers.Done()
		srv.trafficSyncWorker()
	}()

	// Consume decrypted connections routed from the TLS layer.
	srv.httpServer = &http.Server{Handler: r}
	go func() {
		if err := srv.httpServer.Serve(srv); err != nil && err != http.ErrServerClosed && srv.doneOpen() {
			log.Error("admin panel: TLS-shared HTTP server failed:", err)
		}
	}()

	// Start an independently controllable listener when configured.
	if port > 0 {
		listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			log.Error("admin panel: standalone port listener failed:", err)
		} else {
			srv.standaloneListener = listener
			srv.standaloneServer = &http.Server{Handler: r}
			go func() {
				log.Infof("admin panel: listening on http://%s", listener.Addr())
				if err := srv.standaloneServer.Serve(listener); err != nil && err != http.ErrServerClosed && srv.doneOpen() {
					log.Error("admin panel: standalone server failed:", err)
				}
			}()
		}
	}

	return srv
}

// loadAdminCreds 加载管理员凭据，优先使用内存缓存以减少 SQLite 查询
func (s *AdminServer) loadAdminCreds() (user, pass string) {
	s.credMu.RLock()
	if s.cacheValid {
		user, pass = s.cachedAdminUser, s.cachedAdminPass
		s.credMu.RUnlock()
		return
	}
	s.credMu.RUnlock()

	s.credMu.Lock()
	defer s.credMu.Unlock()
	if s.cacheValid {
		return s.cachedAdminUser, s.cachedAdminPass
	}
	user, pass = s.configUser, s.configPass
	var cfgU, cfgP database.Config
	if s.db.Where("`key` = ?", "admin_username").First(&cfgU).Error == nil {
		user = cfgU.Value
	}
	if s.db.Where("`key` = ?", "admin_password").First(&cfgP).Error == nil {
		pass = cfgP.Value
	}
	s.cachedAdminUser, s.cachedAdminPass = user, pass
	s.cacheValid = true
	return
}

// invalidateAdminCache 使管理员凭据缓存失效（密码变更时调用）
func (s *AdminServer) invalidateAdminCache() {
	s.credMu.Lock()
	s.cacheValid = false
	s.credMu.Unlock()
}

// ─── API 处理方法 ────────────────────────────────

func (s *AdminServer) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}

	effUser, effPass := s.loadAdminCreds()

	authSuccess := false
	if req.Username == effUser {
		if strings.HasPrefix(effPass, "$2a$") {
			if bcrypt.CompareHashAndPassword([]byte(effPass), []byte(req.Password)) == nil {
				authSuccess = true
			}
		} else {
			if req.Password == effPass {
				authSuccess = true
				hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
				if err == nil {
					s.db.Save(&database.Config{Key: "admin_password", Value: string(hash)})
					s.invalidateAdminCache()
				}
			}
		}
	}

	if authSuccess {
		s.lastActiveNano.Store(time.Now().UnixNano())
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"user": req.Username,
			"exp":  time.Now().Add(time.Hour * 24).Unix(),
		})
		t, err := token.SignedString(s.jwtSecret)
		if err != nil {
			log.Errorf("Web panel failed to sign JWT for user %q: %v", req.Username, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法生成会话令牌"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"token": t})
	} else {
		log.Warnf("Web panel login failed for username=%q from ip=%s", req.Username, c.ClientIP())
		time.Sleep(1500 * time.Millisecond) // 防暴力破解延迟
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
	}
}

func (s *AdminServer) handleGetWebSocket(c *gin.Context) {
	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "无法读取核心配置文件"})
		return
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析配置文件失败"})
		return
	}

	enabled := false
	wsVal, hasWs := cfg["websocket"]
	if hasWs {
		if ws, ok2 := wsVal.(map[string]any); ok2 {
			enabled, _ = ws["enabled"].(bool)
		} else if wsAny, ok3 := wsVal.(map[any]any); ok3 {
			enabled, _ = wsAny["enabled"].(bool)
		}
	}

	var wsYaml string
	if hasWs {
		if yamlData, err := yaml.Marshal(wsVal); err == nil {
			wsYaml = string(yamlData)
		}
	}
	if wsYaml == "" {
		wsYaml = "enabled: false\npath: /trojan-go\nhost: \"\""
	}

	c.JSON(http.StatusOK, gin.H{
		"enabled": enabled,
		"config":  wsYaml,
	})
}

func (s *AdminServer) handleUpdateWebSocket(c *gin.Context) {
	var req struct {
		Enabled *bool   `json:"enabled"`
		Config  *string `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}

	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}
	var targetPath string
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			targetPath = p
			break
		}
	}
	if targetPath == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "未找到配置文件"})
		return
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "解析配置文件失败"})
		return
	}

	if req.Config != nil && *req.Config != "" {
		var newWs map[string]any
		if err := yaml.Unmarshal([]byte(*req.Config), &newWs); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的 YAML 配置内容"})
			return
		}
		cfg["websocket"] = newWs

		enabled := false
		if val, ok := newWs["enabled"].(bool); ok {
			enabled = val
		}
		s.wsEnabled = enabled
		req.Enabled = &enabled // 同步给下方 modifyYamlField 使用
	} else if req.Enabled != nil {
		wsVal, ok := cfg["websocket"]
		if !ok {
			wsVal = make(map[string]any)
			cfg["websocket"] = wsVal
		}
		var ws map[string]any
		if wsMap, ok := wsVal.(map[string]any); ok {
			ws = wsMap
		} else if wsAny, ok2 := wsVal.(map[any]any); ok2 {
			ws = make(map[string]any)
			for k, v := range wsAny {
				if ks, ok3 := k.(string); ok3 {
					ws[ks] = v
				}
			}
			cfg["websocket"] = ws
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "配置文件中的 websocket 格式不正确"})
			return
		}
		ws["enabled"] = *req.Enabled
		s.wsEnabled = *req.Enabled
	}

	if req.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少 enabled 参数"})
		return
	}

	newContent, err := modifyYamlField(string(data), "websocket", "enabled", *req.Enabled)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "修改配置文件失败"})
		return
	}

	tmpFile := targetPath + ".tmp"
	if err := os.WriteFile(tmpFile, []byte(newContent), 0644); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "写入临时配置文件失败"})
		return
	}
	if err := os.Rename(tmpFile, targetPath); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "重命名配置文件失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "WebSocket 配置更新成功"})
}

func (s *AdminServer) handleGetSettings(c *gin.Context) {
	var cfgs []database.Config
	s.db.Find(&cfgs)
	res := make(map[string]string)
	for _, v := range cfgs {
		res[v.Key] = v.Value
	}
	if _, ok := res["admin_username"]; !ok {
		res["admin_username"] = s.configUser
	}
	res["is_node"] = strconv.FormatBool(s.isNode)
	c.JSON(http.StatusOK, res)
}

func (s *AdminServer) handleUpdateSettings(c *gin.Context) {
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	adminChanged := false
	for k, v := range req {
		if err := s.db.Save(&database.Config{Key: k, Value: v}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "设置保存失败"})
			return
		}
		if k == "admin_username" || k == "admin_password" {
			adminChanged = true
		}
	}
	if adminChanged {
		s.invalidateAdminCache()
	}
	c.JSON(http.StatusOK, gin.H{"message": "设置已更新"})
}

func (s *AdminServer) handleUpdateAdmin(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	if req.Username != "" {
		s.db.Save(&database.Config{Key: "admin_username", Value: req.Username})
		s.invalidateAdminCache()
	}
	if req.Password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err == nil {
			s.db.Save(&database.Config{Key: "admin_password", Value: string(hash)})
			s.invalidateAdminCache()
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "管理员密码已更新，请重新登录"})
}

func (s *AdminServer) verifyJWT(ts string) (*jwt.Token, error) {
	return jwt.Parse(ts, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return s.jwtSecret, nil
	})
}

func (s *AdminServer) handleBackup(c *gin.Context) {
	var users []database.User
	if err := s.db.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "备份用户失败"})
		return
	}
	c.Header("Content-Type", "application/json")
	c.Header("Content-Disposition", "attachment; filename=users_backup.json")
	c.JSON(http.StatusOK, gin.H{"version": 1, "users": toPublicUsers(users)})
}

func (s *AdminServer) handleRestore(c *gin.Context) {
	data, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的备份文件"})
		return
	}
	var users []database.User
	if err := json.Unmarshal(data, &users); err != nil {
		var backup struct {
			Users []database.User `json:"users"`
		}
		if err := json.Unmarshal(data, &backup); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "无效的备份文件"})
			return
		}
		users = backup.Users
	}
	count := 0
	for _, u := range users {
		if u.Hash == "" && u.Password != "" {
			u.Hash = common.SHA224String(u.Password)
		}
		if u.Hash == "" {
			continue
		}
		var exist database.User
		if s.db.Where("hash = ?", u.Hash).First(&exist).Error != nil {
			u.ID = 0
			if err := s.db.Create(&u).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复用户失败"})
				return
			}
			if len(s.auths) > 0 && u.Status == 0 {
				for _, a := range s.auths {
					a.AddUser(u.Hash)
				}
			}
			count++
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("恢复成功: %d 个用户", count)})
}

func (s *AdminServer) handleGetStatus(c *gin.Context) {
	var count int64
	s.db.Model(&database.User{}).Count(&count)
	c.JSON(http.StatusOK, gin.H{"user_count": count})
}

func (s *AdminServer) handleGetServerInfo(c *gin.Context) {
	cpuPercent, _ := cpu.Percent(0, false)
	vmInfo, _ := mem.VirtualMemory()
	diskInfo, _ := disk.Usage("/")
	loadInfo, _ := load.Avg()
	hostInfo, _ := host.Info()
	tcpConns, _ := psnet.Connections("tcp")
	udpConns, _ := psnet.Connections("udp")
	c.JSON(http.StatusOK, gin.H{
		"cpu":    cpuPercent,
		"memory": vmInfo,
		"disk":   diskInfo,
		"load":   loadInfo,
		"host":   hostInfo,
		"connections": gin.H{
			"tcp": len(tcpConns),
			"udp": len(udpConns),
		},
	})
}

func (s *AdminServer) getMainNodeInfo() (string, int, bool, string) {
	// 默认回退值
	domain := ""
	port := 443
	wsEnabled := s.wsEnabled
	wsPath := s.wsPath

	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}

	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err == nil {
		var cfg map[string]any
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			// 1. 读取端口
			if lp, ok := cfg["local_port"].(int); ok {
				port = lp
			} else if lpFloat, ok := cfg["local_port"].(float64); ok {
				port = int(lpFloat)
			}

			// 2. 读取 SNI 域名
			if sslVal, ok := cfg["ssl"].(map[string]any); ok {
				if sni, ok2 := sslVal["sni"].(string); ok2 && sni != "" {
					domain = sni
				}
			} else if sslAny, ok := cfg["ssl"].(map[any]any); ok {
				if sni, ok2 := sslAny["sni"].(string); ok2 && sni != "" {
					domain = sni
				}
			}

			// 3. 读取 WebSocket 状态
			if wsVal, ok := cfg["websocket"].(map[string]any); ok {
				if en, ok2 := wsVal["enabled"].(bool); ok2 {
					wsEnabled = en
				}
				if path, ok2 := wsVal["path"].(string); ok2 {
					wsPath = path
				}
			} else if wsAny, ok := cfg["websocket"].(map[any]any); ok {
				if en, ok2 := wsAny["enabled"].(bool); ok2 {
					wsEnabled = en
				}
				if path, ok2 := wsAny["path"].(string); ok2 {
					wsPath = path
				}
			}
		}
	}
	return domain, port, wsEnabled, wsPath
}

func (s *AdminServer) handleSub(c *gin.Context) {
	if s.isNode {
		log.Warn("subscription request blocked on worker node")
		s.serveMaskPage(c)
		return
	}
	token := c.Query("token")
	if token == "" {
		c.String(http.StatusBadRequest, "Missing token")
		return
	}
	var user database.User
	if err := s.db.Where("hash = ? AND status = 0", token).First(&user).Error; err != nil {
		c.String(http.StatusNotFound, "Invalid token or user disabled")
		return
	}
	if user.ExpiryTime != nil && !user.ExpiryTime.IsZero() && user.ExpiryTime.Before(time.Now()) {
		c.String(http.StatusForbidden, "User expired")
		return
	}
	domain, _, _ := net.SplitHostPort(c.Request.Host)
	if domain == "" {
		domain = c.Request.Host
	}

	mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
	if mainDomain == "" {
		mainDomain = domain
	}

	c.Header("Content-Type", "text/yaml; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=clash-%s.yaml", user.Username))

	// 拉取全部节点生成订阅
	var nodes []database.Node
	s.db.Find(&nodes)
	c.String(http.StatusOK, generateClashConfigMultiNode(s.db, user, nodes, mainDomain, mainPort, mainWs, mainWsPath))
}

// ─── 节点管理 API 处理器 ──────────────────────────────

func (s *AdminServer) handleListNodes(c *gin.Context) {
	var nodes []database.Node
	s.db.Find(&nodes)

	// 如果当前不是从节点（即为主节点），则将主节点自身作为虚拟节点加入列表头部
	if !s.isNode {
		mainNodeName := "主节点"
		var cfgTitle database.Config
		if s.db.Where("`key` = ?", "site_title").First(&cfgTitle).Error == nil && cfgTitle.Value != "" {
			mainNodeName = cfgTitle.Value
		}

		host := c.Request.Host
		domain, _, err := net.SplitHostPort(host)
		if err != nil {
			domain = host
		}

		mainDomain, mainPort, mainWs, mainWsPath := s.getMainNodeInfo()
		if mainDomain == "" {
			mainDomain = domain
		}

		now := time.Now()
		mainNode := database.Node{
			ID:            999999, // 使用特殊的大ID标识系统内置主节点
			Name:          mainNodeName,
			Address:       mainDomain,
			Port:          mainPort,
			Secret:        "MasterNodeSecretKey",
			TrafficRate:   1.0,
			WSEnabled:     mainWs,
			WSPath:        mainWsPath,
			LastHeartbeat: &now,
		}
		nodes = append([]database.Node{mainNode}, nodes...)
	}

	c.JSON(http.StatusOK, nodes)
}

func (s *AdminServer) handleAddNode(c *gin.Context) {
	var node database.Node
	if err := c.ShouldBindJSON(&node); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}
	if node.Name == "" || node.Address == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "节点名称和地址不能为空"})
		return
	}
	// 自动生成随机 16 字节的安全 Secret (Hex 编码，共 32 字符)
	if node.Secret == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err == nil {
			node.Secret = hex.EncodeToString(b)
		}
	}
	if err := s.db.Create(&node).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, node)
}

func (s *AdminServer) handleUpdateNode(c *gin.Context) {
	id := c.Param("id")
	if id == "999999" {
		var req struct {
			Name string `json:"name"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		if req.Name != "" {
			var cfg database.Config
			if err := s.db.Where("`key` = ?", "site_title").Assign(database.Config{Value: req.Name}).FirstOrCreate(&cfg, database.Config{Key: "site_title"}).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
				return
			}
		}
		c.JSON(http.StatusOK, gin.H{"message": "主节点名称更新成功"})
		return
	}

	var req struct {
		Name        string   `json:"name"`
		Address     string   `json:"address"`
		Port        *int     `json:"port"`
		Secret      string   `json:"secret"`
		TrafficRate *float64 `json:"traffic_rate"`
		WSEnabled   *bool    `json:"ws_enabled"`
		WSPath      string   `json:"ws_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var node database.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}
	updates := map[string]interface{}{}
	if req.Name != "" {
		updates["name"] = req.Name
	}
	if req.Address != "" {
		updates["address"] = req.Address
	}
	if req.Port != nil {
		updates["port"] = *req.Port
	}
	if req.Secret != "" {
		updates["secret"] = req.Secret
	}
	if req.TrafficRate != nil {
		updates["traffic_rate"] = *req.TrafficRate
	}
	if req.WSEnabled != nil {
		updates["ws_enabled"] = *req.WSEnabled
	}
	if req.WSPath != "" {
		path := req.WSPath
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		updates["ws_path"] = path
	}
	s.db.Model(&node).Updates(updates)
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (s *AdminServer) handleDeleteNode(c *gin.Context) {
	var node database.Node
	if s.db.First(&node, c.Param("id")).Error == nil {
		s.db.Delete(&node)
	}
	c.JSON(http.StatusOK, gin.H{"message": "已删除"})
}

// ─── 从节点心跳与数据同步接口 ───────────────────────────

func (s *AdminServer) handleNodeSync(c *gin.Context) {
	secret := c.GetHeader("X-Node-Secret")
	if secret == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "缺少通信密钥"})
		return
	}
	var node database.Node
	if err := s.db.Where("secret = ?", secret).First(&node).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的通信密钥"})
		return
	}
	now := time.Now()
	node.LastHeartbeat = &now
	node.Status = 1
	clientIP := c.ClientIP()
	if clientIP != "" && clientIP != "::1" && clientIP != "127.0.0.1" {
		node.DetectedIP = clientIP
	}
	s.db.Save(&node)

	var req struct {
		Traffic map[string]struct {
			Up   uint64 `json:"up"`
			Down uint64 `json:"down"`
		} `json:"traffic"`
	}
	if err := c.ShouldBindJSON(&req); err == nil && len(req.Traffic) > 0 {
		s.db.Transaction(func(tx *gorm.DB) error {
			for hash, t := range req.Traffic {
				total := int64((t.Up + t.Down))
				if node.TrafficRate != 1.0 {
					total = int64(float64(total) * node.TrafficRate)
				}
				tx.Model(&database.User{}).Where("hash = ?", hash).Updates(map[string]interface{}{
					"upload":   gorm.Expr("upload + ?", int64(t.Up)),
					"download": gorm.Expr("download + ?", int64(t.Down)),
					"used":     gorm.Expr("used + ?", total),
				})
			}
			return nil
		})
	}

	var users []database.User
	s.db.Where("status = ?", 0).Find(&users)
	validHashes := []string{}
	for _, u := range users {
		if u.ExpiryTime != nil && !u.ExpiryTime.IsZero() && u.ExpiryTime.Before(now) {
			continue
		}
		if u.Quota > 0 && u.Used >= u.Quota {
			continue
		}
		if u.Hash != "" {
			validHashes = append(validHashes, u.Hash)
		}
	}
	c.JSON(http.StatusOK, gin.H{"users": validHashes})
}

// ─── 多节点 Clash 订阅配置文件生成器 ─────────────────────

func generateClashConfigMultiNode(db *gorm.DB, u database.User, nodes []database.Node, defaultDomain string, defaultPort int, defaultWS bool, defaultWSPath string) string {
	var sb strings.Builder
	var cfgRules, cfgProviders database.Config
	rulesStr := ""
	if db.Where("`key` = ?", "clash_rules").First(&cfgRules).Error == nil {
		rulesStr = cfgRules.Value
	}
	providersStr := ""
	if db.Where("`key` = ?", "clash_rule_providers").First(&cfgProviders).Error == nil {
		providersStr = cfgProviders.Value
	}

	sb.WriteString("port: 7890\nsocks-port: 7891\nallow-lan: true\nmode: rule\nlog-level: info\n\n")
	sb.WriteString("dns:\n  enable: true\n  ipv6: false\n  listen: 0.0.0.0:53\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n  fallback:\n    - 8.8.8.8\n    - 1.1.1.1\n    - https://dns.google/dns-query\n  nameserver-policy:\n    'geosite:cn': 223.5.5.5\n    'github.com': 8.8.8.8\n    'cdn.jsdelivr.net': 119.29.29.29\n\n")
	sb.WriteString("tun:\n  enable: true\n  stack: gvisor\n  auto-route: true\n  auto-detect-interface: true\n\n")

	if providersStr != "" {
		if !strings.Contains(providersStr, "rule-providers:") {
			sb.WriteString("rule-providers:\n")
		}
		sb.WriteString(providersStr)
		sb.WriteString("\n\n")
	}

	sb.WriteString("proxies:\n")

	// 1. 永远先生成主节点代理配置
	mainNodeName := "主节点"
	var cfgTitle database.Config
	if db.Where("`key` = ?", "site_title").First(&cfgTitle).Error == nil && cfgTitle.Value != "" {
		mainNodeName = cfgTitle.Value
	}
	sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: true\n",
		mainNodeName, defaultDomain, defaultPort, u.Password, defaultDomain))
	if defaultWS {
		sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: \"%s\"\n      headers:\n        Host: %s\n", defaultWSPath, defaultDomain))
	}
	sb.WriteString("\n")

	// 2. 依次生成从节点代理配置
	for _, node := range nodes {
		nodeName := node.Name
		if nodeName == "" {
			nodeName = node.Address
		}
		sb.WriteString(fmt.Sprintf("  - name: \"%s\"\n    type: trojan\n    server: %s\n    port: %d\n    password: %s\n    udp: true\n    sni: %s\n    skip-cert-verify: true\n",
			nodeName, node.Address, node.Port, u.Password, node.Address))
		if node.WSEnabled {
			sb.WriteString(fmt.Sprintf("    network: ws\n    ws-opts:\n      path: \"%s\"\n      headers:\n        Host: %s\n", node.WSPath, node.Address))
		}
		sb.WriteString("\n")
	}

	// 收集全部节点名（主节点 + 从节点），用于生成代理组
	nodeNames := make([]string, 0, len(nodes)+1)
	nodeNames = append(nodeNames, mainNodeName)
	for _, node := range nodes {
		nodeName := node.Name
		if nodeName == "" {
			nodeName = node.Address
		}
		nodeNames = append(nodeNames, nodeName)
	}

	// PROXY: 手动选择组，第一项为"自动选择"，用户默认无需干预即走最低延迟节点
	sb.WriteString("proxy-groups:\n  - name: \"PROXY\"\n    type: select\n    proxies:\n")
	sb.WriteString("      - \"自动选择\"\n")
	for _, name := range nodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	// 自动选择: url-test 组，客户端周期性测速自动挑选延迟最低的节点（电信/移动线路自适应）
	sb.WriteString("  - name: \"自动选择\"\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	for _, name := range nodeNames {
		sb.WriteString(fmt.Sprintf("      - \"%s\"\n", name))
	}

	if rulesStr != "" {
		sb.WriteString("\n")
		if !strings.Contains(rulesStr, "rules:") {
			sb.WriteString("rules:\n")
		}
		sb.WriteString(rulesStr)
	} else {
		sb.WriteString("\nrules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY")
	}
	sb.WriteString("\n")
	return sb.String()
}

// publicUser is the non-sensitive representation returned by management APIs.
// Password remains available internally for explicit share/subscription generation,
// but is never serialized as part of ordinary user responses.
type publicUser struct {
	ID         uint       `json:"id"`
	CreatedAt  time.Time  `json:"created_at"`
	Username   string     `json:"username"`
	Hash       string     `json:"hash"`
	Quota      int64      `json:"quota"`
	Used       int64      `json:"used"`
	Upload     int64      `json:"upload"`
	Download   int64      `json:"download"`
	ExpiryTime *time.Time `json:"expiry_time"`
	IPLimit    int        `json:"ip_limit"`
	Status     int        `json:"status"`
}

func toPublicUser(user database.User) publicUser {
	return publicUser{
		ID: user.ID, CreatedAt: user.CreatedAt, Username: user.Username,
		Hash: user.Hash, Quota: user.Quota, Used: user.Used,
		Upload: user.Upload, Download: user.Download, ExpiryTime: user.ExpiryTime,
		IPLimit: user.IPLimit, Status: user.Status,
	}
}

func toPublicUsers(users []database.User) []publicUser {
	result := make([]publicUser, 0, len(users))
	for _, user := range users {
		result = append(result, toPublicUser(user))
	}
	return result
}

// handleListUsers lists users without exposing their reusable passwords.
func (s *AdminServer) handleListUsers(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	var users []database.User
	if err := s.db.Find(&users).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取用户失败"})
		return
	}
	c.JSON(http.StatusOK, toPublicUsers(users))
}

func (s *AdminServer) handleAddUser(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	var user database.User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的参数"})
		return
	}
	if user.Username == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名和密码不能为空"})
		return
	}
	user.Hash = common.SHA224String(user.Password)
	var existing database.User
	if err := s.db.Where("hash = ?", user.Hash).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("此密码已被用户 [%s] 使用", existing.Username)})
		return
	}
	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if len(s.auths) > 0 && user.Status == 0 {
		for _, a := range s.auths {
			a.AddUser(user.Hash)
		}
	}
	c.JSON(http.StatusOK, toPublicUser(user))
}

func (s *AdminServer) handleUpdateUser(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	id := c.Param("id")
	var req struct {
		Username   string  `json:"username"`
		Password   string  `json:"password"`
		Status     *int    `json:"status"`
		ExpiryDays *int    `json:"expiry_days"`
		ExpiryTime *string `json:"expiry_time"`
		Quota      *int64  `json:"quota"`
		IPLimit    *int    `json:"ip_limit"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	var user database.User
	if err := s.db.First(&user, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	oldHash := user.Hash
	updates := map[string]interface{}{}
	if req.Username != "" {
		updates["username"] = req.Username
	}
	if req.Status != nil {
		updates["status"] = *req.Status
	}
	if req.Quota != nil {
		updates["quota"] = *req.Quota
	}
	if req.IPLimit != nil {
		updates["ip_limit"] = *req.IPLimit
	}
	if req.Password != "" {
		newHash := common.SHA224String(req.Password)
		var existing database.User
		if err := s.db.Where("hash = ? AND id != ?", newHash, id).First(&existing).Error; err == nil {
			c.JSON(http.StatusConflict, gin.H{"error": "此密码已被其他用户使用"})
			return
		}
		updates["password"] = req.Password
		updates["hash"] = newHash
		user.Hash = newHash // 用于后续同步
	}
	if req.ExpiryDays != nil {
		if *req.ExpiryDays > 0 {
			expiry := time.Now().AddDate(0, 0, *req.ExpiryDays)
			updates["expiry_time"] = &expiry
		} else {
			updates["expiry_time"] = nil
		}
	}
	if req.ExpiryTime != nil {
		val := *req.ExpiryTime
		if val == "" || val == "null" {
			updates["expiry_time"] = nil
		} else {
			t, err := time.Parse("2006-01-02 15:04:05", val)
			if err == nil {
				updates["expiry_time"] = &t
			} else {
				t, err = time.Parse("2006-01-02", val)
				if err == nil {
					t = time.Date(t.Year(), t.Month(), t.Day(), 23, 59, 59, 0, time.Local)
					updates["expiry_time"] = &t
				} else {
					c.JSON(http.StatusBadRequest, gin.H{"error": "无效的到期时间格式"})
					return
				}
			}
		}
	}
	s.db.Model(&user).Updates(updates)

	// 同步所有存在的核心
	if len(s.auths) > 0 {
		for _, a := range s.auths {
			a.DelUser(oldHash)
		}
		s.db.First(&user, id) // 获取更新后的状态
		if user.Status == 0 {
			for _, a := range s.auths {
				a.AddUser(user.Hash)
			}
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

func (s *AdminServer) handleDeleteUser(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	var user database.User
	if s.db.First(&user, c.Param("id")).Error == nil {
		if len(s.auths) > 0 && user.Hash != "" {
			for _, a := range s.auths {
				a.DelUser(user.Hash)
			}
		}
		s.db.Delete(&user)
	}
	c.JSON(http.StatusOK, gin.H{"message": "已删除"})
}

func (s *AdminServer) handleUpdateQuota(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Quota int64 `json:"quota"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	s.db.Model(&database.User{}).Where("id = ?", id).Update("quota", req.Quota)
	c.JSON(http.StatusOK, gin.H{"message": "限额设置成功"})
}

func (s *AdminServer) handleClearTraffic(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	s.db.Model(&database.User{}).Where("id = ?", c.Param("id")).Updates(map[string]interface{}{
		"used": 0, "upload": 0, "download": 0,
	})
	c.JSON(http.StatusOK, gin.H{"message": "流量已清空"})
}

func (s *AdminServer) handleSetExpire(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Days int `json:"days"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	expiry := time.Now().AddDate(0, 0, req.Days)
	s.db.Model(&database.User{}).Where("id = ?", id).Update("expiry_time", &expiry)
	c.JSON(http.StatusOK, gin.H{"message": "过期时间设置成功", "expiry": expiry})
}

func (s *AdminServer) handleCancelExpire(c *gin.Context) {
	s.db.Model(&database.User{}).Where("id = ?", c.Param("id")).Update("expiry_time", nil)
	c.JSON(http.StatusOK, gin.H{"message": "已取消限期"})
}

func (s *AdminServer) handleShare(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	var user database.User
	if err := s.db.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	domain := s.serverDomain
	if domain == "" {
		domain = c.DefaultQuery("domain", c.Request.Host)
		if strings.Contains(domain, ":") {
			domain, _, _ = net.SplitHostPort(domain)
		}
	}
	remark := url.QueryEscape(fmt.Sprintf("%s:%d", domain, 443))
	link := fmt.Sprintf("trojan://%s@%s:%d#%s", user.Password, domain, 443, remark)
	if s.wsEnabled {
		link = fmt.Sprintf("trojan://%s@%s:%d?type=ws&path=%s&host=%s#%s", user.Password, domain, 443, url.QueryEscape(s.wsPath), domain, remark)
	}
	effSubPath := "/sub"
	if s.subPath != "" {
		effSubPath = s.subPath
	}
	subLink := fmt.Sprintf("https://%s%s?token=%s", domain, effSubPath, user.Hash)
	c.JSON(http.StatusOK, gin.H{"link": link, "sub_link": subLink, "username": user.Username})
}

// ─── 跨平台服务管理辅助函数 ─────────────────────────

// hasSystemctl 检测当前环境是否支持 systemctl
func hasSystemctl() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// getServiceLogs 获取服务日志（优先 journalctl，不可用时返回错误提示）
func getServiceLogs(lines, level string) ([]byte, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("日志服务不可用（journalctl 未找到），请直接查看进程输出")
	}
	args := []string{"-u", "trojan-go", "-n", lines, "--no-pager", "-o", "cat"}
	if level != "" && level != "all" {
		p := ""
		switch level {
		case "info":
			p = "6"
		case "warn":
			p = "4"
		case "error":
			p = "3"
		}
		if p != "" {
			args = append(args, "-p", p)
		}
	}
	return exec.Command("journalctl", args...).CombinedOutput()
}

// controlService 控制 systemd 服务（不可用时返回错误）
func controlService(action string) ([]byte, error) {
	if !hasSystemctl() {
		return nil, fmt.Errorf("systemctl 不可用（非 systemd 环境），请手动操作服务")
	}
	if action == "is-active" {
		return exec.Command("systemctl", "is-active", "trojan-go").Output()
	}
	cmd := exec.Command("systemctl", action, "trojan-go")
	if action == "stop" || action == "restart" {
		return cmd.Output()
	}
	return nil, cmd.Start() // start: 不等待
}

// restartService 重启服务，systemd 不可用时退化为进程内优雅关闭
func restartService() {
	if hasSystemctl() {
		exec.Command("systemctl", "restart", "trojan-go").Run()
		return
	}
	log.Warn("systemctl 不可用，执行进程内优雅退出（请由进程管理器自动重启）")
	common.SignalShutdown()
}

func (s *AdminServer) handleGetLogs(c *gin.Context) {
	lines := c.DefaultQuery("lines", "300")
	level := c.Query("level")

	out, err := getServiceLogs(lines, level)
	if err != nil {
		c.String(http.StatusInternalServerError, "获取日志失败: "+err.Error()+"\n"+string(out))
		return
	}
	c.String(http.StatusOK, string(out))
}

func (s *AdminServer) handleServiceControl(c *gin.Context) {
	var req struct {
		Action string `json:"action"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效动作"})
		return
	}
	validActions := map[string]bool{"start": true, "stop": true, "restart": true, "status": true}
	if !validActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持该操作"})
		return
	}
	if req.Action == "status" {
		out, err := controlService("is-active")
		status := strings.TrimSpace(string(out))
		if err != nil || status == "" {
			if !hasSystemctl() {
				status = "running (standalone mode)"
			} else {
				status = "unknown"
			}
		}
		c.JSON(http.StatusOK, gin.H{"status": status})
		return
	}
	if _, err := controlService(req.Action); err != nil && !hasSystemctl() {
		if req.Action == "restart" || req.Action == "stop" {
			go func() {
				time.Sleep(200 * time.Millisecond)
				restartService()
			}()
			c.JSON(http.StatusOK, gin.H{"message": "systemctl 不可用，正在尝试执行进程内优雅关闭/重启..."})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("正在尝试 %s 服务...", req.Action)})
}

func (s *AdminServer) handleRestart(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "正在重启..."})
	go func() {
		time.Sleep(200 * time.Millisecond)
		restartService()
	}()
}

// ServeConn 将一条已完成 TLS 握手的连接交给管理面板处理
// 由 TLS acceptLoop 调用
func (s *AdminServer) ServeConn(conn net.Conn) {
	select {
	case s.connChan <- conn:
	case <-s.done:
		conn.Close()
	}
}

// Handler 返回 http.Handler（备用，供测试使用）
func (s *AdminServer) Handler() http.Handler {
	return s.handler
}

// --- 实现 net.Listener 接口，让 http.Server.Serve 能消费 chanListener ---

func (s *AdminServer) Accept() (net.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.done:
		return nil, fmt.Errorf("admin server closed")
	}
}

func (s *AdminServer) doneOpen() bool {
	select {
	case <-s.done:
		return false
	default:
		return true
	}
}

func (s *AdminServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.done)
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if s.httpServer != nil {
			if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
				_ = s.httpServer.Close()
			}
		}
		if s.standaloneServer != nil {
			if err := s.standaloneServer.Shutdown(shutdownCtx); err != nil {
				_ = s.standaloneServer.Close()
			}
		}
		if s.standaloneListener != nil {
			_ = s.standaloneListener.Close()
		}
	})
	s.workers.Wait()
	return nil
}

func (s *AdminServer) Addr() net.Addr {
	return &net.TCPAddr{} // 不真实监听任何地址
}

// serveMaskPage 渲染本地伪装网页，用于防探测
func (s *AdminServer) serveMaskPage(c *gin.Context) {
	if s.maskHtmlPath != "" {
		if data, err := os.ReadFile(s.maskHtmlPath); err == nil {
			c.Data(http.StatusOK, "text/html; charset=utf-8", data)
			return
		}
	}
	// 兜底一：尝试读取默认配置文件路径的 index.html
	if data, err := os.ReadFile("/etc/trojan-go/index.html"); err == nil {
		c.Data(http.StatusOK, "text/html; charset=utf-8", data)
		return
	}
	// 兜底二：普通文本
	c.String(http.StatusOK, "Welcome to nginx")
}

func (s *AdminServer) resetTrafficWorker() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var cfg database.Config
			if s.db.Where("`key` = ?", "traffic_reset_day").First(&cfg).Error == nil {
				resetDay := 0
				fmt.Sscanf(cfg.Value, "%d", &resetDay)
				if resetDay > 0 && time.Now().Day() == resetDay {
					// 检查本月是否已重置过，防止一天内重置多次
					lastResetMonth := ""
					var cfgLast database.Config
					if s.db.Where("`key` = ?", "last_reset_month").First(&cfgLast).Error == nil {
						lastResetMonth = cfgLast.Value
					}
					currentMonth := time.Now().Format("2006-01")
					if lastResetMonth != currentMonth {
						log.Infof("自动重置日已达(%d号)，正在清空所有用户流量...", resetDay)
						s.db.Model(&database.User{}).Updates(map[string]interface{}{"used": 0, "upload": 0, "download": 0})
						s.db.Save(&database.Config{Key: "last_reset_month", Value: currentMonth})
					}
				}
			}
		case <-s.done:
			return
		}
	}
}

// trafficSyncWorker 定期将内存中的实时流量统计同步到数据库中
func (s *AdminServer) trafficSyncWorker() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if len(s.auths) == 0 {
				continue
			}
			// 从所有认证器链路收集并合并流量
			trafficMap := make(map[string]struct{ up, down uint64 })
			for _, a := range s.auths {
				for _, st := range a.ListUsers() {
					hash := st.Hash()
					sent, recv := st.ResetTraffic()
					if sent == 0 && recv == 0 {
						continue
					}
					v := trafficMap[hash]
					v.up += recv   // 客户端上传 = 服务端接收
					v.down += sent // 客户端下载 = 服务端发送
					trafficMap[hash] = v
				}
			}

			if len(trafficMap) == 0 {
				select {
				case <-s.done:
					return
				default:
				}
				continue
			}

			// 开启事务，合并所有流量更新操作，防止碎片化 I/O 导致 SQLite 锁定
			s.db.Transaction(func(tx *gorm.DB) error {
				for hash, t := range trafficMap {
					tx.Model(&database.User{}).Where("hash = ?", hash).Updates(map[string]interface{}{
						"upload":   gorm.Expr("upload + ?", int64(t.up)),
						"download": gorm.Expr("download + ?", int64(t.down)),
						"used":     gorm.Expr("used + ?", int64(t.up+t.down)),
					})
				}
				return nil
			})
		case <-s.done:
			return
		}
	}
}

// ─── 流量格式化工具函数 ──────────────────────────────
func FormatBytes(bytes uint64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
		TB = GB * 1024
	)
	switch {
	case bytes >= TB:
		return strconv.FormatFloat(float64(bytes)/float64(TB), 'f', 2, 64) + " TB"
	case bytes >= GB:
		return strconv.FormatFloat(float64(bytes)/float64(GB), 'f', 2, 64) + " GB"
	case bytes >= MB:
		return strconv.FormatFloat(float64(bytes)/float64(MB), 'f', 2, 64) + " MB"
	case bytes >= KB:
		return strconv.FormatFloat(float64(bytes)/float64(KB), 'f', 2, 64) + " KB"
	default:
		return strconv.FormatUint(bytes, 10) + " B"
	}
}

// RunStandalone 以外挂模式启动 Web 管理后台
func RunStandalone(configPath string) error {
	if abs, err := filepath.Abs(configPath); err == nil {
		WebConfigPath = abs
	} else {
		WebConfigPath = configPath
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("读取配置文件失败: %v", err)
	}

	var cfg struct {
		Admin struct {
			Enabled  bool   `yaml:"enabled"`
			Port     int    `yaml:"port"`
			Username string `yaml:"username"`
			Password string `yaml:"password"`
			DBPath   string `yaml:"db"`
			Path     string `yaml:"path"`
		} `yaml:"admin"`
		Node struct {
			Enabled bool `yaml:"enabled"`
		} `yaml:"node"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("解析 YAML 失败: %v", err)
	}

	if !cfg.Admin.Enabled {
		return fmt.Errorf("配置文件中未启用 admin 模块")
	}

	// 初始化数据库
	db, err := database.InitDb(cfg.Admin.DBPath)
	if err != nil {
		return fmt.Errorf("初始化数据库失败: %v", err)
	}

	log.Infof("启动独立 Web 管理后台, 监听端口: %d", cfg.Admin.Port)
	srv := New(db, cfg.Admin.Username, cfg.Admin.Password, cfg.Admin.Path, cfg.Admin.Port, false, "", false, cfg.Node.Enabled, "", "", "")

	// 这里我们需要一个不会自动退出的方式运行
	// New 内部已经启动了 http.Server (如果 port > 0)
	// 我们只需要阻塞主协程
	select {
	case <-srv.done:
	case <-common.ShutdownContext().Done():
		log.Info("独立 Web 管理后台收到全局退出信号，正在优雅关闭...")
		srv.Close()
	}
	return nil
}

func (s *AdminServer) getMasterNodeSyncConfig() (string, string) {
	masterURL := ""
	secret := ""
	paths := []string{"config.yaml", "config.yml", "/etc/trojan-go/config.yaml"}
	if WebConfigPath != "" {
		dir := filepath.Dir(WebConfigPath)
		paths = append([]string{filepath.Join(dir, "config.yaml"), filepath.Join(dir, "config.yml")}, paths...)
	}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err == nil {
		var cfg map[string]any
		if err := yaml.Unmarshal(data, &cfg); err == nil {
			if nodeVal, ok := cfg["node"].(map[string]any); ok {
				masterURL, _ = nodeVal["master_url"].(string)
				secret, _ = nodeVal["secret"].(string)
			} else if nodeAny, ok := cfg["node"].(map[any]any); ok {
				masterURL, _ = nodeAny["master_url"].(string)
				secret, _ = nodeAny["secret"].(string)
			}
		}
	}
	return masterURL, secret
}

func (s *AdminServer) proxyToMaster(c *gin.Context) {
	masterURL, secret := s.getMasterNodeSyncConfig()
	if masterURL == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "从节点未配置主节点同步 URL，无法同步操作"})
		return
	}
	u, err := url.Parse(masterURL)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "主节点 URL 解析失败"})
		return
	}

	targetURL := u.Scheme + "://" + u.Host + c.Request.URL.Path
	if c.Request.URL.RawQuery != "" {
		targetURL += "?" + c.Request.URL.RawQuery
	}

	var body io.Reader
	if c.Request.Body != nil {
		body = c.Request.Body
	}

	req, err := http.NewRequest(c.Request.Method, targetURL, body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建转发请求失败: " + err.Error()})
		return
	}

	// 拷贝原有请求头，并覆盖通信鉴权 Key
	for k, vv := range c.Request.Header {
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}
	req.Header.Set("X-Node-Secret", secret)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "转发请求到主节点失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	// 把主节点的返回头和状态码拷给当前响应
	for k, vv := range resp.Header {
		for _, v := range vv {
			c.Header(k, v)
		}
	}
	c.Status(resp.StatusCode)
	io.Copy(c.Writer, resp.Body)
}

func (s *AdminServer) handleGetMasterConfig(c *gin.Context) {
	masterURL, secret := s.getMasterNodeSyncConfig()
	c.JSON(http.StatusOK, gin.H{
		"master_url": masterURL,
		"secret":     secret,
	})
}

func (s *AdminServer) handleTestSync(c *gin.Context) {
	masterURL, secret := s.getMasterNodeSyncConfig()
	if masterURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "从节点未配置主节点同步 URL"})
		return
	}

	if _, err := url.Parse(masterURL); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "URL 格式错误: " + err.Error()})
		return
	}

	var reqBody struct {
		Traffic map[string]any `json:"traffic"`
	}
	reqBody.Traffic = make(map[string]any)

	bodyData, _ := json.Marshal(reqBody)
	req, err := http.NewRequest("POST", masterURL, bytes.NewBuffer(bodyData))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建探测请求失败: " + err.Error()})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Node-Secret", secret)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "fail", "error": "连接主节点失败: " + err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		c.JSON(http.StatusOK, gin.H{"status": "fail", "error": fmt.Sprintf("主节点返回异常状态码: %d", resp.StatusCode)})
		return
	}

	var respBody struct {
		Users []string `json:"users"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&respBody); err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "fail", "error": "解析主节点响应失败: " + err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status":  "ok",
		"message": fmt.Sprintf("主节点连接成功！同步心跳响应正常，目前主节点下发有效用户数: %d 个。", len(respBody.Users)),
	})
}

func (s *AdminServer) handlePingNode(c *gin.Context) {
	id := c.Param("id")
	var node database.Node
	if err := s.db.First(&node, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "节点不存在"})
		return
	}

	addr := net.JoinHostPort(node.Address, strconv.Itoa(node.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "fail", "error": "TCP 连接失败: " + err.Error()})
		return
	}
	conn.Close()
	c.JSON(http.StatusOK, gin.H{"status": "ok", "message": "节点代理端口探测成功，网络握手正常！"})
}

// modifyYamlField 在不破坏排版和注释的前提下，修改指定 parent 节下的 key 字段值
func modifyYamlField(content, parentKey, key string, value any) (string, error) {
	lines := strings.Split(content, "\n")
	var newLines []string
	inParent := false
	modified := false

	valStr := fmt.Sprintf("%v", value)
	if s, ok := value.(string); ok {
		if !strings.HasPrefix(s, "\"") {
			valStr = fmt.Sprintf("\"%s\"", s)
		}
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, parentKey+":") {
			inParent = true
			newLines = append(newLines, line)
			continue
		}

		if inParent {
			if len(line) > 0 && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "#") {
				inParent = false
			} else if strings.HasPrefix(trimmed, key+":") && !modified {
				parts := strings.SplitN(line, ":", 2)
				leadingSpace := parts[0]

				lineComment := ""
				if len(parts) > 1 && strings.Contains(parts[1], "#") {
					cParts := strings.SplitN(parts[1], "#", 2)
					lineComment = " #" + cParts[1]
				}

				line = fmt.Sprintf("%s: %s%s", leadingSpace, valStr, strings.TrimRight(lineComment, "\r\n"))
				modified = true
			}
		}

		newLines = append(newLines, line)
	}

	return strings.Join(newLines, "\n"), nil
}
