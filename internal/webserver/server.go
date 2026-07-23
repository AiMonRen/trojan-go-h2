package webserver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/internal/nodesync"
	"github.com/voidluo/trojan-go/log"
	"github.com/voidluo/trojan-go/statistic"
	"gopkg.in/yaml.v3"
	"gorm.io/gorm"
)

var WebConfigPath string

const (
	maxAdminRequestBody = 1 << 20 // 1 MiB
	loginFailureLimit   = 5
	loginFailureWindow  = 15 * time.Minute
	adminRequestLimit   = 240
	adminRequestWindow  = time.Minute
	maxRateLimitEntries = 10000
)

type rateLimitEntry struct {
	Count   int
	ResetAt time.Time
}

type subscriptionCacheEntry struct {
	Body      string
	ETag      string
	ExpiresAt time.Time
}

const subscriptionCacheTTL = 15 * time.Second

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

	rateLimitMu   sync.Mutex
	loginFailures map[string]rateLimitEntry
	adminRequests map[string]rateLimitEntry

	subscriptionCacheMu sync.Mutex
	subscriptionCache   map[string]subscriptionCacheEntry
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
		db:                db,
		connChan:          make(chan net.Conn, 64),
		done:              make(chan struct{}),
		configUser:        username,
		configPass:        password,
		wsEnabled:         wsEnabled,
		wsPath:            wsPath,
		muxEnabled:        muxEnabled,
		isNode:            isNode,
		maskHtmlPath:      maskHtmlPath,
		subPath:           subPath,
		serverDomain:      serverDomain,
		loginFailures:     make(map[string]rateLimitEntry),
		adminRequests:     make(map[string]rateLimitEntry),
		subscriptionCache: make(map[string]subscriptionCacheEntry),
	}

	// LoadJWTSecret transparently upgrades legacy plaintext values, while every
	// new value is stored encrypted with the deployment-external credential key.
	jwtSecret, err := database.LoadJWTSecret(db)
	if err != nil {
		log.Fatal("admin panel: load JWT signing secret:", err)
	}
	srv.jwtSecret = jwtSecret

	// 初始化会话激活时间，登录后重新计时
	srv.lastActiveNano.Store(time.Now().UnixNano())

	if isNode {
		if mgr := nodesync.GetManager(); mgr != nil {
			mgr.SetDB(db)
		}
	}

	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	srv.registerRoutes(r, mountPath)
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
		// 独立管理后端仅供本机 HY2 认证接口使用；HTTPS 面板与订阅由 TLS/443
		// 在进程内复用，绝不需要暴露独立 HTTP 端口到公网。
		listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
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
	masterURL, _ := s.getMasterNodeSyncConfig()
	c.JSON(http.StatusOK, gin.H{
		"master_url":        masterURL,
		"secret_configured": masterURL != "",
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
