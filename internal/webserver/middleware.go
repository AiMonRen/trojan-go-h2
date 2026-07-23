package webserver

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"golang.org/x/crypto/bcrypt"
)

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

func (s *AdminServer) limitRequestBody() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxAdminRequestBody)
		}
		c.Next()
	}
}

func (s *AdminServer) rateLimitExceeded(entries map[string]rateLimitEntry, key string, limit int) bool {
	now := time.Now()
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()
	entry, ok := entries[key]
	if !ok || !now.Before(entry.ResetAt) {
		if ok {
			delete(entries, key)
		}
		return false
	}
	return entry.Count >= limit
}

func (s *AdminServer) recordRateLimitEvent(entries map[string]rateLimitEntry, key string, window time.Duration) {
	now := time.Now()
	s.rateLimitMu.Lock()
	defer s.rateLimitMu.Unlock()
	if len(entries) >= maxRateLimitEntries {
		for candidate, entry := range entries {
			if !now.Before(entry.ResetAt) {
				delete(entries, candidate)
			}
		}
		if len(entries) >= maxRateLimitEntries {
			return
		}
	}
	entry := entries[key]
	if entry.ResetAt.IsZero() || !now.Before(entry.ResetAt) {
		entry = rateLimitEntry{ResetAt: now.Add(window)}
	}
	entry.Count++
	entries[key] = entry
}

func (s *AdminServer) clearLoginFailures(clientIP string) {
	s.rateLimitMu.Lock()
	delete(s.loginFailures, clientIP)
	s.rateLimitMu.Unlock()
}

func (s *AdminServer) enforceLoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.rateLimitExceeded(s.loginFailures, c.ClientIP(), loginFailureLimit) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "登录尝试过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		c.Next()
	}
}

// requireAdminSession is used for credential and service-control operations that
// must never be authorized only by a Worker communication secret.
func (s *AdminServer) requireAdminSession() gin.HandlerFunc {
	return func(c *gin.Context) {
		ts := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
		if ts == "" {
			ts = c.Query("token")
		}
		token, err := s.verifyJWT(ts)
		if err != nil || token == nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "需要管理员会话"})
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

func (s *AdminServer) enforceAdminRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if s.rateLimitExceeded(s.adminRequests, c.ClientIP(), adminRequestLimit) {
			c.JSON(http.StatusTooManyRequests, gin.H{"error": "管理请求过于频繁，请稍后再试"})
			c.Abort()
			return
		}
		s.recordRateLimitEvent(s.adminRequests, c.ClientIP(), adminRequestWindow)
		c.Next()
	}
}

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
		s.clearLoginFailures(c.ClientIP())
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
		s.recordRateLimitEvent(s.loginFailures, c.ClientIP(), loginFailureWindow)
		log.Warnf("Web panel login failed for username=%q from ip=%s", req.Username, c.ClientIP())
		time.Sleep(1500 * time.Millisecond) // 防暴力破解延迟
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
	}
}
