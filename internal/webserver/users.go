package webserver

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
)

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
	plaintextPassword := user.Password
	user.Hash = common.SHA224String(plaintextPassword)
	var existing database.User
	if err := s.db.Where("hash = ?", user.Hash).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("此密码已被用户 [%s] 使用", existing.Username)})
		return
	}
	// Persist first to obtain a stable user ID for AES-GCM associated data, then
	// replace the transient plaintext with the encrypted representation.
	user.Password = ""
	if err := s.db.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := database.SetUserPassword(s.db, &user, plaintextPassword); err != nil {
		s.db.Delete(&user)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户凭据加密失败"})
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
	passwordChanged := false
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
		updates["hash"] = newHash
		user.Hash = newHash // 用于后续同步
		passwordChanged = true
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
	if err := s.db.Model(&user).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
		return
	}
	if passwordChanged {
		if err := database.SetUserPassword(s.db, &user, req.Password); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "用户凭据加密失败"})
			return
		}
	}

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
	password, err := database.UserPassword(user)
	if err != nil || password == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户凭据不可用"})
		return
	}
	remark := url.QueryEscape(fmt.Sprintf("%s:%d", domain, 443))
	link := fmt.Sprintf("trojan://%s@%s:%d#%s", password, domain, 443, remark)
	if s.wsEnabled {
		link = fmt.Sprintf("trojan://%s@%s:%d?type=ws&path=%s&host=%s#%s", password, domain, 443, url.QueryEscape(s.wsPath), domain, remark)
	}
	effSubPath := "/sub"
	if s.subPath != "" {
		effSubPath = s.subPath
	}
	subLink := fmt.Sprintf("https://%s%s?token=%s", domain, effSubPath, user.Hash)
	c.JSON(http.StatusOK, gin.H{"link": link, "sub_link": subLink, "username": user.Username})
}
