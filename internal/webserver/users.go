package webserver

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
	"gorm.io/gorm"
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
	if user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名和密码不能为空"})
		return
	}
	// L-02: usernames end up in subscription filenames and share links, so
	// enforce length, UTF-8 validity and character restrictions on create.
	if err := validateUsername(user.Username); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateQuota(user.Quota); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if user.Status < 0 || user.Status > 1 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "状态必须为 0（启用）或 1（禁用）"})
		return
	}
	if user.IPLimit < 0 || user.IPLimit > 100 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IP 限制必须在 0 到 100 之间"})
		return
	}
	plaintextPassword := user.Password
	user.Hash = common.SHA224String(plaintextPassword)
	var existing database.User
	// S-09 (L-01): the `err == nil` form treated a query failure as "no
	// conflict" and continued to Create, so a database outage surfaced as an
	// opaque 500 from the unique index instead of a clear error. Align with the
	// three-branch pattern used everywhere else in the project.
	switch err := s.db.Where("hash = ?", user.Hash).First(&existing).Error; {
	case err == nil:
		c.JSON(http.StatusConflict, gin.H{"error": fmt.Sprintf("此密码已被用户 [%s] 使用", existing.Username)})
		return
	case errors.Is(err, gorm.ErrRecordNotFound):
		// no conflict, continue
	default:
		log.Errorf("create user: password uniqueness precheck: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
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
		// L-01: report a failed compensating delete; otherwise a user row can
		// survive without a usable password ciphertext.
		if delErr := s.db.Delete(&user).Error; delErr != nil {
			log.Errorf("create user: rollback of user %d failed after credential encryption error, an unusable user row may remain: %v", user.ID, delErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户凭据加密失败"})
		return
	}
	if user.Status == 0 {
		s.syncAuthAddUser("create user", user.Hash)
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
		// L-02: the update path used to accept any non-empty username.
		if err := validateUsername(req.Username); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["username"] = req.Username
	}
	if req.Status != nil {
		if *req.Status < 0 || *req.Status > 1 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "状态必须为 0（启用）或 1（禁用）"})
			return
		}
		updates["status"] = *req.Status
	}
	if req.Quota != nil {
		if err := validateQuota(*req.Quota); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		updates["quota"] = *req.Quota
	}
	if req.IPLimit != nil {
		if *req.IPLimit < 0 || *req.IPLimit > 100 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "IP 限制必须在 0 到 100 之间"})
			return
		}
		updates["ip_limit"] = *req.IPLimit
	}
	if req.Password != "" {
		newHash := common.SHA224String(req.Password)
		var existing database.User
		// S-09 (L-01): same fix as the create path — a failed lookup must not
		// be mistaken for "this password is free".
		switch err := s.db.Where("hash = ? AND id != ?", newHash, id).First(&existing).Error; {
		case err == nil:
			c.JSON(http.StatusConflict, gin.H{"error": "此密码已被其他用户使用"})
			return
		case errors.Is(err, gorm.ErrRecordNotFound):
			// no conflict, continue
		default:
			log.Errorf("update user %s: password uniqueness precheck: %v", id, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
			return
		}
		updates["hash"] = newHash
		user.Hash = newHash // 用于后续同步
		passwordChanged = true
	}
	if req.ExpiryDays != nil {
		if *req.ExpiryDays < 0 || *req.ExpiryDays > 3650 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "有效天数必须在 0 到 3650 之间"})
			return
		}
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
	// Wrap field updates and credential encryption in a single transaction.
	// If credential encryption fails the field changes are rolled back,
	// preventing a mismatch between the new hash and the password ciphertext.
	tx := s.db.Begin()
	if tx.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "开启数据库事务失败"})
		return
	}
	if err := tx.Model(&user).Updates(updates).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
		return
	}
	if passwordChanged {
		if err := database.SetUserPassword(tx, &user, req.Password); err != nil {
			tx.Rollback()
			c.JSON(http.StatusInternalServerError, gin.H{"error": "用户凭据加密失败"})
			return
		}
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "提交用户更新事务失败"})
		return
	}

	// 同步所有存在的核心
	if len(s.auths) > 0 {
		s.syncAuthDelUser("update user", oldHash)
		if err := s.db.First(&user, id).Error; err != nil {
			log.Warnf("refresh user %d after update: %v", id, err)
		} else if user.Status == 0 {
			s.syncAuthAddUser("update user", user.Hash)
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
	if err := s.db.First(&user, c.Param("id")).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	s.syncAuthDelUser("delete user", user.Hash)
	if err := s.db.Delete(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除用户失败"})
		return
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
	// L-02: this standalone endpoint used to skip the -1 boundary that the
	// user update path enforces, so it could store values like -5.
	if err := validateQuota(req.Quota); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	result := s.db.Model(&database.User{}).Where("id = ?", id).Update("quota", req.Quota)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置限额失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "限额设置成功"})
}

func (s *AdminServer) handleClearTraffic(c *gin.Context) {
	if s.isNode {
		s.proxyToMaster(c)
		return
	}
	result := s.db.Model(&database.User{}).Where("id = ?", c.Param("id")).Updates(map[string]interface{}{
		"used": 0, "upload": 0, "download": 0,
	})
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "清空流量失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
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
	if req.Days < 0 || req.Days > 3650 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "有效天数必须在 0 到 3650 之间"})
		return
	}
	expiry := time.Now().AddDate(0, 0, req.Days)
	result := s.db.Model(&database.User{}).Where("id = ?", id).Update("expiry_time", &expiry)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "设置过期时间失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "过期时间设置成功", "expiry": expiry})
}

func (s *AdminServer) handleCancelExpire(c *gin.Context) {
	result := s.db.Model(&database.User{}).Where("id = ?", c.Param("id")).Update("expiry_time", nil)
	if result.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取消限期失败"})
		return
	}
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "服务域名为空；请在面板设置中配置 canonical domain"})
		return
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
