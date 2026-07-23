package webserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/host"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
	psnet "github.com/shirou/gopsutil/v3/net"
	"github.com/voidluo/trojan-go/common"
	"github.com/voidluo/trojan-go/internal/database"
	"github.com/voidluo/trojan-go/log"
)

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
			legacyPassword := u.Password
			u.ID = 0
			u.Password = ""
			if err := s.db.Create(&u).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复用户失败"})
				return
			}
			if legacyPassword != "" {
				if err := database.SetUserPassword(s.db, &u, legacyPassword); err != nil {
					s.db.Delete(&u)
					c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复用户凭据加密失败"})
					return
				}
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
