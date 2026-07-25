package webserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"reflect"
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
	"gorm.io/gorm"
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
	// F-3: the restore loop used to commit each user independently, so an error
	// in the middle of a large backup left an arbitrary prefix of users
	// restored with no way for the operator to tell which ones. The whole
	// restore now runs in one transaction: either every new user lands or none
	// does. Authenticator sync is deferred until after a successful commit so
	// we never advertise users that were rolled back.
	var restoredHashes []string
	count := 0
	if err := s.db.Transaction(func(tx *gorm.DB) error {
		restoredHashes = restoredHashes[:0]
		count = 0
		for _, u := range users {
			if u.Hash == "" && u.Password != "" {
				u.Hash = common.SHA224String(u.Password)
			}
			if u.Hash == "" {
				continue
			}
			var exist database.User
			switch err := tx.Where("hash = ?", u.Hash).First(&exist).Error; {
			case err == nil:
				// already present, nothing to restore for this entry
				continue
			case errors.Is(err, gorm.ErrRecordNotFound):
				// fall through and create it
			default:
				return fmt.Errorf("lookup existing user: %w", err)
			}
			legacyPassword := u.Password
			u.ID = 0
			u.Password = ""
			if err := tx.Create(&u).Error; err != nil {
				return fmt.Errorf("create user: %w", err)
			}
			if legacyPassword != "" {
				if err := database.SetUserPassword(tx, &u, legacyPassword); err != nil {
					return fmt.Errorf("encrypt credentials: %w", err)
				}
			}
			if u.Status == 0 {
				restoredHashes = append(restoredHashes, u.Hash)
			}
			count++
		}
		return nil
	}); err != nil {
		log.Errorf("restore users: transaction rolled back, no users were restored: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "恢复用户失败，已回滚"})
		return
	}
	for _, hash := range restoredHashes {
		s.syncAuthAddUser("restore users", hash)
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("恢复成功: %d 个用户", count)})
}

func (s *AdminServer) handleGetStatus(c *gin.Context) {
	var count int64
	// L-01: a failed count used to be reported as user_count: 0, which reads
	// like a healthy but empty deployment. Surface the error instead.
	if err := s.db.Model(&database.User{}).Count(&count).Error; err != nil {
		log.Errorf("status endpoint: count users: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "读取用户统计失败"})
		return
	}
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

// hysteriaUnitPath is the systemd unit file the installer writes when
// Hysteria2 is enabled. It is a var so tests can point it at a temp file.
var hysteriaUnitPath = "/etc/systemd/system/hysteria.service"

// hysteriaUnitInstalled reports whether the optional hysteria unit exists.
// The unit is only present when the deployment enabled Hysteria2, so it is
// detected at call time instead of being hard-coded into the role list.
func hysteriaUnitInstalled() bool {
	_, err := os.Stat(hysteriaUnitPath)
	return err == nil
}

// serviceUnits returns the systemd unit names for the current role.
// Master hosts admin + control + gateway + data-plane; Worker omits admin-service.
//
// M-05: hysteria is included when its unit is installed. It used to be absent
// from this list, so the panel could neither show its status, read its logs, nor
// restart it, even though the installer manages it as a first-class unit.
func (s *AdminServer) serviceUnits() []string {
	var units []string
	if s.isNode {
		units = []string{"trojan-data-plane", "control-service", "gateway-service"}
	} else {
		units = []string{"trojan-data-plane", "admin-service", "control-service", "gateway-service"}
	}
	if hysteriaUnitInstalled() {
		units = append(units, "hysteria")
	}
	return units
}

// isAllowedUnit checks whether the given unit (with or without the ".service"
// suffix) is in the role's allowed list.
func (s *AdminServer) isAllowedUnit(unit string) bool {
	normalized := strings.TrimSuffix(unit, ".service")
	for _, u := range s.serviceUnits() {
		if u == normalized {
			return true
		}
	}
	return false
}

// serviceUnitDescription maps a unit basename to a human-readable label.
func serviceUnitDescription(unit string) string {
	switch unit {
	case "trojan-data-plane":
		return "Trojan 数据面"
	case "admin-service":
		return "管理服务"
	case "control-service":
		return "控制服务"
	case "gateway-service":
		return "公网网关"
	case "hysteria":
		return "Hysteria2 服务"
	default:
		return unit
	}
}

// hasSystemctl detects whether systemctl is available on the host.
func hasSystemctl() bool {
	_, err := exec.LookPath("systemctl")
	return err == nil
}

// getUnitLogs fetches logs for a single service unit via journalctl.
func getUnitLogs(unit, lines, level string) ([]byte, error) {
	if _, err := exec.LookPath("journalctl"); err != nil {
		return nil, fmt.Errorf("日志服务不可用（journalctl 未找到），请直接查看进程输出")
	}
	args := []string{"-u", unit, "-n", lines, "--no-pager", "-o", "cat"}
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

// unitActionTimeout bounds a single systemctl invocation so a hung unit cannot
// block an admin request indefinitely.
const unitActionTimeout = 30 * time.Second

// unitControlOverridden reports whether controlUnit has been replaced (only
// tests do this). It keeps the in-process shutdown fallback from firing when a
// test drives the systemctl path on a non-systemd host.
func unitControlOverridden() bool {
	return reflect.ValueOf(controlUnit).Pointer() != reflect.ValueOf(runSystemctlUnitAction).Pointer()
}

// controlUnit runs a systemctl action against a single service unit. It is a
// var so tests can inject deterministic outcomes without a systemd host.
var controlUnit = runSystemctlUnitAction

// runSystemctlUnitAction is the production implementation of controlUnit.
//
// M-05: start now waits for systemctl to finish like stop and restart do.
// Previously it used cmd.Start() and returned immediately, so the API reported
// success even when the unit failed to come up.
func runSystemctlUnitAction(unit, action string) ([]byte, error) {
	if !hasSystemctl() {
		return nil, fmt.Errorf("systemctl 不可用（非 systemd 环境），请手动操作服务")
	}
	ctx, cancel := context.WithTimeout(context.Background(), unitActionTimeout)
	defer cancel()
	if action == "is-active" {
		return exec.CommandContext(ctx, "systemctl", "is-active", unit).Output()
	}
	out, err := exec.CommandContext(ctx, "systemctl", action, unit).CombinedOutput()
	if ctx.Err() != nil {
		return out, fmt.Errorf("systemctl %s %s 超时（%s）", action, unit, unitActionTimeout)
	}
	return out, err
}

// restartAllUnits restarts every managed service unit in dependency order and
// returns an aggregated error describing every unit that failed.
//
// M-05: failures used to be logged one by one with no aggregate result, so a
// caller could not tell whether the fleet restart actually succeeded.
func (s *AdminServer) restartAllUnits() error {
	if !hasSystemctl() && !unitControlOverridden() {
		log.Warn("systemctl 不可用，执行进程内优雅退出（请由进程管理器自动重启）")
		common.SignalShutdown()
		return nil
	}
	units := s.serviceUnits()
	log.Infof("restarting service units: %v", units)

	var failures []error
	for _, unit := range units {
		out, err := controlUnit(unit, "restart")
		if err == nil {
			continue
		}
		detail := strings.TrimSpace(string(out))
		if detail != "" {
			err = fmt.Errorf("%s: %w (%s)", unit, err, detail)
		} else {
			err = fmt.Errorf("%s: %w", unit, err)
		}
		log.Errorf("restart failed: %v", err)
		failures = append(failures, err)
	}
	if len(failures) > 0 {
		return fmt.Errorf("重启 %d/%d 个服务单元失败: %w",
			len(failures), len(units), errors.Join(failures...))
	}
	return nil
}

func (s *AdminServer) handleGetLogs(c *gin.Context) {
	lines := c.DefaultQuery("lines", "300")
	level := c.Query("level")
	unit := c.Query("unit")

	if unit != "" {
		if !s.isAllowedUnit(unit) {
			c.String(http.StatusBadRequest, "不支持读取该服务单元的日志")
			return
		}
		out, err := getUnitLogs(unit, lines, level)
		if err != nil {
			c.String(http.StatusInternalServerError, "获取日志失败: "+err.Error()+"\n"+string(out))
			return
		}
		c.String(http.StatusOK, string(out))
		return
	}

	// Aggregate logs from all managed units.
	var buf strings.Builder
	for _, u := range s.serviceUnits() {
		fmt.Fprintf(&buf, "=== %s (%s) ===\n", u, serviceUnitDescription(u))
		out, err := getUnitLogs(u, lines, level)
		if err != nil {
			fmt.Fprintf(&buf, "错误: %v\n%s\n\n", err, string(out))
			continue
		}
		buf.Write(out)
		buf.WriteString("\n\n")
	}
	c.String(http.StatusOK, buf.String())
}

func (s *AdminServer) handleServiceControl(c *gin.Context) {
	var req struct {
		Action  string `json:"action"`
		Service string `json:"service"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效请求"})
		return
	}
	// "list" returns all units with their systemd status.
	if req.Action == "list" {
		type unitInfo struct {
			Unit        string `json:"unit"`
			Description string `json:"description"`
			Status      string `json:"status"`
		}
		units := s.serviceUnits()
		infos := make([]unitInfo, len(units))
		for i, u := range units {
			out, err := controlUnit(u, "is-active")
			status := strings.TrimSpace(string(out))
			if err != nil || status == "" {
				status = "unknown"
			}
			infos[i] = unitInfo{Unit: u, Description: serviceUnitDescription(u), Status: status}
		}
		c.JSON(http.StatusOK, infos)
		return
	}
	validActions := map[string]bool{"start": true, "stop": true, "restart": true, "status": true}
	if !validActions[req.Action] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "不支持该操作"})
		return
	}
	unit := req.Service
	if unit == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "缺少服务单元名称"})
		return
	}
	if !s.isAllowedUnit(unit) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("未识别的服务 %q", unit)})
		return
	}

	if req.Action == "status" {
		out, err := controlUnit(unit, "is-active")
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
	out, err := controlUnit(unit, req.Action)
	if err != nil {
		if !hasSystemctl() {
			if req.Action == "restart" || req.Action == "stop" {
				go func() {
					time.Sleep(200 * time.Millisecond)
					if restartErr := s.restartAllUnits(); restartErr != nil {
						log.Errorf("in-process restart fallback: %v", restartErr)
					}
				}()
				c.JSON(http.StatusOK, gin.H{"message": "systemctl 不可用，正在尝试执行进程内优雅关闭/重启..."})
				return
			}
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// M-05: a systemctl failure is now reported instead of being masked by
		// an unconditional "已提交" success response.
		detail := strings.TrimSpace(string(out))
		log.Errorf("service control %s %s failed: %v (%s)", req.Action, unit, err, detail)
		message := fmt.Sprintf("%s %s 失败: %v", req.Action, unit, err)
		if detail != "" {
			message += "\n" + detail
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": message})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("已执行 %s %s", req.Action, unit)})
}

func (s *AdminServer) handleRestart(c *gin.Context) {
	// Restarting admin-service kills the process serving this request, so the
	// work stays asynchronous and the response is an acknowledgement. M-05: the
	// aggregated failure is now logged with the full unit list so operators can
	// see partial failures in the journal.
	units := s.serviceUnits()
	c.JSON(http.StatusOK, gin.H{
		"message": "正在重启所有服务单元...",
		"units":   units,
	})
	go func() {
		time.Sleep(200 * time.Millisecond)
		if err := s.restartAllUnits(); err != nil {
			log.Errorf("restart all units: %v", err)
		}
	}()
}
