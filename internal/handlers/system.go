package handlers

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// RestartService exits the process after responding; the container's
// restart policy brings the service back up (used to apply process-level
// settings such as the Caddy log timezone).
func (h *Handlers) RestartService(c *gin.Context) {
	recordAudit(c, "重启", "系统", "用户触发服务重启")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "服务正在重启"})
	go func() {
		time.Sleep(500 * time.Millisecond)
		os.Exit(0)
	}()
}

func (h *Handlers) GetSystemInfo(c *gin.Context) {
	info := models.SystemInfo{
		NodeMode:      "master",
		IPAddress:     getOutboundIP(),
		Hostname:      getHostname(),
		OSInfo:        getOSInfo(),
		Kernel:        getKernel(),
		Architecture:  getArchitecture(),
		NetworkIPs:    getNetworkIPs(),
		CaddyVersion:  getCaddyVersion(),
		RunningStatus: "running",
		Uptime:        getUptime(),
		Version:       h.cfg.Version,
	}
	var isMaster bool
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err == nil && !isMaster {
		info.NodeMode = "slave"
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: info})
}

func (h *Handlers) GetSystemMetrics(c *gin.Context) {
	metrics, err := getSystemMetrics()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: metrics})
}

func (h *Handlers) GetRealtimeTraffic(c *gin.Context) {
	traffic, err := getRealtimeTraffic()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: traffic})
}

func (h *Handlers) GetConnectionStats(c *gin.Context) {
	stats, err := getConnectionStats()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: stats})
}

func (h *Handlers) GetAppLogs(c *gin.Context) {
	logPath := h.cfg.LogFile
	const maxBytes = 128 * 1024
	const maxLines = 500

	info, err := os.Stat(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": ""}})
			return
		}
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "日志文件不可读: " + err.Error()})
		return
	}
	startOffset := int64(0)
	if info.Size() > maxBytes {
		startOffset = info.Size() - maxBytes
	}
	f, err := os.Open(logPath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "打开日志文件失败: " + err.Error()})
		return
	}
	defer f.Close()
	if _, err := f.Seek(startOffset, io.SeekStart); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志失败: " + err.Error()})
		return
	}
	data, err := io.ReadAll(f)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取日志失败: " + err.Error()})
		return
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) > maxLines {
		lines = lines[len(lines)-maxLines:]
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: map[string]string{"content": strings.Join(lines, "\n")}})
}
