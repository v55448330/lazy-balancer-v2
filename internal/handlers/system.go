package handlers

import (
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) GetSystemInfo(c *gin.Context) {
	info := models.SystemInfo{
		IPAddress:     getOutboundIP(),
		Hostname:      getHostname(),
		OSInfo:        getOSInfo(),
		Kernel:        getKernel(),
		Architecture:  getArchitecture(),
		NetworkIPs:    getNetworkIPs(),
		CaddyVersion:  getCaddyVersion(),
		RunningStatus: "running",
		Uptime:        getUptime(),
		NodeMode:      h.cfg.NodeMode,
		Version:       h.cfg.Version,
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
	const logPath = "/app/logs/lazy-balancer.log"
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
