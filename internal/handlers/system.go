package handlers

import (
	"net/http"

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
