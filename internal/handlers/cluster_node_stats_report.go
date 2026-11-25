package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// HandleClusterNodeStatsReport 机器接口：从节点日报统计上报（2026-11-22
// 主节点集中汇聚）。节点身份以认证中间件注入的 nodes.id 为准（防伪造）；
// 归属键=「从节点 name(ip:port)」（与事件侧 SlaveNodeLabel 同形）——
// 裸 nodes.name 无 UNIQUE，同名节点会互相覆盖。同日重报 upsert 覆盖
// （槽点重试被批准自愈）。
func (h *Handlers) HandleClusterNodeStatsReport(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterReportBodyLimitBytes)
	var stats notify.ClusterNodeStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "cluster.statsPayloadInvalid"))
		return
	}
	date, err := time.Parse("2006-01-02", stats.Date)
	if err != nil {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "cluster.statsDateFormatInvalid"))
		return
	}
	// 降级主节点残留 nodes 行时旧从节点照常上报会让统计错挂主节点簿记；
	// 与同族机器端点（节点上报）同一 requireMaster 门。
	if !h.requireMaster(c) {
		return
	}
	// 统计窗口 [今日-2, 今日]（配置时区）：槽点上报昨日块，留两日迟到重试
	// 余量；未来日期与更早日期直接 400——否则未来行永不被保留窗口清理
	//（只删旧行），成为永久脏数据。
	if !clusterNodeStatsDateInWindow(date) {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(c, 400, "cluster.statsDateOutOfWindow"))
		return
	}
	nodeID := c.GetInt("cluster_node_id")
	nodeName, _, err := h.clusterService.RecordNodeDailyStats(c.Request.Context(), nodeID, stats)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// 直写豁免：集群机器接口（同上）。
			c.JSON(http.StatusForbidden, apimsg.Envelope(c, 403, "cluster.reporterNodeNotRegistered"))
		case errors.Is(err, services.ErrNotMasterNode):
			clusterMasterForbidden(c, err)
		default:
			c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.statsSaveFailed", err))
		}
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"node": nodeName, "date": stats.Date}})
}

// clusterReportBodyLimitBytes 两上报端点的请求体上限。
const clusterReportBodyLimitBytes int64 = 128 << 10

// clusterNodeStatsDateInWindow 校验上报日期落在 [今日-2, 今日]（配置时区）。
func clusterNodeStatsDateInWindow(date time.Time) bool {
	loc := services.CurrentLocation()
	if loc == nil {
		loc = time.Local
	}
	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	day := time.Date(date.Year(), date.Month(), date.Day(), 0, 0, 0, 0, loc)
	return !day.Before(today.AddDate(0, 0, -2)) && !day.After(today)
}
