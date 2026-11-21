package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
)

// clusterNodeStatsRetentionDays 节点统计保留天数（主节点本地表，日报只读当日）。
const clusterNodeStatsRetentionDays = 30

// HandleClusterNodeStatsReport 机器接口：从节点日报统计上报（2026-11-22
// 主节点集中汇聚）。节点名以认证中间件注入的 nodes.name 为准（防伪造），
// (date,node) 主键 upsert——同日重报覆盖（槽点重试被批准自愈）。
func (h *Handlers) HandleClusterNodeStatsReport(c *gin.Context) {
	var stats notify.ClusterNodeStats
	if err := c.ShouldBindJSON(&stats); err != nil {
		// 直写豁免：集群机器接口，消费方为从节点重试逻辑（无用户语言面）。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "统计载荷无效"})
		return
	}
	if _, err := time.Parse("2006-01-02", stats.Date); err != nil {
		// 直写豁免：集群机器接口（同上）。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "统计日期格式无效（YYYY-MM-DD）"})
		return
	}
	nodeName := ""
	if v, ok := c.Get("cluster_node_id"); ok {
		if nodeID, ok := v.(int); ok {
			_ = db.DB.QueryRow(`SELECT COALESCE(name,'') FROM nodes WHERE id=?`, nodeID).Scan(&nodeName)
		}
	}
	if nodeName == "" {
		// 直写豁免：集群机器接口（同上）。
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "上报者节点未登记"})
		return
	}
	raw, err := json.Marshal(stats)
	if err != nil {
		// 直写豁免：集群机器接口（同上）。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计序列化失败"})
		return
	}
	if _, err := db.DB.Exec(`INSERT INTO cluster_node_daily_stats (date,node,stats_json,updated_at) VALUES (?,?,?,datetime('now'))
		ON CONFLICT(date,node) DO UPDATE SET stats_json=excluded.stats_json, updated_at=excluded.updated_at`,
		stats.Date, nodeName, string(raw)); err != nil {
		// 直写豁免：集群机器接口（同上）。
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "统计落库失败"})
		return
	}
	// 保留窗口裁剪（每次上报顺带清理，幂等）
	_, _ = db.DB.Exec(`DELETE FROM cluster_node_daily_stats WHERE date < date('now',?)`,
		"-"+strconv.Itoa(clusterNodeStatsRetentionDays)+" days")
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"node": nodeName, "date": stats.Date}})
}
