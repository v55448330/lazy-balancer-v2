package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// clusterReportMaxBytes 限制节点上报请求体大小（Round 34 F-R34-4）。异常从节点可能
// 携带 MB 级 last_sync_error/health_json，防止其写入主节点 nodes 表。
const clusterReportMaxBytes = 64 << 10

func (h *Handlers) GetClusterStatus(c *gin.Context) {
	status, err := h.clusterService.Status(c.Request.Context())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "读取集群状态失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "查询成功", Data: status})
}

func (h *Handlers) ListClusterNodes(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	nodes, err := h.clusterService.Nodes(c.Request.Context(), time.Now())
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "读取集群节点失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "查询成功", Data: nodes})
}

func (h *Handlers) ReportClusterNode(c *gin.Context) {
	var req models.ClusterReport
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterReportMaxBytes)
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "节点上报格式错误", err)
		return
	}
	nodeID := c.GetInt("cluster_node_id")
	if req.Detached {
		if err := h.clusterService.DeleteNode(c.Request.Context(), nodeID); err != nil {
			clusterError(c, http.StatusInternalServerError, "节点脱离处理失败", err)
			return
		}
		services.RecordAuditLog("system", "脱离", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), services.AuditResultPart("success")), c.ClientIP())
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点已脱离集群"})
		return
	}
	if err := h.clusterService.ReportNode(c.Request.Context(), nodeID, req, time.Now()); err != nil {
		clusterError(c, http.StatusInternalServerError, "节点状态上报失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点状态已更新"})
}
