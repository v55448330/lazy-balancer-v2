package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
)

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
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "节点上报格式错误", err)
		return
	}
	if err := h.clusterService.ReportNode(c.Request.Context(), c.GetInt("cluster_node_id"), req, time.Now()); err != nil {
		clusterError(c, http.StatusInternalServerError, "节点状态上报失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点状态已更新"})
}
