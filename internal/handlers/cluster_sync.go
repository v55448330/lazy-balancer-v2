package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) GetClusterSnapshot(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	sinceVersion, _ := strconv.Atoi(c.Query("since_version"))
	snapshot, changed, err := h.clusterService.Snapshot(c.Request.Context(), sinceVersion, c.Query("fingerprint"))
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "生成集群快照失败", err)
		return
	}
	if !changed {
		c.Status(http.StatusNotModified)
		return
	}
	if nodeIDValue, exists := c.Get("cluster_node_id"); exists {
		if nodeID, ok := nodeIDValue.(int); ok {
			var nodeName string
			_ = db.DB.QueryRow("SELECT COALESCE(name,'') FROM nodes WHERE id=?", nodeID).Scan(&nodeName)
			services.RecordAuditLog("system", "同步下发", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %s", nodeName), fmt.Sprintf("下发版本：%d", snapshot.Version)), c.ClientIP())
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "快照生成成功", Data: snapshot})
}

func (h *Handlers) PullClusterSnapshot(c *gin.Context) {
	result, err := h.syncService.Pull(c.Request.Context())
	if err != nil {
		recordAudit(c, "手动同步失败", "集群同步", err.Error())
		clusterError(c, http.StatusInternalServerError, "手动同步失败: "+err.Error(), err)
		return
	}
	if result.Changed {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("应用版本："+strconv.Itoa(result.AppliedVersion), services.AuditResultPart("success")))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "手动同步完成", Data: result})
}
