package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

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
	snapshot, changed, err := h.clusterService.Snapshot(c.Request.Context(), sinceVersion, c.Query("fingerprint"), authenticatedClusterToken(c))
	if err != nil {
		clusterError(c, http.StatusInternalServerError, "生成集群快照失败", err)
		return
	}
	if !changed {
		// 304「配置无变化」只在从节点侧留痕；主节点每个同步周期都会被
		// 轮询命中，记录只会制造噪音，无需在此审计。
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

func authenticatedClusterToken(c *gin.Context) string {
	if token := c.GetString("cluster_token"); token != "" {
		return token
	}
	if token := c.GetHeader("X-Cluster-Token"); token != "" {
		return token
	}
	return strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
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
	} else {
		recordAudit(c, "手动同步", "集群同步", services.FormatAuditDetail("配置无变化", services.AuditResultPart("success")))
	}
	h.syncService.Resume()
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "手动同步完成", Data: result})
}

// GetClusterWafFiles serves the full CRS/IP2Region file bundle on demand to
// slaves whose snapshot-carried hash reference differs from their local files.
func (h *Handlers) GetClusterWafFiles(c *gin.Context) {
	bundle := services.BuildWafFileBundle()
	if bundle == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "主节点无 WAF 规则文件"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: bundle})
}
