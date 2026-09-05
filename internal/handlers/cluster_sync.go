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
	// 主节点无同步对象：入口直接拒绝，不调 Pull——否则「主节点不能从其他
	// 节点同步」会经 recordSyncError 写入 last_sync_error 且无自动清除路径，
	// 节点页面持续显示假错误（R41 S-1）。前端按钮只对从节点渲染，此为后端防御。
	var isMaster bool
	// 门控查询失败时按主节点语义拒绝（R42 发现2）：放行会让主节点走 Pull
	// 命中 errSyncMasterNoPull 返回 500 + 误导审计「同步失败」，实际
	// 只是瞬时 DB 读错。400 文案与真主节点一致，前端无歧义。
	if err := db.DB.QueryRow("SELECT COALESCE(is_master,1) FROM global_config WHERE id=1").Scan(&isMaster); err != nil || isMaster {
		clusterError(c, http.StatusBadRequest, "主节点无需手动同步", err)
		return
	}
	result, err := h.syncService.Pull(c.Request.Context())
	if err != nil {
		recordAudit(c, "同步失败", "集群同步", err.Error())
		clusterError(c, http.StatusInternalServerError, "同步失败: "+err.Error(), err)
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

// ForgetClusterPins 是从节点管理员的 PinMismatch 补救端点（M13②）：主节点更换
// 管理面板证书后从节点同步持续指纹不匹配，运维确认新证书合法后清空全部 TOFU
// 指纹钉（内存缓存+磁盘 pin 文件），下一同步 tick 按新证书重新钉扎。仅 admin
// 路由组可达（readOnlyGuard 的 /cluster/* 白名单保证从节点可用），操作留审计。
func (h *Handlers) ForgetClusterPins(c *gin.Context) {
	removed, err := h.syncService.ForgetPins()
	if err != nil {
		recordAudit(c, "清除失败", "证书指纹", services.FormatAuditDetail(err.Error(), services.AuditResultPart("failure")))
		clusterError(c, http.StatusInternalServerError, "清除主节点证书指纹失败: "+err.Error(), err)
		return
	}
	recordAudit(c, "清除", "证书指纹", services.FormatAuditDetail(
		fmt.Sprintf("已清除 %d 个主节点证书指纹，下次同步将重新验证并钉扎", removed),
		services.AuditResultPart("success"),
	))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "已清除全部主节点证书指纹，下次同步将按当前证书重新钉扎"})
}

// GetClusterWafFiles serves the full CRS/IP2Region file bundle on demand to
// slaves whose snapshot-carried hash reference differs from their local files.
func (h *Handlers) GetClusterWafFiles(c *gin.Context) {
	if !h.requireMaster(c) {
		return
	}
	bundle := services.BuildWafFileBundle()
	if bundle == nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "主节点无安全数据"})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: bundle})
}
