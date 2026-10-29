package handlers

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// clusterReportMaxBytes 限制节点上报请求体大小。异常从节点可能
// 携带 MB 级 last_sync_error/health_json，防止其写入主节点 nodes 表。
const clusterReportMaxBytes = 64 << 10

func (h *Handlers) GetClusterStatus(c *gin.Context) {
	if !h.requireClusterService(c) {
		return
	}
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
	// 导入窗口 fast-fail——上报写 nodes 瞬态列与分区上报缓存，
	// 导入全量替换 nodes 时窗口写入会被覆盖或阻塞至 busy_timeout。
	if rejectNodeWriteDuringImport(c) {
		return
	}
	var req models.ClusterReport
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterReportMaxBytes)
	if err := c.ShouldBindJSON(&req); err != nil {
		clusterError(c, http.StatusBadRequest, "节点上报格式错误", err)
		return
	}
	nodeID := c.GetInt("cluster_node_id")
	recordDetached := func(result string) {
		services.RecordAuditLog("system", "脱离", "集群节点", services.FormatAuditDetail(fmt.Sprintf("节点 %d", nodeID), services.AuditResultPart(result)), c.ClientIP())
	}
	// 与快照端点对称加 requireMaster——降级主节点残留 nodes 行时,
	// 旧从节点上报照常写入(无审批),再提升后旧令牌静默重组集群。
	// detached 需先解码再进门，才能给主节点门的拒绝留下同资源失败审计。
	if !h.requireMaster(c) {
		if req.Detached {
			result := "failed"
			if c.Writer.Status() == http.StatusForbidden {
				result = "blocked"
			}
			recordDetached(result)
		}
		return
	}
	if req.Detached {
		if err := h.clusterService.DeleteNode(c.Request.Context(), nodeID); err != nil {
			if errors.Is(err, services.ErrNotMasterNode) {
				recordDetached("blocked")
				clusterMasterForbidden(c, err)
				return
			}
			if errors.Is(err, services.ErrNodeNotFound) {
				// 从端重试脱离通知（DELETE 成功但响应丢失）时节点已不存在：
				// 按幂等成功应答，从端据 200 停止重试；500 会让从端按
				// 「服务端故障」持续重试并写入 last_sync_error。
				c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点已不在集群"})
				return
			}
			recordDetached("failed")
			clusterError(c, http.StatusInternalServerError, "节点脱离处理失败", err)
			return
		}
		recordDetached("success")
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点已脱离集群"})
		return
	}
	if err := h.clusterService.ReportNode(c.Request.Context(), nodeID, req, time.Now()); err != nil {
		if errors.Is(err, services.ErrNotMasterNode) {
			clusterMasterForbidden(c, err)
			return
		}
		if errors.Is(err, services.ErrNodeNotFound) {
			// 节点已被主节点删除：身份不存在的 404 语义（同族端点一致）。
			// 注意：404 本身不终止从端上报循环——从端上报客户端对任何 ≥400
			// 都只当作一次可重试失败（cluster_report.go），真正让循环停下的是
			// 下一轮 Pull 的 401（令牌已撤销）。404 的收益是排障语义准确
			// （「身份不存在」而非「服务端故障」），不是停止重试。
			clusterError(c, http.StatusNotFound, "节点状态上报失败：节点已不在集群", err)
			return
		}
		clusterError(c, http.StatusInternalServerError, "节点状态上报失败", err)
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "节点状态已更新"})
}
