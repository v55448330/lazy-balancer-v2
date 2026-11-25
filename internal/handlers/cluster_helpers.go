package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type masterGateOptions struct {
	queryFailure string
	forbidden    string
	// queryFailureKey / forbiddenKey 是对应文案的语义键（internal/i18n 集群目录）。
	// 空表示该中文尚无登记词条（如自动备份/通知的专用提示），按字面量直出。
	queryFailureKey string
	forbiddenKey    string
}

const masterRequiredErrorCode = "master_required"

// requireMasterResult 统一三种入口的角色门结果：查询错误恒 500，确认从节点
// 恒 403，主节点放行。角色读取仍复用 services.RoleOf（ClusterService.IsMaster
// 是其薄包装）；端点仅保留自己的文案，机器错误码恒为 master_required。
func requireMasterResult(c *gin.Context, isMaster bool, err error, options masterGateOptions) bool {
	if err != nil {
		emitClusterError(c, http.StatusInternalServerError, options.queryFailure, options.queryFailureKey, err)
		return false
	}
	if !isMaster {
		c.Header("X-LB-Error-Code", masterRequiredErrorCode)
		emitClusterError(c, http.StatusForbidden, options.forbidden, options.forbiddenKey, nil)
		return false
	}
	return true
}

// requireClusterService 是装配缺失的单点守卫：未注入 ClusterService 时统一
// 503「集群服务未初始化」，避免 nil 解引用走 Gin recovery 变成空体 500
// （无法区分未装配与真实内部故障）。requireMaster 与不经角色门的端点
// （角色变更面/机器面/只读状态）共用本函数。
func (h *Handlers) requireClusterService(c *gin.Context) bool {
	if h.clusterService == nil {
		c.JSON(http.StatusServiceUnavailable, clusterErrorKeyedResponse(http.StatusServiceUnavailable, "cluster.serviceNotInitialized", nil))
		return false
	}
	return true
}

func (h *Handlers) requireMaster(c *gin.Context) bool {
	if !h.requireClusterService(c) {
		return false
	}
	isMaster, err := h.clusterService.IsMaster(c.Request.Context())
	return requireMasterResult(c, isMaster, err, masterGateOptions{
		queryFailure:    "读取节点模式失败",
		queryFailureKey: "cluster.nodeModeReadFailed",
		forbidden:       "该操作仅允许在主节点执行",
		forbiddenKey:    "cluster.masterOnlyOperation",
	})
}

func clusterError(c *gin.Context, status int, message string, err error) {
	if err != nil {
		services.Logf("error", "cluster request failed: %v", err)
	}
	c.JSON(status, models.APIResponse{Code: status, Message: message})
}

// emitClusterError 是集群错误面唯一出口：有语义键走键化装配器，无键（尚无
// 登记词条的专用中文）按字面量直出。两者日志口径同为
// "cluster request failed: <err>"。
func emitClusterError(c *gin.Context, status int, message, key string, err error) {
	if key != "" {
		c.JSON(status, clusterErrorKeyedResponse(status, key, err))
		return
	}
	clusterError(c, status, message, err)
}

// clusterMasterForbidden 统一服务层 ErrNotMasterNode → 403 的输出形状
// 与 requireMasterResult 同源携带 X-LB-Error-Code——从端
// Pull 的错误分类（cluster_sync.go）依赖该头，服务层降级竞态 403 不得裸发。
func clusterMasterForbidden(c *gin.Context, err error) {
	c.Header("X-LB-Error-Code", masterRequiredErrorCode)
	c.JSON(http.StatusForbidden, clusterErrorKeyedResponse(http.StatusForbidden, "cluster.masterOnlyOperation", err))
}
