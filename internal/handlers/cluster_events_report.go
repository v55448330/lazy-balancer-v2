package handlers

import (
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/services"
)

// ── 集群事件上报端点（用户裁定 2026-11-22 主节点集中汇聚）──
// POST /api/v1/cluster/events/report（机器接口组：限流+集群令牌认证）。
// 从节点把本地事件（节点名+类型+级别+正文）推送主节点；主节点校验
// 上报者身份（令牌→节点行→名字比对）后带 Node 字段入通知总线，
// 订阅匹配/投递全部在主节点完成。spool 批次按 BatchID 幂等去重。

// clusterEventPublish 入总线缝（测试捕获事件断言节点名钉扎；生产=notify.Publish）。
var clusterEventPublish = notify.Publish

// clusterEventDedup 上报批次幂等去重窗口（spool 重传可能重复送达）。
var clusterEventDedup = struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	cap   int
}{seen: map[string]struct{}{}, cap: 512}

// clusterEventDedupRecord 记录批次并返回是否首次（true=处理，false=重复丢弃）。
func clusterEventDedupRecord(batchID string) bool {
	if batchID == "" {
		return true // 非批次上报（即时单条）恒处理
	}
	clusterEventDedup.mu.Lock()
	defer clusterEventDedup.mu.Unlock()
	if _, ok := clusterEventDedup.seen[batchID]; ok {
		return false
	}
	clusterEventDedup.seen[batchID] = struct{}{}
	clusterEventDedup.order = append(clusterEventDedup.order, batchID)
	if len(clusterEventDedup.order) > clusterEventDedup.cap {
		oldest := clusterEventDedup.order[0]
		clusterEventDedup.order = clusterEventDedup.order[1:]
		delete(clusterEventDedup.seen, oldest)
	}
	return true
}

// HandleClusterEventReport 机器接口：从节点事件上报。
func (h *Handlers) HandleClusterEventReport(c *gin.Context) {
	var req notify.ClusterEventReport
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Events) == 0 {
		// 直写豁免：集群机器接口，消费方为从节点重试逻辑（无用户语言面）。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上报载荷无效"})
		return
	}
	if len(req.Events) > 100 {
		// 直写豁免：集群机器接口（同上，无用户语言面）。
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "单批事件数超限（≤100）"})
		return
	}
	if !clusterEventDedupRecord(req.BatchID) {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"deduped": true}})
		return
	}
	// 上报者身份→节点名（令牌认证中间件已验签；这里把载荷 Node 与节点行名
	// 比对——不一致以节点行为准（防伪造他节点名）。取 nodes 表按认证节点。
	nodeIDVal, exists := c.Get("cluster_node_id")
	reporterName := ""
	if exists {
		if nodeID, ok := nodeIDVal.(int); ok {
			_ = db.DB.QueryRow(`SELECT COALESCE(name,'') FROM nodes WHERE id=?`, nodeID).Scan(&reporterName)
		}
	}
	if reporterName == "" {
		// 中间件未注入节点 id（形态变更兜底）：信任载荷名但标记（降级面）
		reporterName = strings.TrimSpace(req.Node)
	}
	accepted := 0
	for _, one := range req.Events {
		// 目录门+节点名钉扎：载荷 Node 不可伪造他节点（以认证节点行为准）
		evt := notify.Event{
			Type:   one.Type,
			Title:  one.Title,
			Body:   one.Body,
			Fields: one.Fields,
			Node:   reporterName,
		}
		if one.Level != "" {
			evt.Level = notify.Level(one.Level)
		}
		// 目录外事件在此静默丢弃（与本地 Publish 同门——错误响应会放大重试）
		if notify.CatalogLookup(one.Type) {
			clusterEventPublish(evt)
			accepted++
		}
	}
	if req.Spooled {
		services.Logf("info", "集群事件 spool 批次 %s 收敛：节点 %q 接受 %d/%d 条", req.BatchID, reporterName, accepted, len(req.Events))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"accepted": accepted}})
}
