package handlers

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/apimsg"
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

// clusterEventDedup 上报批次幂等去重窗口（spool 重传/live 重试可能重复送达）。
// 进程内窗口（512 批次 FIFO）：进程重启后窗口重置，主节点侧无法跨重启去重——
// 该边界在 apidocs 端点说明中如实标注，消费方不得据此假定严格 exactly-once。
var clusterEventDedup = struct {
	mu    sync.Mutex
	seen  map[string]struct{}
	order []string
	cap   int
}{seen: map[string]struct{}{}, cap: 512}

// clusterEventDedupRecord 记录批次并返回是否首次（true=处理，false=重复丢弃）。
func clusterEventDedupRecord(batchID string) bool {
	if batchID == "" {
		return true // 无批次键的旧客户端：无法去重，恒处理
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

// parseReportEventTime 解析上报事件的原始发生时刻（RFC3339Nano/RFC3339）；
// 空串/畸形返回零值（Publish 侧回退当前时刻，不因坏时间戳丢事件）。
// 未来时刻同样按零值处理：created_at 落在远未来会让 7 天过期/保留清理永不
// 命中（从节点时钟错乱或恶意载荷即可把事件钉在保留边界之外，回归
// （回归）；Publish 对零值回填当前时刻，事件正常参与过期。
func parseReportEventTime(raw string) time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}
	}
	now := time.Now()
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, raw); err == nil {
			if t.After(now) {
				return time.Time{}
			}
			return t
		}
	}
	return time.Time{}
}

// HandleClusterEventReport 机器接口：从节点事件上报。
func (h *Handlers) HandleClusterEventReport(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, clusterReportBodyLimitBytes)
	var req notify.ClusterEventReport
	if err := c.ShouldBindJSON(&req); err != nil || len(req.Events) == 0 {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "cluster.reportPayloadInvalid"))
		return
	}
	if len(req.Events) > 100 {
		c.JSON(http.StatusBadRequest, apimsg.Envelope(400, "cluster.eventBatchTooLarge"))
		return
	}
	// 与同族机器端点（节点上报）同一 requireMaster 门——降级主节点残留 nodes
	// 行时旧从节点事件会被错挂到已降级主节点并入本地总线，而非转发现主节点。
	if !h.requireMaster(c) {
		return
	}
	nodeID := c.GetInt("cluster_node_id")
	_, reporterLabel, err := h.clusterService.NodeIdentity(c.Request.Context(), nodeID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusForbidden, apimsg.Envelope(403, "cluster.reporterNodeNotRegistered"))
			return
		}
		c.JSON(http.StatusInternalServerError, clusterErrorKeyedResponse(http.StatusInternalServerError, "cluster.reporterNodeReadFailed", err))
		return
	}
	// 去重登记放在角色/身份门之后：非主节点或未登记节点的重试不得消耗
	// 批次键（否则恢复主节点角色后同批次被误判重复而静默丢弃）。
	if !clusterEventDedupRecord(req.BatchID) {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"deduped": true}})
		return
	}
	// 事件起源节点（防回荡）：客户端显式上报的 origin 优先，缺省回退上报者
	// 节点名；Hop=已转发跳数（>=1 的从节点侧 Publish 不再外发，互指收敛）。
	origin := strings.TrimSpace(req.Origin)
	if origin == "" {
		origin = strings.TrimSpace(req.Node)
	}
	accepted := 0
	for _, one := range req.Events {
		// 目录门+节点名钉扎：载荷 Node 不可伪造他节点（以认证节点行为准）。
		evt := notify.Event{
			Type:   one.Type,
			Title:  one.Title,
			Body:   one.Body,
			Fields: one.Fields,
			Node:   reporterLabel,
			Origin: origin,
			Hop:    req.Hop,
			// 原始发生时刻（客户端时钟）：spool 重放不得把 created_at 改成重放
			// 时刻（排序/过期口径后移）。解析失败=零值，Publish 回退当前时刻。
			Time: parseReportEventTime(one.Time),
		}
		// 级别白名单：任意字符串入总线会让 levelRank 查表得 0（=info），
		// 订阅过滤静默失效。非法级别留空——Publish 回退目录级别。
		if one.Level != "" {
			if lvl := notify.Level(one.Level); lvl == notify.LevelInfo || lvl == notify.LevelWarn || lvl == notify.LevelCritical {
				evt.Level = lvl
			}
		}
		// 目录外事件在此静默丢弃（与本地 Publish 同门——错误响应会放大重试）
		if notify.CatalogLookup(one.Type) {
			clusterEventPublish(evt)
			accepted++
		}
	}
	if req.Spooled {
		services.Logf("info", "集群事件 spool 批次 %s 收敛：节点 %q 接受 %d/%d 条", req.BatchID, reporterLabel, accepted, len(req.Events))
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"accepted": accepted}})
}
