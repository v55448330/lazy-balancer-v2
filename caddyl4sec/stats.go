package caddyl4sec

import (
	"context"
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2"
)

// —— 连接计数（契约 C3）——
//
// per-rule allowed/denied 全量累计 + 放行连接 1/16 采样的国家归属累计。
// 计数器随 /load 重建归零（契约锁定语义）：caddy 每次 load 为全部模块生成新
// 的 caddy.Context（新 *cancelCtx），Provision 以载次身份为键——新载次首次
// 注册即整体重置注册表；旧载次实例的 Cleanup 按指针身份注销，不误删新载次
// 条目；换载次后仍存活/在途的旧实例把计数打在已被替换的孤儿结构上，不再进
// 端点快照——即「与 HTTP 计数器同口径」的重建归零。

type ruleConnCounters struct {
	allowed atomic.Uint64
	denied  atomic.Uint64

	mu        sync.Mutex
	countries map[string]uint64
}

type connStatsRegistry struct {
	mu      sync.Mutex
	loadCtx context.Context // 当前载次身份（caddy load 生成的 ctx.Context）
	rules   map[string]*ruleConnCounters
}

var connStats = &connStatsRegistry{rules: map[string]*ruleConnCounters{}}

// sameLoadCtx 载次身份比较：载次 ctx 的动态值是 *cancelCtx 指针（可比），
// 防御性 recover 覆盖不可比较动态值（按「不同载次」处理=保守重置）。
func sameLoadCtx(a, b context.Context) (same bool) {
	defer func() {
		if recover() != nil {
			same = false
		}
	}()
	return a == b
}

// beginLoad 标记载次：同一载次（同 ctx）幂等；新载次整体重置注册表。
func beginLoad(ctx caddy.Context) {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	if connStats.loadCtx != nil && sameLoadCtx(connStats.loadCtx, ctx.Context) {
		return
	}
	connStats.loadCtx = ctx.Context
	connStats.rules = make(map[string]*ruleConnCounters)
}

// getOrCreateRuleCounters 取（或建）规则的计数条目。
func getOrCreateRuleCounters(ruleID string) *ruleConnCounters {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	if c, ok := connStats.rules[ruleID]; ok {
		return c
	}
	c := &ruleConnCounters{countries: map[string]uint64{}}
	connStats.rules[ruleID] = c
	return c
}

// deregisterRuleCounters 按指针身份注销（同载次多实例共享条目：仅持有者
// 自己的 Cleanup 生效）。
func deregisterRuleCounters(ruleID string, c *ruleConnCounters) {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	if cur, ok := connStats.rules[ruleID]; ok && cur == c {
		delete(connStats.rules, ruleID)
	}
}

// ruleStatsView 是端点快照的行视图（值拷贝，锁外序列化）。
type ruleStatsView struct {
	AllowedTotal uint64
	DeniedTotal  uint64
	Countries    map[string]uint64
}

type connStatsView struct {
	Rules map[string]*ruleStatsView
}

// connStatsSnapshot 全表快照（锁内拷贝）。
func connStatsSnapshot() connStatsView {
	connStats.mu.Lock()
	defer connStats.mu.Unlock()
	out := connStatsView{Rules: make(map[string]*ruleStatsView, len(connStats.rules))}
	for id, c := range connStats.rules {
		c.mu.Lock()
		countries := make(map[string]uint64, len(c.countries))
		for k, v := range c.countries {
			countries[k] = v
		}
		c.mu.Unlock()
		out.Rules[id] = &ruleStatsView{AllowedTotal: c.allowed.Load(), DeniedTotal: c.denied.Load(), Countries: countries}
	}
	return out
}

// l4ConnStatsPayload 是契约 C3 的响应形状（逐字锁定，不得增删键）。
type l4ConnStatsPayload struct {
	Rules map[string]l4RuleStatsPayload `json:"rules"`
}

type l4RuleStatsPayload struct {
	AllowedTotal uint64            `json:"allowed_total"`
	DeniedTotal  uint64            `json:"denied_total"`
	Countries    map[string]uint64 `json:"countries"`
}

// connStatsJSON 渲染 C3 快照（encoding/json 对 map 键排序，输出稳定）。
func connStatsJSON() []byte {
	snap := connStatsSnapshot()
	payload := l4ConnStatsPayload{Rules: make(map[string]l4RuleStatsPayload, len(snap.Rules))}
	for id, r := range snap.Rules {
		payload.Rules[id] = l4RuleStatsPayload{AllowedTotal: r.AllowedTotal, DeniedTotal: r.DeniedTotal, Countries: r.Countries}
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		// 结构恒可序列化；防御分支返回空 rules 形态（消费端差分健壮性）。
		return []byte(`{"rules":{}}`)
	}
	return raw
}

// —— admin 端点（caddygeoip TrafficStatsAdmin 同模式：admin.api 模块随每次
// admin 服务重建实例化，无实例状态、读全局计数，无 reload 重复注册问题）——

// L4StatsAdmin 注册 GET /lb/l4-conn-stats（契约 C3）与 GET /lb/l4-shipper-stats
// （投递/丢弃计数——丢弃可观测）。契约 C3 的 /lb/l4-conn-stats JSON 形状锁定；
// shipper 端点是本模块的附加观测面，A1 不消费。
type L4StatsAdmin struct{}

// CaddyModule returns the Caddy module information.
func (L4StatsAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.lb_l4_conn_stats",
		New: func() caddy.Module { return new(L4StatsAdmin) },
	}
}

// Routes registers the read-only endpoints.
func (L4StatsAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/lb/l4-conn-stats",
			Handler: caddy.AdminHandlerFunc(serveL4ConnStats),
		},
		{
			Pattern: "/lb/l4-shipper-stats",
			Handler: caddy.AdminHandlerFunc(serveL4ShipperStats),
		},
	}
}

func serveL4ConnStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(connStatsJSON())
	return nil
}

// l4ShipperStatsPayload 投递/兜底过程计数（进程内观测；不进跨进程契约）。
type l4ShipperStatsPayload struct {
	IPCEnabled  bool   `json:"ipc_enabled"`
	IPCSent     uint64 `json:"ipc_sent"`
	IPCFailed   uint64 `json:"ipc_failed"`
	SpoolWrites uint64 `json:"spool_written"`
	SpoolErrors uint64 `json:"spool_errors"`
	QueueLen    int    `json:"queue_len"`
	QueueBytes  int64  `json:"queue_bytes"`
	Dropped     uint64 `json:"dropped"`
}

func serveL4ShipperStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	payload := l4ShipperStatsPayload{}
	if p := currentL4Pipeline(); p != nil {
		payload.IPCEnabled = p.shipper != nil
		payload.IPCSent, payload.IPCFailed, payload.SpoolWrites, payload.SpoolErrors = p.shipperCounters()
		payload.QueueLen = len(p.queue)
		payload.QueueBytes = p.queueBytes.Load()
		payload.Dropped = p.dropped.Load()
	}
	raw, err := json.Marshal(payload)
	if err == nil {
		_, _ = w.Write(raw)
	} else {
		_, _ = w.Write([]byte(`{}`))
	}
	return nil
}

// Interface guards（编译期契约）。
var (
	_ caddy.AdminRouter = (*L4StatsAdmin)(nil)
	_ caddy.Module      = (*L4StatsAdmin)(nil)
)
