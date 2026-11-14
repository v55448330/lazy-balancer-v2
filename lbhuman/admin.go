package lbhuman

import (
	"encoding/json"
	"net/http"

	"github.com/caddyserver/caddy/v2"
)

// HumanStatsAdmin admin.api 模块：GET /lb/human/stats 挑战/通过/失败计数端点
// （TrafficStatsAdmin 同模式：admin.api 模块随编译自动挂载，无需配置启用）。
type HumanStatsAdmin struct{}

// CaddyModule returns the Caddy module information.
func (HumanStatsAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.lb_human",
		New: func() caddy.Module { return new(HumanStatsAdmin) },
	}
}

// Routes registers the read-only endpoint.
func (HumanStatsAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/lb/human/stats",
			Handler: caddy.AdminHandlerFunc(serveHumanStats),
		},
		{
			Pattern: "/lb/human/live",
			Handler: caddy.AdminHandlerFunc(serveHumanLive),
		},
	}
}

// humanStatsPayload 统计响应（总览卡数据源；差分语义由 LB 侧聚合）。
// CC「封禁」响应退役（2026-11-13）：封禁由自动封禁管线承载，此处不再有 bans。
// cc_triggers=触发原因分布（auto 模式阈值触发，进程累计）；
// events_dropped=事件队列饱和丢弃计数（静默丢事件的对账源）。
type humanStatsPayload struct {
	Challenges    int64          `json:"challenges"`
	Passes        int64          `json:"passes"`
	Fails         int64          `json:"fails"`
	CCTriggers    ccTriggersJSON `json:"cc_triggers"`
	EventsDropped int64          `json:"events_dropped"`
}

// ccTriggersJSON CC 触发原因分布（键与 evalCC Reason 同口径）。
type ccTriggersJSON struct {
	RPSSpike       int64 `json:"rps_spike"`
	Ratio4xx       int64 `json:"4xx_ratio"`
	SessionAnomaly int64 `json:"session_anomaly"`
}

func serveHumanStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	raw, err := json.Marshal(humanStatsPayload{
		Challenges: humanStats.Challenges.Load(),
		Passes:     humanStats.Passes.Load(),
		Fails:      humanStats.Fails.Load(),
		CCTriggers: ccTriggersJSON{
			RPSSpike:       humanCCTriggers.RPSSpike.Load(),
			Ratio4xx:       humanCCTriggers.Ratio4xx.Load(),
			SessionAnomaly: humanCCTriggers.SessionAnomaly.Load(),
		},
		EventsDropped: humanEventDropped.Load(),
	})
	if err != nil {
		raw = []byte(`{}`)
	}
	_, _ = w.Write(raw)
	return nil
}

// Interface guards（编译期契约）。
var (
	_ caddy.AdminRouter = (*HumanStatsAdmin)(nil)
	_ caddy.Module      = (*HumanStatsAdmin)(nil)
)

func init() {
	caddy.RegisterModule(HumanHandler{})
	caddy.RegisterModule(HumanStatsAdmin{})
}
