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
	}
}

// humanStatsPayload 统计响应（总览卡数据源；差分语义由 LB 侧聚合）。
type humanStatsPayload struct {
	Challenges int64 `json:"challenges"`
	Passes     int64 `json:"passes"`
	Fails      int64 `json:"fails"`
	Bans       int64 `json:"bans"`
}

func serveHumanStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	raw, err := json.Marshal(humanStatsPayload{
		Challenges: humanStats.Challenges.Load(),
		Passes:     humanStats.Passes.Load(),
		Fails:      humanStats.Fails.Load(),
		Bans:       humanStats.Bans.Load(),
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
