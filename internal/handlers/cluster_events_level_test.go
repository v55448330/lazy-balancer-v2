package handlers

// 集群事件上报的级别白名单（2026-11-22 集中汇聚）：上报载荷 Level 为任意
// 字符串时原样入总线，levelRank 查不到=0（=info）→ 订阅过滤静默失效。
// 非法级别必须留空（Publish 回退目录级别），合法三级原样透传。

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/notify"
)

func TestHandleClusterEventReport_sanitizesEventLevel(t *testing.T) {
	withIsolatedGlobal(t) // 改写 clusterEventPublish seam
	h := newBackupTestHandlers(t)
	seedClusterNodeForReport(t, 46, "slave-lvl")
	var captured []notify.Event
	oldPublish := clusterEventPublish
	clusterEventPublish = func(evt notify.Event) { captured = append(captured, evt) }
	t.Cleanup(func() { clusterEventPublish = oldPublish })

	router := clusterReportRouter(t, h, 46, "/cluster/events/report", h.HandleClusterEventReport)
	body := `{"node":"slave-lvl","events":[
		{"type":"cfg.caddy_apply_failed","level":"urgent"},
		{"type":"cfg.caddy_apply_failed","level":"info"},
		{"type":"cfg.caddy_apply_failed","level":"warn"},
		{"type":"cfg.caddy_apply_failed","level":"critical"},
		{"type":"cfg.caddy_apply_failed"}
	]}`
	rec := postClusterJSON(router, "/cluster/events/report", body)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if len(captured) != 5 {
		t.Fatalf("入总线事件数=%d, want 5", len(captured))
	}
	wantLevels := []notify.Level{"", notify.LevelInfo, notify.LevelWarn, notify.LevelCritical, ""}
	for i, want := range wantLevels {
		if captured[i].Level != want {
			t.Fatalf("事件[%d] Level=%q, want %q（非法级别必须留空）", i, captured[i].Level, want)
		}
	}
}
