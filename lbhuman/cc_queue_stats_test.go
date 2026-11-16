package lbhuman

// queue 发放计入挑战发放计数器（与 kind=challenge 事件落库口径一致）：
// 总览卡 challenges 是发放口径统计，queue 等待页/queue JSON 都属挑战发放；
// reject 属被拦截口径（rate_reject→blocked 维度），不得虚增 challenges。

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func queueStatsHandler(action string) *HumanHandler {
	return &HumanHandler{HumanConfig{
		Mode: "auto", Type: "js", TTLMinutes: 30, Secret: "0123456789abcdef0123456789abcdef",
		CCEnabled: true, CCRPSLimit: 5, CCWindowSec: 10,
		CCTriggerAction: action, CCQueueWaitSec: 15, RuleID: "rule-queue-stats-" + action,
	}}
}

// Given queue 动作策略。
// When 浏览器等待页 / API JSON / 非幂等请求三种发放形态。
// Then challenges 计数各 +1（与 kind=challenge 落库同口径）。
func TestQueueIssuance_countsChallenge(t *testing.T) {
	cases := []struct {
		name   string
		method string
		accept string
	}{
		{"browser_wait_page", http.MethodGet, "text/html"},
		{"api_json", http.MethodGet, "application/json"},
		{"non_idempotent_json", http.MethodPost, "text/html"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := queueStatsHandler("queue")
			r := httptest.NewRequest(tc.method, "https://example.com/page", nil)
			r.Header.Set("Accept", tc.accept)
			before := humanStats.Challenges.Load()
			h.serveQueueWait(httptest.NewRecorder(), r, "203.0.113.70")
			if got := humanStats.Challenges.Load() - before; got != 1 {
				t.Fatalf("queue 发放 challenges 增量=%d, want 1（与 kind=challenge 落库同口径）", got)
			}
		})
	}
}

// Given reject 动作策略。
// When 浏览器拒绝页 / API JSON 两种形态。
// Then challenges 不增（rate_reject 按 blocked 口径，不进挑战发放）。
func TestRateReject_notCountedAsChallenge(t *testing.T) {
	for _, accept := range []string{"text/html", "application/json"} {
		t.Run(accept, func(t *testing.T) {
			h := queueStatsHandler("reject")
			r := httptest.NewRequest(http.MethodGet, "https://example.com/page", nil)
			r.Header.Set("Accept", accept)
			before := humanStats.Challenges.Load()
			h.serveRateReject(httptest.NewRecorder(), r, "203.0.113.71")
			if got := humanStats.Challenges.Load() - before; got != 0 {
				t.Fatalf("reject challenges 增量=%d, want 0（rate_reject 属 blocked 口径）", got)
			}
		})
	}
}
