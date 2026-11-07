package caddyl4sec

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// 检测放行拆分（logged）TCP 对称 RED→GREEN 用例：
// trust_detect（logged）连接除计入 allowed 外，必须单独计入 logged 计数；
// logged 列为归因明细（2026-11-08 用户裁定：读侧 normal = allowed 全额，
// 信任检测连接计入正常列，消费侧不再扣减 logged），本模块只
// 保证三件事：①logged 全量计数 ②不改变 allowed/denied 既有语义 ③
// 契约 C3 端点快照携带 logged_total 键（附加键，向后兼容：旧消费端零感知）。

// Given: trust_detect 形态 handler
// When: 一次连接穿过 Handle
// Then: logged=1 且 allowed=1、denied=0（logged ⊆ allowed，语义不变）
func TestL4SecHandler_trustDetectCountsLogged(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()
	restore := setSampleCountryLookuperForTest(func(string) (string, bool) { return "", false })
	defer restore()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-logged", Reason: reasonTrustDetect})
	next := &nextCapture{}
	if err := h.Handle(newTestConn("203.0.113.70"), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	snap := connStatsSnapshot()
	rule := snap.Rules["r-logged"]
	if rule == nil {
		t.Fatal("r-logged not registered")
	}
	if rule.LoggedTotal != 1 {
		t.Fatalf("logged_total = %d, want 1（trust_detect 连接必须计入检测列）", rule.LoggedTotal)
	}
	if rule.AllowedTotal != 1 || rule.DeniedTotal != 0 {
		t.Fatalf("allowed/denied = %d/%d, want 1/0（logged 计入 allowed 的既有语义不得改变）",
			rule.AllowedTotal, rule.DeniedTotal)
	}
}

// Given: deny 形态 handler
// Then: logged 恒 0（拦截不进检测列）
func TestL4SecHandler_denyDoesNotCountLogged(t *testing.T) {
	t.Setenv("LB_SECURITY_EVENTS_IPC_SOCKET", "")
	resetConnStatsForTest()
	p := acquirePipelineForTest()
	defer p.resetForTest()

	h := newHandlerForTest(t, &L4SecHandler{RuleCaddyID: "r-logged", Reason: reasonDeny, PolicyID: 3})
	next := &nextCapture{}
	if err := h.Handle(newTestConn("203.0.113.71"), next); err != nil {
		t.Fatalf("Handle() = %v", err)
	}
	rule := connStatsSnapshot().Rules["r-logged"]
	if rule == nil || rule.LoggedTotal != 0 || rule.DeniedTotal != 1 {
		t.Fatalf("logged/denied = %v, want 0/1（拦截不计检测列）", rule)
	}
}

// 契约 C3（2026-11 检测放行拆分扩展）：快照 JSON 携带 logged_total 键，
// 值=trust_detect 计数；既有 allowed_total/denied_total/countries 键不变
// （附加键向后兼容，services 侧 L4TrafficRuleCounters 同步扩展）。
func TestConnStatsSnapshotIncludesLoggedTotal(t *testing.T) {
	resetConnStatsForTest()
	beginLoad(caddy.Context{Context: context.Background()})
	c := getOrCreateRuleCounters("r-c3-logged")
	c.allowed.Add(5)
	c.logged.Add(2)

	raw := connStatsJSON()
	var doc struct {
		Rules map[string]struct {
			AllowedTotal uint64            `json:"allowed_total"`
			DeniedTotal  uint64            `json:"denied_total"`
			LoggedTotal  uint64            `json:"logged_total"`
			Countries    map[string]uint64 `json:"countries"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("snapshot not JSON: %v\n%s", err, raw)
	}
	rule, ok := doc.Rules["r-c3-logged"]
	if !ok {
		t.Fatalf("r-c3-logged missing in %s", raw)
	}
	if rule.LoggedTotal != 2 || rule.AllowedTotal != 5 {
		t.Fatalf("logged/allowed = %d/%d, want 2/5", rule.LoggedTotal, rule.AllowedTotal)
	}
}
