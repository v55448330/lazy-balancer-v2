package services

// 自动封禁触发原因归因钉：名单条目备注从占位符「自动封禁」升级为具体
// 触发原因（用户裁定）——累犯升档=「累犯·<原因>」，首封/关闭档=直接原因。
//   - 原因分类：人机验证挑战/失败、CRS 拦截/检测、自定义规则拦截/检测
//     （值域=喂入点实际可达形态，阶段 3 族门内）；
//   - 桶窗口内按类别计数，候选透传主原因（计数最多，平局按固定优先序）；
//   - 兼容判据：新 remark 形态仍被识别为自动条目（挤出/到期手动豁免），
//     存量占位符形态同样识别（升级不回改存量）。

import (
	"testing"
	"time"

	"lazy-balancer-v2/internal/models"
)

// Given 喂入点实际可达的 action×rule_triggered 形态。
// When 原因分类。
// Then 人机两态/CRS 两态/自定义两态各归其类；未知形态空串（降级占位符）。
func TestAutobanBanReason_classifiesFeedShapes(t *testing.T) {
	cases := []struct {
		action, rule string
		want         string
	}{
		{"challenged", "human_challenge", "人机验证挑战"},
		{"challenged", "human_failed", "人机验证失败"},
		{"challenged", "cc_session_anomaly", "会话异常"},
		{"blocked", "cc_rate_reject", "限流拒绝"},
		{"blocked", "942100", "CRS拦截"},
		{"logged", "942100", "CRS检测"},
		{"blocked", "10001", "自定义规则拦截"},
		{"logged", "1000001", "自定义规则检测"},
		{"blocked", "not-a-rule", ""},
		{"logged", "", ""},
	}
	for _, c := range cases {
		if got := autobanBanReason(c.action, c.rule); got != c.want {
			t.Fatalf("autobanBanReason(%q,%q)=%q, want %q", c.action, c.rule, got, c.want)
		}
	}
}

// Given CC 触发原因 token 值域（lbhuman evalCC 的 Reason：三合法 token +
// 未知/空）。
// When AutobanCCTriggerReasonLabel 映射。
// Then 三 token 各归中文标签；未知/空返回空串（不污染归因，rule_msg 与
// 条目备注共用本单源）。
func TestAutobanCCTriggerReasonLabel_valueDomain(t *testing.T) {
	cases := []struct {
		reason, want string
	}{
		{"session_anomaly", "会话异常"},
		{"rps_spike", "突刺"},
		{"4xx_ratio", "4xx激增"},
		{"unknown_token", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := AutobanCCTriggerReasonLabel(c.reason); got != c.want {
			t.Fatalf("AutobanCCTriggerReasonLabel(%q)=%q, want %q", c.reason, got, c.want)
		}
	}
}

// Given 桶内混合原因（CRS拦截×2 + 人机验证失败×3）。
// When 评估候选。
// Then 候选主原因=计数最多类别（人机验证失败）。
func TestAutobanCandidates_carriesDominantReason(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 5, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged,challenge_issued,challenge_failed"}
	ip := "45.33.32.201"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "blocked", "942100", autobanNow())
	}
	for range 3 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "challenged", "human_failed", autobanNow())
	}
	candidates := autobanCandidates(AutobanConfig{Threshold: 5}, 5*time.Minute)
	if len(candidates) != 1 {
		t.Fatalf("candidates=%+v, want 1", candidates)
	}
	if candidates[0].Reason != "人机验证失败" {
		t.Fatalf("主原因=%q, want 人机验证失败（计数最多）", candidates[0].Reason)
	}
}

// Given 桶内两类原因计数相同（CRS拦截×2 + 自定义规则拦截×2）。
// When 评估候选。
// Then 平局按固定优先序（人机>CRS>自定义，拦截>检测）取 CRS拦截。
func TestAutobanCandidates_reasonTieBreakFixedOrder(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 4, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	ip := "45.33.32.202"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "blocked", "10001", autobanNow())
	}
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "blocked", "942100", autobanNow())
	}
	candidates := autobanCandidates(AutobanConfig{Threshold: 4}, 5*time.Minute)
	if len(candidates) != 1 || candidates[0].Reason != "CRS拦截" {
		t.Fatalf("平局主原因=%+v, want CRS拦截（固定优先序）", candidates)
	}
}

// Given 桶尾达标形态（最后采样在窗口尾，tick 晚于窗口到期）。
// When 评估候选（过期桶并入候选再删）。
// Then 过期候选同样携带主原因（不丢归因）。
func TestAutobanCandidates_expiredReachedCarriesReason(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	ip := "45.33.32.203"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "blocked", "942100", autobanNow())
	}
	clock.Advance(6 * time.Minute)
	candidates := autobanCandidates(AutobanConfig{Threshold: 2}, 5*time.Minute)
	if len(candidates) != 1 || candidates[0].Reason != "CRS拦截" {
		t.Fatalf("过期候选=%+v, want 携带 CRS拦截", candidates)
	}
}

// Given 首封（无累犯行）+ 候选主原因。
// When merge（escalation=standard）。
// Then 条目备注=直接原因（首封不冠累犯前缀）。
func TestAutobanMerge_firstBanRemarkIsReason(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	ip := "45.33.32.204"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "blocked", "942100", autobanNow())
	}
	if _, err := autobanMergeEntries(cfg, autobanCandidates(AutobanConfig{Threshold: 2}, 5*time.Minute)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Remark != "CRS拦截" {
		t.Fatalf("首封备注=%+v, want CRS拦截", entries)
	}
}

// Given 已有累犯行（offense=1）+ 候选主原因。
// When merge（standard 二次升档）。
// Then 条目备注=「累犯·原因」。
func TestAutobanMerge_escalatedBanRemarkHasRecidPrefix(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t, [4]string{"45.33.32.205", "1", "2026-11-14 10:00:00", "1h"})
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "challenge_failed", Escalation: "standard"}
	ip := "45.33.32.205"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "challenged", "human_failed", autobanNow())
	}
	if _, err := autobanMergeEntries(cfg, autobanCandidates(AutobanConfig{Threshold: 2}, 5*time.Minute)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Remark != "累犯·人机验证失败" {
		t.Fatalf("升档备注=%+v, want 累犯·人机验证失败", entries)
	}
}

// Given escalation=off + 已有累犯行 + 候选主原因。
// When merge。
// Then 备注=直接原因（关闭档不冠累犯前缀——用户裁定）。
func TestAutobanMerge_escalationOffRemarkNoPrefix(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t, [4]string{"45.33.32.206", "2", "2026-11-14 10:00:00", "24h"})
	cfg := AutobanConfig{Enabled: true, Threshold: 2, WindowMinutes: 5, Duration: "1h", Scope: "logged", Escalation: "off"}
	ip := "45.33.32.206"
	for range 2 {
		autobanObserveEventScopedAt(cfg, AutobanScopeSet(cfg.Scope), ip, "logged", "10001", autobanNow())
	}
	if _, err := autobanMergeEntries(cfg, autobanCandidates(AutobanConfig{Threshold: 2}, 5*time.Minute)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Remark != "自定义规则检测" {
		t.Fatalf("关闭档备注=%+v, want 自定义规则检测（无前缀）", entries)
	}
}

// Given 候选无原因（direct test seam 无 feed 详情）。
// When merge。
// Then 备注降级占位符「自动封禁」（存量形态，判据兼容）。
func TestAutobanMerge_noReasonFallsBackToPlaceholder(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	if _, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: "45.33.32.207", Count: 3}}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Remark != autobanEntryRemark {
		t.Fatalf("无原因备注=%+v, want 占位符", entries)
	}
}

// Given 新原因形态/累犯前缀形态/存量占位符/手动备注。
// When 自动条目判据。
// Then 前三者=自动条目（挤出/豁免判据兼容）；手动备注=非自动。
func TestAutobanEntryIsAutomatic_remarkShapes(t *testing.T) {
	cases := []struct {
		remark string
		want   bool
	}{
		{"自动封禁", true},
		{"CRS拦截", true},
		{"人机验证失败", true},
		{"累犯·CRS拦截", true},
		{"手动封禁", false},
		{"事件处置", false},
		{"", false},
		{"CRS拦截备注", false},
	}
	for _, c := range cases {
		if got := autobanEntryIsAutomatic(models.IPListEntry{Remark: c.remark}); got != c.want {
			t.Fatalf("autobanEntryIsAutomatic(%q)=%v, want %v", c.remark, got, c.want)
		}
	}
}

// Given 名单含新原因形态自动条目（临期）+ 手动条目。
// When merge 容量挤出。
// Then 新形态自动条目参与挤出（判据兼容），手动条目豁免。
func TestAutobanMerge_reasonRemarkEntriesEvictable(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	seedPresetEntries(t, []models.IPListEntry{
		{Value: "45.33.32.1", Remark: "事件处置"},
		{Value: "45.33.32.210", Remark: "CRS拦截", CreatedAt: "2026-11-15 09:00:00", ExpiresAt: "2026-11-15 11:00:00"},
	})
	oldCap := AutobanListEntryCap
	AutobanListEntryCap = 2
	t.Cleanup(func() { AutobanListEntryCap = oldCap })
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "off"}
	if _, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: "45.33.32.211", Count: 2, Reason: "人机验证挑战"}}); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 2 {
		t.Fatalf("entries=%+v, want 2（容量）", entries)
	}
	var manualKept, newBanned bool
	for _, e := range entries {
		if e.Value == "45.33.32.1" {
			manualKept = true
		}
		if e.Value == "45.33.32.211" && e.Remark == "人机验证挑战" {
			newBanned = true
		}
		if e.Value == "45.33.32.210" {
			t.Fatalf("新形态自动条目必须参与挤出, entries=%+v", entries)
		}
	}
	if !manualKept || !newBanned {
		t.Fatalf("手动豁免/新封落库失真: %+v", entries)
	}
}
