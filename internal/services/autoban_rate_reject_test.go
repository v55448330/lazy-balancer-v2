package services

// CC reject 动作喂自动封禁 blocked 口径钉测：kind=rate_reject 经人机事件
// 传输通道映射到 blocked 维度（429 确属拦截）；challenge/fail 现行维度不变。

import (
	"testing"
	"time"
)

func TestObserveHumanEvents_rateRejectCountsBlocked(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "blocked", true)
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.60", Kind: "rate_reject", At: time.Time{}},
	})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.60"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("rate_reject 必须按 blocked 口径计数（scope=blocked），w=%+v", w)
	}
}

func TestObserveHumanEvents_rateRejectEvidenceConfirmed(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.61", Kind: "rate_reject", At: time.Time{}},
	})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.61"]
	autobanMu.Unlock()
	if w == nil || w.Confirmed != 1 || w.Suspicion != 0 {
		t.Fatalf("rate_reject 在 evidence 模式必须计确证（blocked 属确证组），w=%+v", w)
	}
}

func TestObserveHumanEvents_challengeFailDimsUnchanged(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.62", Kind: "challenge", At: time.Time{}},
		{IP: "45.33.32.62", Kind: "fail", At: time.Time{}},
	})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.62"]
	autobanMu.Unlock()
	if w == nil || w.Confirmed != 1 || w.Suspicion != 1 {
		t.Fatalf("challenge=嫌疑/fail=确证 现行维度不得变，w=%+v", w)
	}
}

// Given CC reject 拦截事件经人机通道喂入（blocked×cc_rate_reject）。
// When 窗口原因计数与候选归因。
// Then 原因类别=限流拒绝（不得丢归因降级占位符），主原因透传候选。
func TestObserveHumanEvents_rateRejectCarriesReason(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.63", Kind: "rate_reject", At: time.Time{}},
	})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.63"]
	autobanMu.Unlock()
	if w == nil || w.Reasons["限流拒绝"] != 1 {
		t.Fatalf("rate_reject 必须计入「限流拒绝」原因桶，w=%+v", w)
	}
	cands := autobanCandidates(cfg, 5*time.Minute)
	if len(cands) != 1 || cands[0].Reason != "限流拒绝" {
		t.Fatalf("候选主原因=%+v, want 限流拒绝", cands)
	}
}

// Given rate_reject 达阈值候选。
// When merge 落名单。
// Then 条目备注=限流拒绝（归因缺口修复：此前分类空串→占位符「自动封禁」）。
func TestObserveHumanEvents_rateRejectBanRemark(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked"}
	if err := SetAutobanConfig(cfg); err != nil {
		t.Fatal(err)
	}
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.64", Kind: "rate_reject", At: time.Time{}},
	})
	if _, err := autobanMergeEntries(cfg, autobanCandidates(cfg, 5*time.Minute)); err != nil {
		t.Fatalf("merge: %v", err)
	}
	entries := presetEntries(t)
	if len(entries) != 1 || entries[0].Remark != "限流拒绝" {
		t.Fatalf("封禁备注=%+v, want 限流拒绝", entries)
	}
}

// Given CC reject（429）人机通道批喂入（IPC 提交后形态）+ 一次挑战发放 +
// 一条保留地址 reject。
// When ObserveHumanEvents。
// Then 只有 429 拦截弧入攻击光流环（同屏 feed/拦截率已含该事件，光流不得缺弧）；
// challenged（发放/失败）不属攻击、保留地址按入环门硬排除。
func TestObserveHumanEvents_rateRejectFeedsAttackFlow(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "blocked", true)
	ResetThreatScreenAttackFlowForTest()
	mustAcquireAttackFlowLease(t, "tab-d1-flow", 1)
	t.Cleanup(ResetThreatScreenAttackFlowForTest)
	at := autobanNow()
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "45.33.32.66", Kind: "rate_reject", At: at},
		{IP: "45.33.32.67", Kind: "challenge", At: at},
		{IP: "192.168.5.5", Kind: "rate_reject", At: at},
	})
	events, _, _ := ThreatScreenAttackFlowSnapshot(0, 10)
	if len(events) != 1 {
		t.Fatalf("光流环入环数=%d, want 1（仅 CC reject 拦截弧）: %+v", len(events), events)
	}
	ev := events[0]
	if ev.ClientIP != "45.33.32.66" || ev.Action != "blocked" || ev.RuleTriggered != "cc_rate_reject" {
		t.Fatalf("光流弧=%+v, want 45.33.32.66/blocked/cc_rate_reject", ev)
	}
}
