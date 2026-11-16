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
