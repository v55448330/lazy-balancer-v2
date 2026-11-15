package services

// 证据分层计数引擎钉测：双累加器分组、判定公式（快通道/打底/T2 边界）、
// 纯嫌疑永不封、窗口滚动双清零、classic 等权回归。

import (
	"testing"
	"time"
)

// evidence 配置 helper：四口径全选、阈值 T1、倍率 M、打底 f。
func evidenceCfg(threshold, mult int, floor string) AutobanConfig {
	return AutobanConfig{
		Enabled: true, Threshold: threshold, WindowMinutes: 5, Duration: "1h",
		Scope: "blocked,logged,challenge_issued,challenge_failed", DryRun: true,
		CountingMode: "evidence", SuspicionMultiplier: mult, ConfirmFloorRatio: floor,
	}
}

// Given evidence 模式四口径全选。
// When 依次摄入 blocked/logged/challenge_issued/challenge_failed 各 1。
// Then 确证=2 嫌疑=2 Count=4。
func TestAutobanEvidence_groupedCounting(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	autobanObserveEventScopedAt(cfg, "45.33.32.1", "blocked", "942100", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.1", "logged", "942100", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.1", "challenged", "human_challenge", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.1", "challenged", "human_failed", time.Time{})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.1"]
	autobanMu.Unlock()
	if w == nil {
		t.Fatal("计数桶缺失")
	}
	if w.Confirmed != 2 || w.Suspicion != 2 || w.Count != 4 {
		t.Fatalf("confirmed=%d suspicion=%d count=%d, want 2/2/4", w.Confirmed, w.Suspicion, w.Count)
	}
}

// Given evidence 模式 scope 不含 logged。
// When 摄入 logged。
// Then 双累加器不变。
func TestAutobanEvidence_scopeGateStillApplies(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	cfg.Scope = "blocked,challenge_failed"
	autobanObserveEventScopedAt(cfg, "45.33.32.2", "logged", "942100", time.Time{})
	autobanMu.Lock()
	n := len(autobanWindows)
	autobanMu.Unlock()
	if n != 0 {
		t.Fatalf("scope 未选口径不得计数，残留 %d 键", n)
	}
}

// 判定公式边界：T1=5, M=4(T2=20), f=0.4(floor=2)。
func TestAutobanEvidence_decisionBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name      string
		confirmed int
		suspicion int
		want      bool
	}{
		{"pure-attack-reaches-T1", 5, 0, true},
		{"pure-attack-below-T1", 4, 0, false},
		{"pure-suspicion-never", 0, 100, false},
		{"mixed-floor-and-T2-exact", 2, 18, true},
		{"mixed-floor-short", 1, 19, false},
		{"mixed-T2-short", 2, 17, false},
		{"mixed-floor-exact-T2-over", 3, 20, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := autobanEvidenceReached(tc.confirmed, tc.suspicion, 5, 4, "0.4")
			if got != tc.want {
				t.Fatalf("confirmed=%d suspicion=%d reached=%v, want %v", tc.confirmed, tc.suspicion, got, tc.want)
			}
		})
	}
}

// 打底比例 ceil 口径：T1=5, f=0.2 → floor=ceil(1)=1；T1=3,f=0.4→ceil(1.2)=2。
func TestAutobanEvidence_floorCeil(t *testing.T) {
	// T1=5 f=0.2 floor=1：确证 1 + 嫌疑 19（合计 20=T2）达标
	if !autobanEvidenceReached(1, 19, 5, 4, "0.2") {
		t.Fatal("T1=5 f=0.2 floor=1，确证 1+嫌疑 19 应达标")
	}
	// T1=3 f=0.4 floor=ceil(1.2)=2：确证 1 不足打底
	if autobanEvidenceReached(1, 100, 3, 4, "0.4") {
		t.Fatal("T1=3 f=0.4 floor=2，确证 1 不得达标")
	}
	if !autobanEvidenceReached(2, 10, 3, 4, "0.4") {
		t.Fatal("T1=3 f=0.4 floor=2，确证 2+嫌疑 10（合计 12=T2）应达标")
	}
}

// Given evidence 计数桶。
// When 窗口滚动。
// Then 双累加器与 Count/Reached 同清零。
func TestAutobanEvidence_windowRollClearsBoth(t *testing.T) {
	clock := installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	autobanObserveEventScopedAt(cfg, "45.33.32.3", "blocked", "942100", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.3", "logged", "942100", time.Time{})
	clock.Advance(6 * time.Minute)
	autobanObserveEventScopedAt(cfg, "45.33.32.3", "blocked", "942100", time.Time{})
	autobanMu.Lock()
	w := autobanWindows["45.33.32.3"]
	autobanMu.Unlock()
	if w.Confirmed != 1 || w.Suspicion != 0 || w.Count != 1 {
		t.Fatalf("窗口滚动后 confirmed=%d suspicion=%d count=%d, want 1/0/1", w.Confirmed, w.Suspicion, w.Count)
	}
}

// classic 模式等权回归：四口径各 1 → Count=4，Confirmed/Suspicion 不参与判定。
func TestAutobanClassic_equalWeightUnchanged(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := evidenceCfg(100, 4, "0.4")
	cfg.CountingMode = "classic"
	for _, ev := range []struct{ action, rule string }{
		{"blocked", "942100"}, {"logged", "942100"},
		{"challenged", "human_challenge"}, {"challenged", "human_failed"},
	} {
		autobanObserveEventScopedAt(cfg, "45.33.32.4", ev.action, ev.rule, time.Time{})
	}
	autobanMu.Lock()
	w := autobanWindows["45.33.32.4"]
	autobanMu.Unlock()
	if w.Count != 4 {
		t.Fatalf("classic Count=%d, want 4（等权）", w.Count)
	}
}
