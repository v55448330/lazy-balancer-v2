package services

import (
	"testing"
)

// 挑战发放/失败按口径维度成员资格计入自动封禁（2026-11-13 用户裁定：
// count_human_failed 开关退役，语义并入 challenge_failed 维度）；通过永不计。
// 批喂入口径（ObserveHumanEvents）。
func TestObserveHumanEvents_respectsScopeDimensions(t *testing.T) {
	installAutobanFixture(t, "2026-11-12 10:00:00")
	// 仅勾选挑战失败：发放不计，失败计。
	setAutobanConfigRaw(t, true, 3, 5, "1h", "challenge_failed", false)
	ObserveHumanEvents([]HumanObserveItem{{IP: "203.0.113.50", Kind: "challenge", At: autobanNow()}})
	autobanMu.Lock()
	if autobanWindows["203.0.113.50"] != nil {
		autobanMu.Unlock()
		t.Fatal("未勾选挑战发放维度时，发放不得计入")
	}
	autobanMu.Unlock()

	fails := make([]HumanObserveItem, 0, 3)
	for range 3 {
		fails = append(fails, HumanObserveItem{IP: "203.0.113.50", Kind: "fail", At: autobanNow()})
	}
	ObserveHumanEvents(fails)
	autobanMu.Lock()
	w := autobanWindows["203.0.113.50"]
	autobanMu.Unlock()
	if w == nil || w.Count != 3 || !w.Reached {
		t.Fatalf("挑战失败计数=%+v, want count=3 reached", w)
	}

	// 仅勾选检测（logged）：挑战发放/失败均不计。
	resetAutobanStateForTest()
	setAutobanConfigRaw(t, true, 3, 5, "1h", "logged", false)
	ObserveHumanEvents([]HumanObserveItem{
		{IP: "203.0.113.51", Kind: "fail", At: autobanNow()},
		{IP: "203.0.113.51", Kind: "challenge", At: autobanNow()},
	})
	autobanMu.Lock()
	if autobanWindows["203.0.113.51"] != nil {
		autobanMu.Unlock()
		t.Fatal("仅检测口径时挑战事件不得计入")
	}
	autobanMu.Unlock()

	// 挑战通过在任何口径下都不计。
	resetAutobanStateForTest()
	setAutobanConfigRaw(t, true, 3, 5, "1h", "blocked,logged,challenge_issued,challenge_failed", false)
	ObserveHumanEvents([]HumanObserveItem{{IP: "203.0.113.52", Kind: "pass", At: autobanNow()}})
	autobanMu.Lock()
	if autobanWindows["203.0.113.52"] != nil {
		autobanMu.Unlock()
		t.Fatal("挑战通过永不计入")
	}
	autobanMu.Unlock()
}
