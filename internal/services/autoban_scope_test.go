package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 用户裁定（2026-11-13）：自动封禁统计口径单选改四维多选
// （拦截 blocked / 检测 logged / 挑战发放 challenge_issued / 挑战失败
// challenge_failed），count_human_failed 开关退役（语义并入 challenge_failed）。
// scope 存逗号分隔集合；默认四维全选。

func TestValidAutobanScope_acceptsNonEmptySubset(t *testing.T) {
	for _, s := range []string{
		"blocked", "logged", "challenge_issued", "challenge_failed",
		"blocked,logged", "blocked,challenge_failed",
		"blocked,logged,challenge_issued,challenge_failed",
		" logged , blocked ", // 容忍空白
	} {
		if !ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=false, want true", s)
		}
	}
	for _, s := range []string{"", "all", "deny", "BLOCKED", "blocked,", "blocked,bogus", "blocked,blocked"} {
		if ValidAutobanScope(s) {
			t.Errorf("ValidAutobanScope(%q)=true, want false", s)
		}
	}
}

func TestAutobanScopeSet_parsesCanonical(t *testing.T) {
	got := AutobanScopeSet(" logged , blocked ")
	if len(got) != 2 || !got["blocked"] || !got["logged"] {
		t.Fatalf("AutobanScopeSet=%v, want {blocked,logged}", got)
	}
}

// 挑战发放/失败按各自维度成员资格计数；挑战通过永不计数（批喂入口径）。
func TestObserveHumanEvents_countsByScopeDimension(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_issued,challenge_failed", false)

	ObserveHumanEvents([]HumanObserveItem{
		{IP: "203.0.113.70", Kind: "challenge", At: autobanNow()},
		{IP: "203.0.113.70", Kind: "fail", At: autobanNow()},
		{IP: "203.0.113.70", Kind: "pass", At: autobanNow()}, // 通过不计
	})
	autobanMu.Lock()
	w := autobanWindows["203.0.113.70"]
	autobanMu.Unlock()
	if w == nil || w.Count != 2 {
		t.Fatalf("发放+失败应计 2，实际=%+v", w)
	}

	// 仅勾选挑战失败：发放不计。
	resetAutobanStateForTest()
	setAutobanConfigRaw(t, true, 100, 5, "1h", "challenge_failed", false)
	ObserveHumanEvents([]HumanObserveItem{{IP: "203.0.113.71", Kind: "challenge", At: autobanNow()}})
	autobanMu.Lock()
	_, issuedCounted := autobanWindows["203.0.113.71"]
	autobanMu.Unlock()
	if issuedCounted {
		t.Fatal("仅勾选挑战失败时，挑战发放不得计数")
	}
	ObserveHumanEvents([]HumanObserveItem{{IP: "203.0.113.71", Kind: "fail", At: autobanNow()}})
	autobanMu.Lock()
	w = autobanWindows["203.0.113.71"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("挑战失败应计 1，实际=%+v", w)
	}
}

// WAF 拦截/检测仍受阶段 3 族门约束，且按 blocked/logged 维度成员资格计数。
func TestObserveBatch_wafDimensionsRespectScope(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	setAutobanConfigRaw(t, true, 100, 5, "1h", "logged", false)
	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.72", Action: "blocked", RuleTriggered: "942100", At: autobanNow()},
	})
	autobanMu.Lock()
	_, blockedCounted := autobanWindows["203.0.113.72"]
	autobanMu.Unlock()
	if blockedCounted {
		t.Fatal("仅勾选检测时，WAF 拦截不得计数")
	}
	autobanObserveBatch([]autobanFeedItem{
		{IP: "203.0.113.72", Action: "logged", RuleTriggered: "942100", At: autobanNow()},
	})
	autobanMu.Lock()
	w := autobanWindows["203.0.113.72"]
	autobanMu.Unlock()
	if w == nil || w.Count != 1 {
		t.Fatalf("WAF 检测应计 1，实际=%+v", w)
	}
}

// 新装默认口径=四维全选（用户裁定）。
func TestAutobanDefaultScope_allFourDimensions(t *testing.T) {
	if db.DefaultAutobanScope != "blocked,logged,challenge_issued,challenge_failed" {
		t.Fatalf("DefaultAutobanScope=%q, want 四维全选", db.DefaultAutobanScope)
	}
	set := AutobanScopeSet(db.DefaultAutobanScope)
	for _, dim := range []string{"blocked", "logged", "challenge_issued", "challenge_failed"} {
		if !set[dim] {
			t.Fatalf("默认口径缺维度 %s", dim)
		}
	}
}
