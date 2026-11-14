package services

// 摄取单事件门控重构的等价钉：口径集合单次解析（scopeSet 成员表共用）与
// 廉价门控前置（ip/ruleTriggered/window 先判）不得改变任何计数资格。

import (
	"testing"
	"time"
)

// Given 各口径形态（含空白/重复成员）与身份/窗口边界。
// When 直接驱动单事件摄取点。
// Then 计数资格与重构前逐形等价：空 ip/空 token/零窗口先于口径解析丢弃，
// 口径成员资格按同一成员表判定（WAF 维度与人机维度共用一次解析）。
func TestAutobanObserveEventScopedAt_gateEquivalence(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h", Scope: "blocked,logged"}
	cases := []struct {
		name          string
		ip            string
		action        string
		ruleTriggered string
		windowMinutes int
		wantFed       bool
	}{
		{"目标形态", "45.33.32.1", "blocked", "942100", 5, true},
		{"空ip先判丢弃", "", "blocked", "942100", 5, false},
		{"空token先判丢弃", "45.33.32.2", "blocked", "", 5, false},
		{"零窗口先判丢弃", "45.33.32.3", "blocked", "942100", 0, false},
		{"负窗口先判丢弃", "45.33.32.4", "blocked", "942100", -1, false},
		{"口径外action", "45.33.32.5", "challenged", "942100", 5, false},
		{"阶段1族不计", "45.33.32.6", "blocked", "850001", 5, false},
		{"非数值token不计", "45.33.32.7", "blocked", "not-a-rule", 5, false},
		{"logged维度照常", "45.33.32.8", "logged", "942100", 5, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetAutobanStateForTest()
			c := cfg
			c.WindowMinutes = tc.windowMinutes
			autobanObserveEventScopedAt(c, tc.ip, tc.action, tc.ruleTriggered, time.Time{})
			autobanMu.Lock()
			_, fed := autobanWindows[tc.ip]
			autobanMu.Unlock()
			if fed != tc.wantFed {
				t.Fatalf("ip=%q action=%q token=%q window=%d 计数=%v, want %v",
					tc.ip, tc.action, tc.ruleTriggered, tc.windowMinutes, fed, tc.wantFed)
			}
		})
	}
}

// Given 口径集合带空白/重复成员（解析归一形态）。
// When WAF 事件与人机事件共用同一成员表判定。
// Then 成员资格与逐次解析完全一致（单次解析不得改变口径语义）。
func TestAutobanObserveEventScopedAt_scopeSetSharedAcrossDimensions(t *testing.T) {
	installAutobanFixture(t, "2026-11-13 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 100, WindowMinutes: 5, Duration: "1h",
		Scope: " blocked , logged ,challenge_issued, challenge_failed ,blocked"}
	autobanObserveEventScopedAt(cfg, "45.33.32.10", "blocked", "942100", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.11", "logged", "942100", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.12", "challenged", "human_challenge", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.13", "challenged", "human_failed", time.Time{})
	autobanObserveEventScopedAt(cfg, "45.33.32.14", "challenged", "human_pass", time.Time{})
	autobanMu.Lock()
	defer autobanMu.Unlock()
	for _, ip := range []string{"45.33.32.10", "45.33.32.11", "45.33.32.12", "45.33.32.13"} {
		if w := autobanWindows[ip]; w == nil || w.Count != 1 {
			t.Fatalf("%s 应计数 1, got %+v", ip, w)
		}
	}
	if w := autobanWindows["45.33.32.14"]; w != nil {
		t.Fatalf("human_pass 永不计数, got %+v", w)
	}
}
