package services

// 重置累犯前科必须同时清空窗口计数桶与观察建议：只删 autoban_recidivism 行时，
// 窗口内旧计数仍 ≥ 阈值，下一轮 tick 会把刚重置的身份按「首次档」立即重封
// （用户可见的「重置后按首次档起算」被旧计数撤销）。

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestResetAutobanRecidivism_clearsWindowCounters(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	seedAutobanRecidivismRows(t,
		[4]string{"45.33.32.50", "3", "2026-11-15 09:00:00", "24h"},
	)
	setAutobanConfigRaw(t, true, 5, 5, "1h", AutobanScopeBlocked, false)
	// 造窗口计数与观察建议（重置前必须非空，否则断言无判别力）。
	autobanObserveBatch([]autobanFeedItem{{
		IP: "45.33.32.50", Action: "blocked", RuleTriggered: "942100", At: clock.Now(),
	}})
	autobanSetSuggestions([]AutobanSuggestion{{IP: "45.33.32.50", Count: 1}})
	autobanMu.Lock()
	windowsBefore := len(autobanWindows)
	autobanMu.Unlock()
	if windowsBefore == 0 {
		t.Fatal("前置：窗口计数桶应非空")
	}

	if err := ResetAutobanRecidivism(); err != nil {
		t.Fatalf("reset: %v", err)
	}

	var rows int
	if err := db.GetDB().QueryRow(`SELECT COUNT(*) FROM autoban_recidivism`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("累犯历史未清空：%d 行", rows)
	}
	autobanMu.Lock()
	windowsAfter := len(autobanWindows)
	autobanMu.Unlock()
	if windowsAfter != 0 {
		t.Fatalf("重置后窗口计数桶=%d 键，want 0（旧计数会让下一轮立即重封）", windowsAfter)
	}
	if got := AutobanSuggestions(); len(got) != 0 {
		t.Fatalf("重置后观察建议=%d 条，want 0", len(got))
	}
}

// /64 身份的两种文本前缀模式：压缩网络串 + 前四个 hextet 全展开——
// 覆盖第 5 个 hextet 非零、不以压缩网络串开头的同段地址；均无前导通配符
// （可按 idx_security_events_ip_time 前缀扫描）。
func TestAutobanIPv6IdentityPatterns(t *testing.T) {
	cases := []struct {
		identity string
		want     [2]string
	}{
		{"2606:4700:abcd:1234::", [2]string{"2606:4700:abcd:1234::%", "2606:4700:abcd:1234:%"}},
		{"2001:db8::", [2]string{"2001:db8::%", "2001:db8:0:0:%"}},
		{"::", [2]string{"::%", "0:0:0:0:%"}},
		{"not-an-ip", [2]string{"not-an-ip%", "not-an-ip%"}},
	}
	for _, tc := range cases {
		if got := autobanIPv6IdentityPatterns(tc.identity); got != tc.want {
			t.Fatalf("patterns(%q)=%v, want %v", tc.identity, got, tc.want)
		}
	}
}
