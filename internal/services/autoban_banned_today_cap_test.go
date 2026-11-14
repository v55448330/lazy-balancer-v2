package services

//「今日封禁」是封禁事件数（与名单现状解耦），单轮逐 IP 审计行上限不得让洪峰
// 轮次的封禁数被截断：单轮 800 个 IP（逐条上限 500）应显示 800，而不是
// 501（500 条逐 IP 行 + 1 条汇总行被当成 1 个事件）。

import (
	"fmt"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestAutobanBannedToday_countsOmittedBansBeyondRoundCap(t *testing.T) {
	installAutobanFixture(t, "2026-10-14 10:00:00")
	// 钉 UTC：今日边界由 autobanNow（夹具时钟）换算，时区参与判定。
	previous := CurrentLocation().String()
	if _, err := ConfigureLocation("UTC"); err != nil {
		t.Fatalf("configure UTC: %v", err)
	}
	t.Cleanup(func() { _, _ = ConfigureLocation(previous) })

	oldCap := autobanAuditPerRoundCap
	autobanAuditPerRoundCap = 3
	t.Cleanup(func() { autobanAuditPerRoundCap = oldCap })

	ips := make([]string, 0, 8)
	for i := 1; i <= 8; i++ {
		ips = append(ips, fmt.Sprintf("45.33.32.%d", i))
	}
	cfg := AutobanConfig{Threshold: 5, WindowMinutes: 10, Duration: "1h"}
	autobanAuditBanned(cfg, ips)

	// 前提：上限确实把逐 IP 行截到 3 条，剩余信息只存在于一条非逐 IP 的汇总行。
	var perIP, total int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND detail LIKE 'IP：%'`, AutobanAuditAction).Scan(&perIP); err != nil {
		t.Fatal(err)
	}
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, AutobanAuditAction).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if perIP != 3 || total-perIP != 1 {
		t.Fatalf("逐 IP 行=%d 汇总行=%d, want 3/1（单轮上限生效形态）", perIP, total-perIP)
	}
	if got := AutobanBannedToday(); got != 8 {
		t.Fatalf("今日封禁=%d, want 8（逐 IP 行 3 + 汇总行携带的省略数 5；汇总行本身不重复计为 1 个事件）", got)
	}

	// 未超上限的轮次：逐 IP 行直接计数，跨轮累加。
	autobanAuditBanned(cfg, ips[:2])
	if got := AutobanBannedToday(); got != 10 {
		t.Fatalf("跨轮累计今日封禁=%d, want 10", got)
	}
}
