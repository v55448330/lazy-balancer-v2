package services

// 累犯升级封禁审计时长钉测：逐 IP「自动封禁」审计的时长必须报告该 IP 的
// 实际执法时长（升级后可能不同于配置时长），不得恒报基础配置时长——
// 排障时审计时长与名单到期/累犯表记账对不上会把升级执法误判为配置错误。

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Given standard 升级（配置时长 1h）、同轮两个 IP：一个首封、一个已有一次
// 累犯记账（本次升档 24h）。
// When merge 后按生产 Run 轮同链写逐 IP 审计。
// Then 逐 IP 行时长各报实际执法时长（首封 1 小时 / 升档 24 小时），
// 升档行不得恒报基础时长。
func TestAutobanAuditBanned_reportsPerIPEnforcedDuration(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "standard"}
	const firstIP, repeatIP = "45.33.32.70", "45.33.32.71"

	// 首次封禁 repeatIP → 到期 → 窗口内再犯（与升级阶梯钉测同链）。
	escalationBan(t, cfg, repeatIP)
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)

	out, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: firstIP, Count: 10}, {IP: repeatIP, Count: 10}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out.Banned) != 2 {
		t.Fatalf("本轮新封=%v, want 两个 IP", out.Banned)
	}
	autobanAuditBanned(cfg, out)

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='自动封禁' AND detail LIKE 'IP：%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	byIP := map[string]string{}
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		for _, ip := range []string{firstIP, repeatIP} {
			if strings.HasPrefix(detail, "IP："+ip+"；") {
				byIP[ip] = detail
			}
		}
	}
	if len(byIP) != 2 {
		t.Fatalf("逐 IP 审计行=%v, want 两行", byIP)
	}
	if !strings.Contains(byIP[firstIP], "时长：1 小时") {
		t.Fatalf("首封审计时长错位: %q, want 时长：1 小时", byIP[firstIP])
	}
	if !strings.Contains(byIP[repeatIP], "时长：24 小时") {
		t.Fatalf("升档审计必须报实际执法时长 24 小时: %q", byIP[repeatIP])
	}
}

// Given aggressive 升级二次累犯（实际执法永久）+ 配置时长 1h。
// When merge 后写逐 IP 审计。
// Then 时长报「永久」（0 时长=永久的审计口径与配置枚举一致）。
func TestAutobanAuditBanned_escalatedPermanentReportsPermanent(t *testing.T) {
	clock := installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "aggressive"}
	const ip = "45.33.32.72"

	escalationBan(t, cfg, ip)
	clock.Advance(time.Hour + time.Minute)
	escalationSweepExpired(t, cfg)
	clock.Advance(time.Hour)

	out, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: ip, Count: 10}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	autobanAuditBanned(cfg, out)

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='自动封禁' AND detail LIKE 'IP：%' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "时长：永久") {
		t.Fatalf("升档永久审计时长错位: %q, want 时长：永久", detail)
	}
}

// Given 升级关闭（off，固定配置时长）。
// When merge 后写逐 IP 审计。
// Then 时长恒报配置时长（回归形状：固定时长现行行为不变）。
func TestAutobanAuditBanned_offKeepsConfigDuration(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Enabled: true, Threshold: 1, WindowMinutes: 5, Duration: "1h", Scope: "blocked", Escalation: "off"}
	out, err := autobanMergeEntries(cfg, []AutobanSuggestion{{IP: "45.33.32.73", Count: 10}})
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	autobanAuditBanned(cfg, out)

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='自动封禁' AND detail LIKE 'IP：%'`).Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, "时长：1 小时") {
		t.Fatalf("off 档审计时长错位: %q, want 时长：1 小时", detail)
	}
}

// Given 无 merge 结果的直调形态（banned 只有 IP 名单，不携带执法时长）。
// When 写逐 IP 审计。
// Then 回退配置时长（现行口径不变，兼容既有直调调用方）。
func TestAutobanAuditBanned_bareIPsFallBackToConfigDuration(t *testing.T) {
	installAutobanFixture(t, "2026-11-15 10:00:00")
	cfg := AutobanConfig{Threshold: 5, WindowMinutes: 10, Duration: "1h"}
	ips := make([]string, 0, 3)
	for i := 1; i <= 3; i++ {
		ips = append(ips, fmt.Sprintf("45.33.32.%d", i))
	}
	autobanAuditBanned(cfg, autobanMergeOutcome{Banned: ips})

	rows, err := db.AuditDB.Query(`SELECT detail FROM audit_log WHERE action='自动封禁' AND detail LIKE 'IP：%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(detail, "时长：1 小时") {
			t.Fatalf("直调形态审计时长错位: %q, want 时长：1 小时", detail)
		}
		n++
	}
	if n != 3 {
		t.Fatalf("逐 IP 行=%d, want 3", n)
	}
}
