package handlers

// 仅含保留/私网地址的分钟：主 rollup 固化期排除这些行（newTotal=0），但总览
// 两表口径包含它们（7 日趋势/Top IP 数据源）。旧实现 newTotal==0&&oldTotal==0
// 提前返回，整分钟总览静默少计。

import (
	"testing"
	"time"
)

func TestThreatOverviewRollup_reservedOnlyMinuteStillWritesOverview(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	m := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	minute := m.Format(threatRewindMinuteLayout)
	eventTime := m.Format("2006-01-02 15:04:05")
	seedThreatScreenEvent(t, eventTime, "127.0.0.1", "942100", "SQL Injection", "blocked")
	seedThreatScreenEvent(t, eventTime, "10.0.0.8", "942100", "SQL Injection", "blocked")

	fixThreatOverviewMinute(t, m, false)

	// 主 rollup：保留/私网地址固化期排除 → 0。
	if got := threatRollupCountForMinute(t, minute); got != 0 {
		t.Fatalf("主 rollup 总量=%d, want 0（保留/私网地址不计主聚合）", got)
	}
	// 总览：必须包含这些行（旧实现早退 → 0）。
	if total := overviewIPTotalForMinute(t, minute); total != 2 {
		t.Fatalf("总览 IP 维度总量=%d, want 2（仅保留地址分钟的 overview 不得被早退跳过）", total)
	}
	if got := overviewIPCountFor(t, minute, "127.0.0.1", "blocked"); got != 1 {
		t.Fatalf("保留地址 127.0.0.1 计数=%d, want 1", got)
	}
	if got := overviewIPCountFor(t, minute, "10.0.0.8", "blocked"); got != 1 {
		t.Fatalf("私网地址 10.0.0.8 计数=%d, want 1", got)
	}

	// 增量轮不得清空已固化总览。
	fixThreatOverviewMinute(t, m, false)
	if total := overviewIPTotalForMinute(t, minute); total != 2 {
		t.Fatalf("增量轮后总览总量=%d, want 2（不得被空差量路径清除）", total)
	}
}
