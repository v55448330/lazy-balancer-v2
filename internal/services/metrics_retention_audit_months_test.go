package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// S-7（2026-09-06 裁定）：指标历史保留期复用「日志保留」配置项
// audit_retention_months（与操作/运行/安全事件同源同义），按 months×30 天清理；
// 独立的 metrics_retention_days 不再读取（死配置随 S-6 先例清退）。
func setupMetricsRetentionTest(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
}

func seedMetricsRow(t *testing.T, ruleID, ageModifier string) {
	t.Helper()
	query := "INSERT INTO metrics_history (rule_id, timestamp) VALUES (?, datetime('now'))"
	args := []any{ruleID}
	if ageModifier != "" {
		// datetime('now','')/datetime('now','now') 返回 NULL（modifier 语义），
		// 仅非空 modifier 才走双参形式。
		query = "INSERT INTO metrics_history (rule_id, timestamp) VALUES (?, datetime('now', ?))"
		args = append(args, ageModifier)
	}
	if _, err := db.MetricsDB.Exec(query, args...); err != nil {
		t.Fatalf("seed metrics history %s: %v", ruleID, err)
	}
}

func countMetricsRow(t *testing.T, ruleID string) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow("SELECT COUNT(*) FROM metrics_history WHERE rule_id=?", ruleID).Scan(&n); err != nil {
		t.Fatalf("count metrics history %s: %v", ruleID, err)
	}
	return n
}

// 默认 audit_retention_months=3（=90 天窗口）：45 天前的行仍在保留期内、不得
// 清理（旧实现按 metrics_retention_days 默认 7 天会将其删除——本用例即 RED 判据）。
func TestMetricsServiceCleanupHistory_usesAuditRetentionMonthsDefaultWindow(t *testing.T) {
	// Given：默认配置（audit_retention_months schema 默认 3）+ 45 天前与当前各 1 行
	setupMetricsRetentionTest(t)
	seedMetricsRow(t, "lb_45d", "-45 days")
	seedMetricsRow(t, "lb_now", "")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：45 天 < 90 天窗口，保留
	if got := countMetricsRow(t, "lb_45d"); got != 1 {
		t.Fatalf("45-day row count=%d, want 1（audit_retention_months=3 ⇒ 90 天窗口内不得清理）", got)
	}
	if got := countMetricsRow(t, "lb_now"); got != 1 {
		t.Fatalf("fresh row count=%d, want 1", got)
	}
}

// audit_retention_months=1（=30 天窗口）：窗口外删除、窗口内保留。
func TestMetricsServiceCleanupHistory_deletesBeyondConfiguredMonths(t *testing.T) {
	// Given
	setupMetricsRetentionTest(t)
	if _, err := db.DB.Exec("UPDATE global_config SET audit_retention_months=1 WHERE id=1"); err != nil {
		t.Fatalf("set audit retention: %v", err)
	}
	seedMetricsRow(t, "lb_35d", "-35 days")
	seedMetricsRow(t, "lb_5d", "-5 days")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then
	if got := countMetricsRow(t, "lb_35d"); got != 0 {
		t.Fatalf("35-day row count=%d, want 0（1 个月=30 天窗口外）", got)
	}
	if got := countMetricsRow(t, "lb_5d"); got != 1 {
		t.Fatalf("5-day row count=%d, want 1（窗口内保留）", got)
	}
}

// audit_retention_months<1 回退默认 3（对齐 CleanupAuditLogs 的回退语义）。
func TestMetricsServiceCleanupHistory_fallsBackWhenMonthsBelowOne(t *testing.T) {
	// Given
	setupMetricsRetentionTest(t)
	if _, err := db.DB.Exec("UPDATE global_config SET audit_retention_months=0 WHERE id=1"); err != nil {
		t.Fatalf("set audit retention: %v", err)
	}
	seedMetricsRow(t, "lb_45d", "-45 days")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：按回退 3 个月（90 天）执行，45 天行保留
	if got := countMetricsRow(t, "lb_45d"); got != 1 {
		t.Fatalf("45-day row count=%d, want 1（months<1 回退 3 个月）", got)
	}
}

// 死配置不再读取：手动补回 metrics_retention_days 列并设 1（模拟存量库残留），
// audit_retention_months=3 ⇒ 90 天窗口，20 天前的行必须保留——旧实现按
// metrics_retention_days=1 会将其删除（RED 判据），证明清理不再消费该键。
func TestMetricsServiceCleanupHistory_ignoresDeadMetricsRetentionDaysColumn(t *testing.T) {
	// Given：补回死列并塞入激进值 1 天
	setupMetricsRetentionTest(t)
	if _, err := db.DB.Exec(`ALTER TABLE global_config ADD COLUMN metrics_retention_days INTEGER DEFAULT 7;
		UPDATE global_config SET metrics_retention_days=1 WHERE id=1`); err != nil {
		t.Fatalf("seed dead column: %v", err)
	}
	seedMetricsRow(t, "lb_20d", "-20 days")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：仅按 audit_retention_months（默认 3 个月=90 天）清理，死列值不生效
	if got := countMetricsRow(t, "lb_20d"); got != 1 {
		t.Fatalf("20-day row count=%d, want 1（metrics_retention_days 不得再被读取）", got)
	}
}
