package services

import (
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 2026-09-15 用户裁定:指标历史固定保留最近 7 天,不读任何配置项
// (覆盖 S-7 复用「日志保留」的裁定);metrics_retention_days 死列已清退。
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

// 固定 7 天窗口(2026-09-15 用户裁定):8 天前清理、5 天前/当前保留。
func TestMetricsServiceCleanupHistory_usesFixedSevenDayWindow(t *testing.T) {
	// Given：默认配置 + 8 天前/5 天前/当前各 1 行
	setupMetricsRetentionTest(t)
	seedMetricsRow(t, "lb_8d", "-8 days")
	seedMetricsRow(t, "lb_5d", "-5 days")
	seedMetricsRow(t, "lb_now", "")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then：8 天>7 天窗口清,5 天窗口内留
	if got := countMetricsRow(t, "lb_8d"); got != 0 {
		t.Fatalf("8-day row count=%d, want 0（固定 7 天窗口外）", got)
	}
	if got := countMetricsRow(t, "lb_5d"); got != 1 {
		t.Fatalf("5-day row count=%d, want 1（窗口内保留）", got)
	}
	if got := countMetricsRow(t, "lb_now"); got != 1 {
		t.Fatalf("fresh row count=%d, want 1", got)
	}
}

// audit_retention_months=12（=360 天）也不扩窗——固定 7 天(用户裁定:
// 指标类数据独立于日志保留配置)。
func TestMetricsServiceCleanupHistory_ignoresAuditRetentionMonths(t *testing.T) {
	// Given
	setupMetricsRetentionTest(t)
	if _, err := db.DB.Exec("UPDATE global_config SET audit_retention_months=12 WHERE id=1"); err != nil {
		t.Fatalf("set audit retention: %v", err)
	}
	seedMetricsRow(t, "lb_35d", "-35 days")
	seedMetricsRow(t, "lb_5d", "-5 days")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then:audit_retention_months=12 不扩窗——35 天仍按固定 7 天清
	if got := countMetricsRow(t, "lb_35d"); got != 0 {
		t.Fatalf("35-day row count=%d, want 0（固定 7 天窗口,audit_retention_months 不扩窗）", got)
	}
	if got := countMetricsRow(t, "lb_5d"); got != 1 {
		t.Fatalf("5-day row count=%d, want 1（窗口内保留）", got)
	}
}

// audit_retention_months<1 不影响——固定 7 天窗口(不读配置)。
func TestMetricsServiceCleanupHistory_ignoresMonthsBelowOne(t *testing.T) {
	// Given
	setupMetricsRetentionTest(t)
	if _, err := db.DB.Exec("UPDATE global_config SET audit_retention_months=0 WHERE id=1"); err != nil {
		t.Fatalf("set audit retention: %v", err)
	}
	seedMetricsRow(t, "lb_8d", "-8 days")

	// When
	NewMetricsService("", 30).cleanupHistory()

	// Then:固定 7 天窗口清 8 天行,months<1 不回退
	if got := countMetricsRow(t, "lb_8d"); got != 0 {
		t.Fatalf("8-day row count=%d, want 0（固定 7 天窗口,months<1 不回退）", got)
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
	if got := countMetricsRow(t, "lb_20d"); got != 0 {
		t.Fatalf("20-day row count=%d, want 0（固定 7 天窗口;metrics_retention_days 与 audit_retention_months 均不读取）", got)
	}
}
