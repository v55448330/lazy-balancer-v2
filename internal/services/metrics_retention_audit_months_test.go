package services

import (
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 2026-09-15 用户裁定:指标历史固定保留最近 7 天,不读任何配置项
// (覆盖复用「日志保留」的裁定);metrics_retention_days 死列已清退。
func setupMetricsRetentionTest(t *testing.T) {
	t.Helper()
	// 复用单源隔离夹具：四句柄（含 db.GetDB 原子句柄）成对保存/还原。
	setupIsolatedDBWithMetrics(t)
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

// seedMetricsRowModifiers 以多个 SQLite 时间修饰符落一行
// （datetime('now','-7 days','+1 second')）：边界行需要「整窗 + 偏移」组合，
// 单个修饰符表达不出来。
func seedMetricsRowModifiers(t *testing.T, ruleID string, modifiers ...string) {
	t.Helper()
	placeholders := make([]string, 0, len(modifiers))
	args := []any{ruleID}
	for _, modifier := range modifiers {
		placeholders = append(placeholders, "?")
		args = append(args, modifier)
	}
	query := "INSERT INTO metrics_history (rule_id, timestamp) VALUES (?, datetime('now'"
	if len(placeholders) > 0 {
		query += ", " + strings.Join(placeholders, ", ")
	}
	query += "))"
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

// 7 天窗口的裁剪边界与时区口径：cutoff 必须按 UTC 计算。用「整窗 ∓1 秒」
// 两行把窗口边沿夹住——8 天/5 天的宽边距对半天级偏差与时区偏移（如 +8h）
// 没有分辨力。两种面板时区下各跑一遍：切到 Asia/Shanghai 时若实现改用本地
// 时区算 cutoff，边界行会翻转。
func TestMetricsServiceCleanupHistory_sevenDayBoundaryIsUTCBased(t *testing.T) {
	for _, zone := range []string{"UTC", "Asia/Shanghai"} {
		t.Run(zone, func(t *testing.T) {
			setupMetricsRetentionTest(t)
			previous := CurrentLocation()
			if _, err := ConfigureLocation(zone); err != nil {
				t.Fatalf("configure location %s: %v", zone, err)
			}
			t.Cleanup(func() { _, _ = ConfigureLocation(previous.String()) })

			seedMetricsRowModifiers(t, "lb_just_outside", "-7 days", "-1 second")
			seedMetricsRowModifiers(t, "lb_just_inside", "-7 days", "+1 second")

			NewMetricsService("", 30).cleanupHistory()

			if got := countMetricsRow(t, "lb_just_outside"); got != 0 {
				t.Fatalf("7 天减 1 秒的行 count=%d, want 0（窗口外必须删除）", got)
			}
			if got := countMetricsRow(t, "lb_just_inside"); got != 1 {
				t.Fatalf("7 天加 1 秒的行 count=%d, want 1（窗口内必须保留）", got)
			}
		})
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
// audit_retention_months 保持默认 3（=90 天）——20 天前的行仍按固定 7 天窗口
// 删除。若实现回退到读 audit_retention_months（90 天窗口）该行会被保留
// （RED 判据）；证明清理对两个配置键均不消费。
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

	// Then：固定 7 天窗口清理——audit_retention_months 与死列值均不读取
	if got := countMetricsRow(t, "lb_20d"); got != 0 {
		t.Fatalf("20-day row count=%d, want 0（固定 7 天窗口;metrics_retention_days 与 audit_retention_months 均不读取）", got)
	}
}
