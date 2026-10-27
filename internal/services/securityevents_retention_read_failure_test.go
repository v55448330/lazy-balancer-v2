package services

// 安全事件保留策略读取失败的留痕去重：该读取同时被每日清理与面板轮询消费，
// 裸 warn 会在库故障窗口按请求刷屏——首报 warn、持续静默、恢复一条 info，
// 回退值仍为内置默认（90 天 / 平台默认行帽）。

import (
	"context"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSecurityEventsRetentionReadFailure_warnsOnceAndRecovers(t *testing.T) {
	initServicesDB(t)
	const stateKey = "security-events-retention-read"
	resetLogStateTransitionForTest(stateKey)
	t.Cleanup(func() { resetLogStateTransitionForTest(stateKey) })
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30, security_events_row_cap=1234 WHERE id=1`); err != nil {
		t.Fatalf("seed retention settings: %v", err)
	}
	logs := captureServiceLog(t)

	// Given 配置表不可读（库故障/迁移窗口形态）。
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_unavailable`); err != nil {
		t.Fatalf("simulate read failure: %v", err)
	}

	// When 连续两轮读取（清理轮 + 面板轮询）。
	days, rows := securityEventsRetentionSettings()
	securityEventsRetentionSettings()

	// Then 回退内置默认，且只有一条 warn（去重）。
	if days != securityEventsRetentionDefaultDays || rows != int(securityEventsRetentionDefaultMax) {
		t.Fatalf("read failure policy=(%d,%d), want defaults (%d,%d)", days, rows, securityEventsRetentionDefaultDays, securityEventsRetentionDefaultMax)
	}
	if warns := countLogLines(logs, "security events retention: read retention settings failed"); warns != 1 {
		t.Fatalf("read failure warn lines=%d, want 1（状态转换去重）; logs=%s", warns, logs.String())
	}

	// When 配置恢复可读。
	if _, err := db.DB.Exec(`ALTER TABLE global_config_unavailable RENAME TO global_config`); err != nil {
		t.Fatalf("restore config table: %v", err)
	}
	days, rows = securityEventsRetentionSettings()

	// Then 读到配置值，并补一条恢复 info（仅一次）。
	if days != 30 || rows != 1234 {
		t.Fatalf("recovered policy=(%d,%d), want (30,1234)", days, rows)
	}
	if infos := countLogLines(logs, "security events retention: retention settings read recovered"); infos != 1 {
		t.Fatalf("recovery info lines=%d, want 1; logs=%s", infos, logs.String())
	}
	securityEventsRetentionSettings()
	if infos := countLogLines(logs, "security events retention: retention settings read recovered"); infos != 1 {
		t.Fatalf("持续成功不得重复记恢复，info lines=%d", infos)
	}
}

func TestSecurityEventsRetentionCleanup_readFailureDefersAllDeletion(t *testing.T) {
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=365, security_events_row_cap=2000000 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES (datetime('now', '-120 days'), '198.51.100.10', 'retained')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`ALTER TABLE global_config RENAME TO global_config_unavailable`); err != nil {
		t.Fatal(err)
	}

	result, err := securityEventsRetentionCleanup(context.Background())
	if err == nil {
		t.Fatal("cleanup must fail when the stored retention policy cannot be read")
	}
	if result.Events != 0 || countSecurityEventsByType(t, "retained") != 1 {
		t.Fatalf("read failure deleted history: result=%+v", result)
	}

	if _, err := db.DB.Exec(`ALTER TABLE global_config_unavailable RENAME TO global_config`); err != nil {
		t.Fatal(err)
	}
	if _, err := securityEventsRetentionCleanup(context.Background()); err != nil {
		t.Fatalf("cleanup after recovery: %v", err)
	}
	if got := countSecurityEventsByType(t, "retained"); got != 1 {
		t.Fatalf("event older than default but inside configured retention was deleted: %d", got)
	}
}
