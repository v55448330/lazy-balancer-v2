package services

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func setupSecurityEventsRetentionTestDB(t *testing.T) {
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

func countSecurityEventsByType(t *testing.T, eventType string) int {
	t.Helper()
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE event_type=?`, eventType).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func TestSecurityEventsRetentionCleanup_deletesEventsOlderThanConfiguredDays(t *testing.T) {
	// Given: a 30-day retention window and events older and newer than the cutoff
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-40 days'), '198.51.100.1', 'expired'),
		(datetime('now', '-1 day'), '198.51.100.2', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup()

	// Then: the expired event is gone, the recent one survives
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
}

func TestSecurityEventsRetentionCleanup_trimsOldestRowsWhenCountExceedsMax(t *testing.T) {
	// Given: a wide age window (120 months) and 5 recent events
	// The hardcoded safety max (100000) means count-based trim won't fire for 5 rows.
	// This test now verifies that with a wide age window, all events survive.
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=120 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip) VALUES (datetime('now'), ?)`,
			fmt.Sprintf("198.51.100.%d", i)); err != nil {
			t.Fatal(err)
		}
	}

	// When
	securityEventsRetentionCleanup()

	// Then: all 5 events survive (safety max not reached)
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 5 {
		t.Fatalf("events after cleanup = %d, want 5 (safety max not reached)", count)
	}
}

func TestSecurityEventsRetentionSettings_appliesDefaultsWhenZero(t *testing.T) {
	// Given: non-positive retention values stored in global_config
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When
	days, max := securityEventsRetentionSettings()

	// Then: the documented defaults apply
	if days != 30 || max != 100000 {
		t.Fatalf("settings = (%d, %d), want (30, 100000)", days, max)
	}
}

func TestSecurityEventsRetentionCleanup_usesDefaultDaysWhenConfigZero(t *testing.T) {
	// Given: zeroed retention config and events straddling the default 30-day window
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-31 days'), '198.51.100.1', 'expired'),
		(datetime('now', '-29 days'), '198.51.100.2', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup()

	// Then: the default 30-day window deleted the 31-day-old event only
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
}

func TestStartSecurityEventsRetention_idempotentAndAlwaysRunning(t *testing.T) {
	// R69 REMOVE 后的契约锁定：worker 生命周期由 main.go 单点拥有——重复启动
	// 幂等（不重启 worker）；不存在任何「停止」生产路径（从节点也摄入事件，
	// 停止会致事件表越过 10 万行上限无界增长，R62 B-NEW-2 确立的设计语义）。
	setupSecurityEventsRetentionTestDB(t)
	t.Cleanup(securityEventsRetentionStop)
	workerDone := func() chan struct{} {
		securityEventsRetentionMu.Lock()
		defer securityEventsRetentionMu.Unlock()
		return securityEventsRetentionDone
	}

	StartSecurityEventsRetention(context.Background())
	first := workerDone()
	if first == nil {
		t.Fatal("StartSecurityEventsRetention must start the retention worker")
	}
	StartSecurityEventsRetention(context.Background())
	if second := workerDone(); second != first {
		t.Fatal("repeated start must not restart the retention worker")
	}
	select {
	case <-first:
		t.Fatal("worker must keep running（无停止路径是设计语义）")
	default:
	}
}

func TestStartSecurityEventsRetention_stopsWhenParentContextCanceled(t *testing.T) {
	// Given: a worker bound to a cancelable parent context
	setupSecurityEventsRetentionTestDB(t)
	t.Cleanup(securityEventsRetentionStop)
	ctx, cancel := context.WithCancel(context.Background())
	StartSecurityEventsRetention(ctx)
	securityEventsRetentionMu.Lock()
	done := securityEventsRetentionDone
	securityEventsRetentionMu.Unlock()
	if done == nil {
		t.Fatal("worker did not publish its completion channel")
	}

	// When
	cancel()

	// Then: the worker exits and clears its state so a restart is possible
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker must stop when the parent context is canceled")
	}
	securityEventsRetentionMu.Lock()
	cleared := securityEventsRetentionDone == nil
	securityEventsRetentionMu.Unlock()
	if !cleared {
		t.Fatal("worker state must be cleared after parent context cancellation")
	}
	StartSecurityEventsRetention(context.Background())
	securityEventsRetentionMu.Lock()
	restarted := securityEventsRetentionDone != nil
	securityEventsRetentionMu.Unlock()
	if !restarted {
		t.Fatal("worker must be restartable after parent context cancellation")
	}
}

func TestSecurityEventsRetentionCleanup_batchesAgeDelete(t *testing.T) {
	// Given: 12000 expired events（超过单批 5000，必须分批循环）+ 1 条近期事件
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=1 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	for start := 0; start < 12000; start += 1000 {
		sb.Reset()
		sb.WriteString("INSERT INTO security_events (event_time, client_ip, event_type) VALUES ")
		for i := 0; i < 1000; i++ {
			if i > 0 {
				sb.WriteString(", ")
			}
			fmt.Fprintf(&sb, "(datetime('now', '-40 days'), '198.51.100.%d', 'expired')", (start+i)%250)
		}
		if _, err := db.MetricsDB.Exec(sb.String()); err != nil {
			t.Fatalf("seed expired batch: %v", err)
		}
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES (datetime('now'), '198.51.100.250', 'recent')`); err != nil {
		t.Fatal(err)
	}

	// When
	securityEventsRetentionCleanup()

	// Then：全部过期事件被分批删除，近期事件保留
	if got := countSecurityEventsByType(t, "expired"); got != 0 {
		t.Fatalf("expired events after cleanup = %d, want 0", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("recent events after cleanup = %d, want 1", got)
	}
}
