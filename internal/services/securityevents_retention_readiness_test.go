package services

// 保留清理的「就绪判据读失败」分支（securityevents_retention.go:229 附近）：
// 预聚合就绪状态读不到（metrics_state 表损坏/不可读）时必须**当作未就绪**并
// 让任务失败，绝不能 fail-open 继续按年龄/行帽删除——删掉的是不可再生的原始
// 事件，而任务摘要还会显示「清理完成」。
//
// 此前该分支零钉测：把 `perr != nil` 改成恒假（读失败按就绪继续删）后整组
// 保留清理用例仍然全绿。本用例制造真实的
// 读失败（DROP TABLE metrics_state），同时钉住四件事：返回错误、两个 Deferred
// 置真、过期事件仍在、错误文案点名就绪判据（任务体据此落 task_runs.failed）。

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestSecurityEventsRetentionCleanup_readinessProbeFailureFailsTask(t *testing.T) {
	// Given：30 天保留期 + 一条超期事件 + 一条近期事件，且就绪判据读失败。
	setupSecurityEventsRetentionTestDB(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
		(datetime('now', '-40 days'), '198.51.100.11', 'expired'),
		(datetime('now', '-1 day'), '198.51.100.12', 'recent')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.MetricsDB.Exec(`DROP TABLE metrics_state`); err != nil {
		t.Fatalf("drop metrics_state（制造就绪判据读失败）: %v", err)
	}

	// When
	result, err := SecurityEventsRetentionCleanupDetail(context.Background())

	// Then：任务必须失败（taskengine_wire 的任务体直接把 err 上抛 → task_runs
	// 落 failed 并退避重试），两个删除阶段都必须显式顺延。
	if err == nil {
		t.Fatalf("就绪判据读失败必须返回错误（否则任务落 success，排障方向被带偏）: result=%+v", result)
	}
	if !strings.Contains(err.Error(), "读取预聚合就绪状态失败") {
		t.Fatalf("error=%v, want 点名就绪判据（失败可归因）", err)
	}
	if !result.AgeDeferred || !result.RowCapDeferred {
		t.Fatalf("result=%+v, want AgeDeferred && RowCapDeferred（未知就绪态不得删除）", result)
	}
	if got := countSecurityEventsByType(t, "expired"); got != 1 {
		t.Fatalf("过期事件=%d, want 1（就绪态未知时不得删除不可再生历史）", got)
	}
	if got := countSecurityEventsByType(t, "recent"); got != 1 {
		t.Fatalf("近期事件=%d, want 1（本轮不应有任何删除）", got)
	}
	if result.Events != 0 || result.Aggregates() != 0 {
		t.Fatalf("result=%+v, want 零删除计数", result)
	}
}

func TestSecurityEventsRetentionCleanup_emptyRebuildMarkerDefersDeletion(t *testing.T) {
	for _, value := range []string{"", "   "} {
		t.Run(fmt.Sprintf("value_%q", value), func(t *testing.T) {
			// Given：重建意图键存在但值损坏为空，其余就绪键齐全。
			setupSecurityEventsRetentionTestDB(t)
			seedRollupReadyState(t)
			if _, err := db.DB.Exec(`UPDATE global_config SET security_events_retention_days=30 WHERE id=1`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, event_type) VALUES
				(datetime('now', '-40 days'), '198.51.100.11', 'expired')`); err != nil {
				t.Fatal(err)
			}
			if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_state (key,value) VALUES (?,?)`, ThreatRollupRebuildFromKey, value); err != nil {
				t.Fatal(err)
			}

			// When
			result, err := SecurityEventsRetentionCleanupDetail(context.Background())

			// Then：存在即 pending，空值不是「无重建意图」，不得删除原始事件。
			if err != nil {
				t.Fatal(err)
			}
			if !result.AgeDeferred || !result.RowCapDeferred {
				t.Fatalf("result=%+v, want both trims deferred for present empty rebuild key", result)
			}
			if got := countSecurityEventsByType(t, "expired"); got != 1 {
				t.Fatalf("expired events=%d, want 1 (raw events must survive damaged rebuild state)", got)
			}
		})
	}
}
