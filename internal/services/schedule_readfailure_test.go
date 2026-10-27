package services

// 排程/配置读失败必须经 logScheduleReadFailure 单源留痕（首报
// warn + 恢复 info）——自动备份槽位计算与启用源最早槽两处此前静默归零，
// 库故障窗口任务「静默停摆」零信号。

import (
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestScheduleReads_readFailureLeavesWarnTrace(t *testing.T) {
	newClusterTestService(t)
	isolateMetricsState(t)
	if err := db.DB.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	buf := captureLogf(t)

	// 两处读取各失败两次：首报警告各一条，重复不刷屏。
	if _, ok := nextAutoBackupSlot(time.Now()); ok {
		t.Fatal("closed DB must yield no slot")
	}
	nextAutoBackupSlot(time.Now())
	if got := earliestEnabledSourceUpdate("security_threat_sources", nil); got != "" {
		t.Fatalf("closed DB must yield empty earliest slot, got %q", got)
	}
	earliestEnabledSourceUpdate("security_threat_sources", nil)

	out := buf.String()
	if strings.Count(out, "schedule-read-auto-backup") != 1 {
		t.Fatalf("auto-backup schedule read failure warn count wrong\n%s", out)
	}
	if strings.Count(out, "schedule-earliest-security_threat_sources") != 1 {
		t.Fatalf("earliest source read failure warn count wrong\n%s", out)
	}
}

// 启用源最早槽必须按 datetime() 归一后的时间序挑选，而不是原始串 MIN：
// 库内允许 crsTimeLayout（空格）与 RFC3339（T 分隔）双形态（parseUTCSlot
// 明确兼容），字典序会把 "2026-01-02 05:00:00" 排在 "2026-01-02T01:00:00Z"
// 之前，选出的「最早槽」不是真实最早（任务延迟/提前到点）。
func TestEarliestEnabledSourceUpdate_ordersMixedSlotFormats(t *testing.T) {
	newClusterTestService(t)
	if _, err := db.DB.Exec(`INSERT INTO security_threat_sources (name, url, update_enabled, next_update) VALUES
		('space', 'https://a.example/list.txt', 1, '2026-01-02 05:00:00'),
		('rfc', 'https://b.example/list.txt', 1, '2026-01-02T01:00:00Z')`); err != nil {
		t.Fatalf("seed threat sources: %v", err)
	}

	// When
	got := earliestEnabledSourceUpdate("security_threat_sources", nil)

	// Then：真实最早＝01:00Z，且归一为空格形态（crsTimeLayout）
	if want := "2026-01-02 01:00:00"; got != want {
		t.Fatalf("earliest=%q, want %q（按时间序而非字典序）", got, want)
	}
}
