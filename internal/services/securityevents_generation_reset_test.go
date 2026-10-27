package services

import (
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// metrics 库被隔离重建（损坏自愈/新库文件）后，摄取 offset 属于旧库代数：
// 沿用旧 offset 会让新库永久跳过文件中段之前的事件。契约：新代际 = 新库
// 语义 → offset 归零从头摄取；同代际重启/空闲 tick 绝不重放。
func TestSecurityEventsTick_resetsOffsetWhenMetricsDBGenerationChanges(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	// Given：三事务审计日志，offset 预置在第一个事务之后（旧库已摄取过前段）。
	content := strings.Join([]string{
		securityEventsFixtureBlocked,
		securityEventsFixtureUnknownHost,
		securityEventsFixtureClean,
	}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	mid := int64(len(securityEventsFixtureBlocked) + 1)
	if err := securityEventsWriteOffset(offsetPath, mid); err != nil {
		t.Fatal(err)
	}

	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if n := stallEventCount(t); n != 2 {
		t.Fatalf("count before rebuild=%d, want 2 (resumed from mid-file offset)", n)
	}

	// When：metrics 库隔离重建——新库文件（新代际），旧库连同其事件一并丢弃。
	oldMetrics := db.MetricsDB
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize rebuilt metrics db: %v", err)
	}
	t.Cleanup(func() {
		if db.MetricsDB != nil && db.MetricsDB != oldMetrics {
			_ = db.MetricsDB.Close()
		}
		db.MetricsDB = oldMetrics
	})
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick after rebuild: %v", err)
	}

	// Then：新库从头摄取全部事务（旧 offset 作废），且旧库事件不可能在新库重放
	// （旧库文件已隔离，新库为空）。
	if n := stallEventCount(t); n != 3 {
		t.Fatalf("count after rebuild=%d, want 3 (fresh library re-ingests from offset 0)", n)
	}
	if !stallHasEvent(t, "tx-blocked-1") {
		t.Fatal("event before the stale offset missing after rebuild (offset not reset)")
	}
	offset, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(len(content) - 1); offset != want {
		t.Fatalf("offset=%d, want %d (end of last document)", offset, want)
	}

	// And：同代际的下一轮 tick 不得重放已入库事件。
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("second tick after rebuild: %v", err)
	}
	if n := stallEventCount(t); n != 3 {
		t.Fatalf("count after idle tick=%d, want 3 (no replay under the same generation)", n)
	}
}

// 代际复位=整份 audit.log 从头重放（新库为空、每行 RowsAffected=1 全部再喂
// autobanBatch）；自动封禁计数器在内存、不随库重置——不复位则窗口内事件被
// 二次计数、阈值提前达成误封。契约：代际变化复位 offset 的同时清空计数器，
// 由重放按事件时间恰好重建一次。
func TestSecurityEventsGenerationGuard_resetsAutobanCountersOnReplay(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	// Given：登记当前代际（首次只见证、不复位），并预置窗口内计数。
	if _, err := tailer.securityEventsGenerationGuard(0); err != nil {
		t.Fatalf("first guard: %v", err)
	}
	ResetAutobanCounters()
	t.Cleanup(ResetAutobanCounters)
	autobanMu.Lock()
	autobanWindows["198.51.100.77"] = &autobanCounter{Count: 4, WindowStart: time.Now(), LastSeen: time.Now()}
	autobanMu.Unlock()

	// When：metrics 库隔离重建（新代际）→ 代际复位。
	oldMetrics := db.MetricsDB
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize rebuilt metrics db: %v", err)
	}
	t.Cleanup(func() {
		if db.MetricsDB != nil && db.MetricsDB != oldMetrics {
			_ = db.MetricsDB.Close()
		}
		db.MetricsDB = oldMetrics
	})
	offset, err := tailer.securityEventsGenerationGuard(4096)

	// Then：offset 归零，且自动封禁计数器随代际复位清空（重放不二次计数）。
	if err != nil {
		t.Fatalf("guard after rebuild: %v", err)
	}
	if offset != 0 {
		t.Fatalf("offset=%d, want 0（代际复位）", offset)
	}
	if got := autobanTrackedCount(); got != 0 {
		t.Fatalf("autoban tracked IPs=%d, want 0（代际重放不得二次喂计数器）", got)
	}
}

// 代际重放同样必须复位 messages_dropped 累计：同一份 audit.log 会被从头再解析
// 一遍，每行按其行内 messages_dropped 递增进程级计数——不清零则历史丢弃量被
// 二次累计（健康快照虚高到两倍，排障高估写侧截断规模）。契约：重放后该值等于
// 单遍真实总量。
func TestSecurityEventsGenerationGuard_resetsMessagesDroppedOnReplay(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	tailer := securityEventsNewTailer(logPath, offsetPath)
	// Given：登记当前代际（首次只见证、不复位），并预置上一代已披露的截断量。
	if _, err := tailer.securityEventsGenerationGuard(0); err != nil {
		t.Fatalf("first guard: %v", err)
	}
	securityEventsMessagesDropped.Store(4)
	t.Cleanup(func() { securityEventsMessagesDropped.Store(0) })

	// When：metrics 库隔离重建（新代际）→ 代际复位 + 整份日志重放。
	oldMetrics := db.MetricsDB
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize rebuilt metrics db: %v", err)
	}
	t.Cleanup(func() {
		if db.MetricsDB != nil && db.MetricsDB != oldMetrics {
			_ = db.MetricsDB.Close()
		}
		db.MetricsDB = oldMetrics
	})
	offset, err := tailer.securityEventsGenerationGuard(4096)

	// Then
	if err != nil {
		t.Fatalf("guard after rebuild: %v", err)
	}
	if offset != 0 {
		t.Fatalf("offset=%d, want 0（代际复位）", offset)
	}
	if got := securityEventsMessagesDropped.Load(); got != 0 {
		t.Fatalf("messages_dropped=%d, want 0（重放前必须清零，否则历史截断量被二次累计）", got)
	}
}
