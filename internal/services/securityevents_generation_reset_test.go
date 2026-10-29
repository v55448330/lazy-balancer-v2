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

func useSecurityEventsPollFiles(t *testing.T, logPath, offsetPath string) {
	t.Helper()
	oldLogPath, oldOffsetPath := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	resetSecurityEventsPollState(t)
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath = oldLogPath, oldOffsetPath
	})
}

// 代际复位=整份 audit.log 从头重放（新库为空、每行 RowsAffected=1 全部再喂
// autobanBatch）；自动封禁计数器在内存、不随库重置——不复位则窗口内事件被
// 二次计数、阈值提前达成误封。契约：代际变化复位 offset 的同时清空计数器，
// 由重放按事件时间恰好重建一次。
func TestSecurityEventsGenerationGuard_resetsAutobanCountersOnReplay(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	useSecurityEventsPollFiles(t, logPath, offsetPath)
	setAutobanConfigRaw(t, true, 5, 60, "1h", "all", false)
	oldMaster := autobanIsMaster
	autobanIsMaster = func() bool { return true }
	t.Cleanup(func() { autobanIsMaster = oldMaster })
	ResetAutobanCounters()
	t.Cleanup(ResetAutobanCounters)

	// Given：一条窗口内真实事件和上一代遗留计数；首轮先把遗留 4 推进到 5，
	// 证明夹具确实喂入自动封禁，而不是靠禁用/过期得到零计数。
	const ip = "198.51.100.77"
	fixture := securityEventsLoggedRuleFixture("tx-generation-autoban", ip, "")
	if err := os.WriteFile(logPath, []byte(fixture+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	autobanMu.Lock()
	autobanWindows[ip] = &autobanCounter{Count: 4, WindowStart: time.Now(), LastSeen: time.Now()}
	autobanMu.Unlock()
	ingested, err := SecurityEventsPollOnce()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if ingested != 1 || autobanCountForTest(ip) != 5 {
		t.Fatalf("首轮摄取=%d、计数=%d, want 1、5（重放前置条件）", ingested, autobanCountForTest(ip))
	}

	// When：metrics 库隔离重建后走真实 SecurityEventsPollOnce，代际复位并整份重放。
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
	ingested, err = SecurityEventsPollOnce()

	// Then：计数由本轮真实事件恰好重建一次，不归零，也不叠加旧代计数。
	if err != nil {
		t.Fatalf("replay poll: %v", err)
	}
	if ingested != 1 {
		t.Fatalf("重放摄取=%d, want 1", ingested)
	}
	if got := autobanCountForTest(ip); got != 1 {
		t.Fatalf("重放后自动封禁计数=%d, want 1（单遍真实总量）", got)
	}
}

// 代际重放同样必须复位 messages_dropped 累计：同一份 audit.log 会被从头再解析
// 一遍，每行按其行内 messages_dropped 递增进程级计数——不清零则历史丢弃量被
// 二次累计（健康快照虚高到两倍，排障高估写侧截断规模）。契约：重放后该值等于
// 单遍真实总量。
func TestSecurityEventsGenerationGuard_resetsMessagesDroppedOnReplay(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	useSecurityEventsPollFiles(t, logPath, offsetPath)
	// Given：单条事件披露丢弃 4 条消息，进程计数预置上一代总量 4。
	content := strings.TrimSuffix(securityEventsFixtureBlocked, "}") + `,"messages_dropped":4}` + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsMessagesDropped.Store(4)
	t.Cleanup(func() { securityEventsMessagesDropped.Store(0) })
	ingested, err := SecurityEventsPollOnce()
	if err != nil {
		t.Fatalf("first poll: %v", err)
	}
	if ingested != 1 || securityEventsMessagesDropped.Load() != 8 {
		t.Fatalf("首轮摄取=%d、messages_dropped=%d, want 1、8（重放前置条件）", ingested, securityEventsMessagesDropped.Load())
	}

	// When：metrics 库隔离重建后走真实 SecurityEventsPollOnce 复位并重放。
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
	ingested, err = SecurityEventsPollOnce()

	// Then：重放后的进程计数等于日志单遍真实总量，不是重放前清零后的零或两遍之和。
	if err != nil {
		t.Fatalf("replay poll: %v", err)
	}
	if ingested != 1 {
		t.Fatalf("重放摄取=%d, want 1", ingested)
	}
	if got := securityEventsMessagesDropped.Load(); got != 4 {
		t.Fatalf("重放后 messages_dropped=%d, want 4（单遍真实总量）", got)
	}
}

func TestSecurityEventsMessagesDropped_replayCountsOnlyNewInsert(t *testing.T) {
	logPath, offsetPath := stallSetup(t)
	content := strings.TrimSuffix(securityEventsFixtureBlocked, "}") + `,"messages_dropped":4}` + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	securityEventsMessagesDropped.Store(0)
	t.Cleanup(func() { securityEventsMessagesDropped.Store(0) })
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	if got := securityEventsMessagesDropped.Load(); got != 4 {
		t.Fatalf("first messages_dropped=%d, want 4", got)
	}

	// When：同代 offset 丢失导致整行重放，INSERT OR IGNORE 会忽略既有事件。
	if err := os.Remove(offsetPath); err != nil {
		t.Fatal(err)
	}
	replayed := securityEventsNewTailer(logPath, offsetPath)
	if err := replayed.securityEventsTick(); err != nil {
		t.Fatalf("replay tick: %v", err)
	}

	// Then：忽略行没有产生新的落库事实，健康计数不得翻倍。
	if got := securityEventsMessagesDropped.Load(); got != 4 {
		t.Fatalf("replayed messages_dropped=%d, want 4", got)
	}
}
