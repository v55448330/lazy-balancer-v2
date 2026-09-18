package services

import (
	"os"
	"path/filepath"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// SECLB35-1（2026-09-18 第三轮 UI 精修期间实证）：并发/突发请求下 coraza 审计
// 追加对 2s tick 呈现「暂时性中段残缺」（写入进行中的字节，随后补全；实测审计
// 文件最终 192/192 行全部合法）。旧重同步分支「找到下一文档头即跳过」把跳过
// 窗口内随后补全的文档永久丢弃（19 条审计事务仅 11 条落库）。修复语义：解码
// 失败先原地等待重试（偏移不推进），连续 securityEventsDecodeStallLimit 个 tick
// 仍在同一偏移失败才走跳过路径（保留崩溃残片防呆）。
//
// 三测试共享的字节布局模型（单行紧凑 JSON，与 coraza 生产审计同构）：
//	doc1 完整行 → doc2 残缺半行（无换行结尾、JSON 截断）→ 换行 → doc3 完整行。
// 生产事故中该布局由并发事务的审计写入交错产生：残缺行之后存在完整行，
// findNextDocument 能找到后续 "\n{" 文档头，从而触发被测的跳过分支。

const (
	stallFixtureDoc1 = `{"transaction":{"id":"tx-stall-a","unix_timestamp":1789740000,"client_ip":"::1","server_id":"stall.test","request":{"method":"GET","uri":"/a"},"response":{"status":200},"is_interrupted":false},"messages":[]}`
	// 残缺半行：JSON 在 messages 处截断，且行尾无换行（写入进行中）。
	stallFixtureDoc2Partial = `{"transaction":{"id":"tx-stall-b","unix_timestamp":1789740001,"client_ip":"::1","server_id":"stall.test","request":{"method":"GET","uri":"/b"},"response":{"status":200},"is_interrupted":false},"mess`
	// doc2 补全后的完整行（重试路径的终态数据）。
	stallFixtureDoc2Full     = `{"transaction":{"id":"tx-stall-b","unix_timestamp":1789740001,"client_ip":"::1","server_id":"stall.test","request":{"method":"GET","uri":"/b"},"response":{"status":200},"is_interrupted":false},"messages":[]}`
	stallFixtureDoc3         = `{"transaction":{"id":"tx-stall-c","unix_timestamp":1789740002,"client_ip":"::1","server_id":"stall.test","request":{"method":"GET","uri":"/c"},"response":{"status":200},"is_interrupted":false},"messages":[]}`
	stallFixtureDoc2Partial2 = `{"transaction":{"id":"tx-stall-d","unix_timestamp":1789740003,"client_ip":"::1","server_id":"stall.test","request":{"method":"GET","uri":"/d"},"response":{"status":200},"is_interrupted":false},"mess`
)

// stallFixtureBytes 组装布局：doc1\n + doc2Partial + \n + doc3\n。
// 残缺行与后续完整行之间以换行分隔——触发 findNextDocument 找到 doc3 头。
func stallFixtureBytes(doc2, doc3 string) []byte {
	return []byte(stallFixtureDoc1 + "\n" + doc2 + "\n" + doc3 + "\n")
}

func stallSetup(t *testing.T) (logPath, offsetPath string) {
	t.Helper()
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath = filepath.Join(dir, "audit.log")
	offsetPath = filepath.Join(dir, "security_events.offset")
	return logPath, offsetPath
}

func stallEventCount(t *testing.T) int {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func stallHasEvent(t *testing.T, txID string) bool {
	t.Helper()
	var n int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events WHERE transaction_id=?`, txID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n > 0
}

func TestSecurityEventsTick_partialMidFileDocWaitsInsteadOfSkipping(t *testing.T) {
	// Given：doc1 完整 + doc2 残缺半行 + doc3 完整（写入进行中的中间态）。
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, stallFixtureBytes(stallFixtureDoc2Partial, stallFixtureDoc3), 0o644); err != nil {
		t.Fatal(err)
	}
	// 停等偏移 = 残缺文档起点（doc1 行尾换行经空白窗口无害推进后被越过）；
	// 断言关键是「绝不越过残缺文档本体」。
	doc2Start := int64(len(stallFixtureDoc1) + 1)

	// When：一次摄取 tick。
	tickErr := securityEventsNewTailer(logPath, offsetPath).securityEventsTick()

	// Then：doc1 正常入库；偏移停在残缺文档起点（数据未被跳过，等待补写）；
	// doc3 尚未入库（其排在残缺文档之后，等待窗口内不越过）。
	if tickErr == nil {
		t.Fatalf("tick on incomplete mid-file doc should report stall, got nil")
	}
	if !stallHasEvent(t, "tx-stall-a") {
		t.Fatal("doc1 (complete, before the partial doc) must be ingested")
	}
	if stallHasEvent(t, "tx-stall-c") {
		t.Fatal("doc3 must NOT be ingested while the partial doc ahead of it is still incomplete")
	}
	persisted, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if persisted != doc2Start {
		t.Fatalf("persisted offset=%d, want %d (start of the partial doc — never past it; skip would permanently lose it)", persisted, doc2Start)
	}
}

func TestSecurityEventsTick_partialDocCompletedOnRetryIsIngested(t *testing.T) {
	// Given：首 tick 见到 doc2 残缺（同上一测试），随后写入方补全 doc2。
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, stallFixtureBytes(stallFixtureDoc2Partial, stallFixtureDoc3), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err == nil {
		t.Fatal("first tick should stall on the partial doc")
	}
	if err := os.WriteFile(logPath, stallFixtureBytes(stallFixtureDoc2Full, stallFixtureDoc3), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：数据补全后的下一次 tick。
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick after completion: %v", err)
	}

	// Then：doc2、doc3 全部入库，doc1 不重复（transaction_id 幂等）。
	for _, txID := range []string{"tx-stall-a", "tx-stall-b", "tx-stall-c"} {
		if !stallHasEvent(t, txID) {
			t.Fatalf("transaction %s must be ingested after the writer completed it", txID)
		}
	}
	if n := stallEventCount(t); n != 3 {
		t.Fatalf("event count=%d, want 3 (no duplicates)", n)
	}
}

func TestSecurityEventsTick_permanentGarbageSkippedAfterStallLimit(t *testing.T) {
	// Given：doc2 永久残缺（崩溃残片形态——永不补全），doc3 完整排在其后。
	logPath, offsetPath := stallSetup(t)
	if err := os.WriteFile(logPath, stallFixtureBytes(stallFixtureDoc2Partial2, stallFixtureDoc3), 0o644); err != nil {
		t.Fatal(err)
	}
	doc2Start := int64(len(stallFixtureDoc1) + 1)
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When：连续 securityEventsDecodeStallLimit 次 tick（文件不再增长——空闲
	// tick 提前返回被停等状态禁用，每次 tick 都真实重读残缺文档）。
	for i := 1; i <= securityEventsDecodeStallLimit; i++ {
		if err := tailer.securityEventsTick(); err == nil {
			t.Fatalf("tick %d: expected stall error while garbage is within stall limit", i)
		}
		if persisted, err := securityEventsReadOffset(offsetPath); err != nil || persisted != doc2Start {
			t.Fatalf("tick %d: persisted offset=%d err=%v, want %d (staying at the garbage doc)", i, persisted, err, doc2Start)
		}
	}

	// Then：第 securityEventsDecodeStallLimit+1 次 tick 走跳过路径——残缺文档
	// 放弃，其后完整文档恢复摄取（防呆语义保留，只是延迟了限值个 tick）。
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick after stall limit should skip garbage and succeed: %v", err)
	}
	if !stallHasEvent(t, "tx-stall-c") {
		t.Fatal("doc3 (after permanent garbage) must be ingested once the stall limit trips the skip path")
	}
	if stallHasEvent(t, "tx-stall-d") {
		t.Fatal("permanent garbage doc itself must never be ingested")
	}
	if n := stallEventCount(t); n != 2 {
		t.Fatalf("event count=%d, want 2 (doc1 + doc3 only)", n)
	}
}
