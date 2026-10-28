package services

// 去重表的排他持有期必须与「批次」对齐，而不是整段 pass：跨通道的
// lookup→落库→record 原子性只需要在批内成立（批提交后状态已完整落表），
// 而整段 pass（活文件单轮上限 5 万条/32MiB，归档补采无界）独占会把 IPC 主路径
// 的 2s 预算排在补采之后——超时后写侧按设计整批落 spool（不丢，但实时性丢失、
// spool 增长）。本用例用「逐字节投喂 + 每次 Read 探测锁状态」的方式把持有期
// 变成可观察事实。

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// dedupeLockProbeFile 把审计日志逐字节喂给解析器，并在每次 Read 前探测去重锁
// 是否空闲。探测与 pass 同 goroutine（sleep 无关、无竞态）：TryLock 成功即
// 「此刻未持有」。
type dedupeLockProbeFile struct {
	file *os.File
	// observe 是要探测的去重表（nil=不探测）。
	observe *securityEventsRequestDeduper
	// readChunk 限制单次 Read 返回字节数（1=每字节一次 Read，把「批边界」与
	// 「下一次读取」之间的空隙放大成必然发生的事件）。
	readChunk int
	freeReads int
	heldReads int
}

func (p *dedupeLockProbeFile) Read(b []byte) (int, error) {
	if p.observe != nil {
		if p.observe.mu.TryLock() {
			p.observe.mu.Unlock()
			p.freeReads++
		} else {
			p.heldReads++
		}
	}
	if p.readChunk > 0 && len(b) > p.readChunk {
		b = b[:p.readChunk]
	}
	return p.file.Read(b)
}

func (p *dedupeLockProbeFile) Seek(offset int64, whence int) (int64, error) {
	return p.file.Seek(offset, whence)
}

func (p *dedupeLockProbeFile) Stat() (os.FileInfo, error) { return p.file.Stat() }

// ReadAt 直接透传（本用例的日志走顺序 Read；残缺段重同步路径才会用到它）。
func (p *dedupeLockProbeFile) ReadAt(b []byte, offset int64) (int, error) {
	return p.file.ReadAt(b, offset)
}

func TestSecurityEventsProcessPass_releasesDedupeLockBetweenBatches(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	// 1200 条可去重事件（各自不同请求级计时头→逐条 lookup，不互相归并）：
	// 跨越 500 条/批的批边界两次以上。
	var docs []string
	for i := range 1200 {
		docs = append(docs, securityEventsDedupeFixture(
			fmt.Sprintf("tx-span-%d", i), fmt.Sprintf("span-timing-%d", i),
			fmt.Sprintf("/span/%d", i), "logged", 942100))
	}
	writeSecurityEventsDedupeLog(t, logPath, docs...)
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	logFile, err := os.Open(logPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer logFile.Close()
	tailer := securityEventsNewTailer(logPath, offsetPath)
	probe := &dedupeLockProbeFile{file: logFile, observe: securityEventsSharedDedupe, readChunk: 1}

	// When
	inserted, passErr := tailer.securityEventsProcessPass(context.Background(), probe, 0, rules, bindings, policyByID)

	// Then
	if passErr != nil {
		t.Fatalf("pass: %v", passErr)
	}
	_ = inserted
	if probe.heldReads == 0 {
		t.Fatal("整段 pass 未持有过去重锁——本用例失去鉴别力（去重表必须仍在批内排他）")
	}
	if probe.freeReads == 0 {
		t.Fatalf("整段 pass 独占去重锁（free=%d held=%d）：批提交后必须放锁，否则补采期间 IPC 主路径排队落 spool",
			probe.freeReads, probe.heldReads)
	}
}

// 语义回归：批边界放锁不得破坏「一批内同一请求的后续引擎事务归并为一条」。
func TestSecurityEventsProcessPass_stillMergesWithinBatchAcrossLockRelease(t *testing.T) {
	logPath, offsetPath := seedSecurityEventsDedupeDB(t)
	// 前 499 条互不相关的请求，把「同一请求的两个引擎事务」推到批边界两侧。
	var docs []string
	for i := range 499 {
		docs = append(docs, securityEventsDedupeFixture(
			fmt.Sprintf("tx-filler-%d", i), fmt.Sprintf("filler-timing-%d", i),
			fmt.Sprintf("/filler/%d", i), "logged", 942100))
	}
	docs = append(docs,
		securityEventsDedupeFixture("tx-split-a", "split-timing", "/split", "logged", 942100),
		securityEventsDedupeFixture("tx-split-b", "split-timing", "/split", "blocked", 942100),
	)
	writeSecurityEventsDedupeLog(t, logPath, strings.Join(docs, "\n")+"\n")
	runSecurityEventsDedupeTick(t, securityEventsNewTailer(logPath, offsetPath))

	rows := readDedupeSplitRows(t)
	if len(rows) != 500 {
		t.Fatalf("rows=%d, want 500（同一请求的两次引擎事务必须归并为一条）", len(rows))
	}
	if rows[499].action != "blocked" || rows[499].transactionID == "" {
		t.Fatalf("split row action=%q tx=%q, want blocked 且保留首次落库行", rows[499].action, rows[499].transactionID)
	}
}

type dedupeSplitRow struct {
	action        string
	transactionID string
}

func readDedupeSplitRows(t *testing.T) []dedupeSplitRow {
	t.Helper()
	rows, err := db.MetricsDB.Query(`SELECT action, COALESCE(transaction_id, '') FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatalf("query events: %v", err)
	}
	defer rows.Close()
	var out []dedupeSplitRow
	for rows.Next() {
		var row dedupeSplitRow
		if err := rows.Scan(&row.action, &row.transactionID); err != nil {
			t.Fatalf("scan event row: %v", err)
		}
		out = append(out, row)
	}
	return out
}
