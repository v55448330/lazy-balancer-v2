package services

// metrics_history 孤儿行收敛清理（taskengine metrics-orphan-cleanup
// 任务体）钉测试。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"sync"
	"testing"

	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
)

func seedMetricsHistory(t *testing.T, ruleID any, requests int) {
	t.Helper()
	if _, err := db.MetricsDB.Exec(`INSERT INTO metrics_history (rule_id, timestamp, requests_total) VALUES (?, datetime('now'), ?)`, ruleID, requests); err != nil {
		t.Fatalf("seed metrics_history(%v): %v", ruleID, err)
	}
}

func countMetricsHistory(t *testing.T, where string, args ...any) int {
	t.Helper()
	var count int
	query := `SELECT COUNT(*) FROM metrics_history`
	if where != "" {
		query += " WHERE " + where
	}
	if err := db.MetricsDB.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatalf("count metrics_history: %v", err)
	}
	return count
}

// Given 存活规则指标 + 已删除规则残留指标 + 全局(NULL rule_id)指标。
// When 执行孤儿清理。
// Then 仅残留行被删；存活规则与全局行保留；返回删除的规则数。
func TestPurgeOrphanMetricsHistory_deletesOrphansKeepsLiveAndGlobal(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port,enabled) VALUES ('lb_live','live','http',18091,1)`); err != nil {
		t.Fatalf("seed live rule: %v", err)
	}
	seedMetricsHistory(t, "lb_live", 3)
	seedMetricsHistory(t, "lb_orphan", 4)
	seedMetricsHistory(t, "lb_orphan", 5)
	seedMetricsHistory(t, nil, 6)

	// When
	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())

	// Then
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deletedRules != 1 {
		t.Fatalf("deletedRules=%d, want 1", deletedRules)
	}
	if got := countMetricsHistory(t, "rule_id='lb_orphan'"); got != 0 {
		t.Fatalf("孤儿行残留=%d, want 0", got)
	}
	if got := countMetricsHistory(t, "rule_id='lb_live'"); got != 1 {
		t.Fatalf("存活规则行=%d, want 1（不得误删）", got)
	}
	if got := countMetricsHistory(t, "rule_id IS NULL"); got != 1 {
		t.Fatalf("全局(NULL)行=%d, want 1（不得误删）", got)
	}
}

// Given 孤儿行数超过单轮上限。
// When 连续两轮执行。
// Then 首轮只删上限数（有界），次轮收敛余量——重试有界且最终收敛。
func TestPurgeOrphanMetricsHistory_boundedPerRun(t *testing.T) {
	_, database := newClusterTestService(t)
	_ = database
	for _, ruleID := range []string{"lb_o1", "lb_o2", "lb_o3"} {
		seedMetricsHistory(t, ruleID, 1)
	}
	previous := metricsOrphanPurgeRulesPerRun
	metricsOrphanPurgeRulesPerRun = 2
	t.Cleanup(func() { metricsOrphanPurgeRulesPerRun = previous })

	// When
	firstRun, err := PurgeOrphanMetricsHistory(t.Context())
	if err != nil {
		t.Fatalf("purge round 1: %v", err)
	}
	secondRun, err := PurgeOrphanMetricsHistory(t.Context())
	if err != nil {
		t.Fatalf("purge round 2: %v", err)
	}

	// Then
	if firstRun != 2 {
		t.Fatalf("首轮删除规则数=%d, want 2（单轮有界）", firstRun)
	}
	if secondRun != 1 {
		t.Fatalf("次轮删除规则数=%d, want 1（收敛余量）", secondRun)
	}
	if got := countMetricsHistory(t, "rule_id IS NOT NULL"); got != 0 {
		t.Fatalf("孤儿行残留=%d, want 0", got)
	}
}

// Given 单条孤儿规则的行数超过单条 DELETE 行预算。
// When 执行孤儿清理。
// Then 删除按 rowid 分批执行（语句数 >1），全部行仍被清空，存活/全局行不受
// 影响——批大小只限制单事务行数，不改变收敛结果。
func TestPurgeOrphanMetricsHistory_batchesRowsPerDelete(t *testing.T) {
	_, _ = newClusterTestService(t)
	const rows = 12
	for range rows {
		seedMetricsHistory(t, "lb_big_orphan", 1)
	}
	seedMetricsHistory(t, nil, 9)
	previousBatch := metricsOrphanPurgeRowsPerBatch
	metricsOrphanPurgeRowsPerBatch = 5
	t.Cleanup(func() { metricsOrphanPurgeRowsPerBatch = previousBatch })

	counter, restore := wrapMetricsDBWithDeleteCounter(t)
	t.Cleanup(restore)

	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if deletedRules != 1 {
		t.Fatalf("deletedRules=%d, want 1", deletedRules)
	}
	if got := countMetricsHistory(t, "rule_id='lb_big_orphan'"); got != 0 {
		t.Fatalf("孤儿行残留=%d, want 0（分批必须收敛）", got)
	}
	if got := countMetricsHistory(t, "rule_id IS NULL"); got != 1 {
		t.Fatalf("全局(NULL)行=%d, want 1（不得误删）", got)
	}
	// 12 行 / 批大小 5 = 3 条 DELETE（单条 IN 形态只有 1 条 → RED）。
	if got := counter.count(); got < 3 {
		t.Fatalf("DELETE 语句数=%d, want >=3（必须按行分批，单条大事务会阻塞指标写入）", got)
	}
}

// Given 单规则孤儿行跨多条 DELETE 批，第一批执行完成后 metrics 库句柄被关停
// 置 nil（关停排空超时后 db.Close 执行，在途轮仍在下一批）。
// When 执行孤儿清理。
// Then 返回可见错误而非 nil 解引用 panic；已删除批次不可逆，规则未清空不计入。
func TestPurgeOrphanMetricsHistory_metricsDBClosedMidRunDoesNotPanic(t *testing.T) {
	_, _ = newClusterTestService(t)
	const rows = 12
	for range rows {
		seedMetricsHistory(t, "lb_shutdown_orphan", 1)
	}
	previousBatch := metricsOrphanPurgeRowsPerBatch
	metricsOrphanPurgeRowsPerBatch = 5
	t.Cleanup(func() { metricsOrphanPurgeRowsPerBatch = previousBatch })

	counter, restore := wrapMetricsDBWithDeleteCounter(t)
	t.Cleanup(restore)
	counter.afterExec = func(n int) {
		if n == 1 {
			db.MetricsDB = nil // 关停尾部 db.Close() 的等价形态
		}
	}

	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())

	if err == nil {
		t.Fatal("metrics 库关停后必须返回错误（任务落 failed），不得静默成功")
	}
	if deletedRules != 0 {
		t.Fatalf("deletedRules=%d, want 0（未清空的规则不得计入）", deletedRules)
	}
}

// Given 孤儿规则在本批即被清空（deleted < batch），该批 DELETE 完成后 ctx 已被取消
// （任务取消/关停）。
// When 执行孤儿清理。
// Then 返回真实部分计数 + ctx 错误——清空最后一条后仍以取消态收尾，不得报成功。
func TestPurgeOrphanMetricsHistory_cancelAfterFinalBatchReturnsContextError(t *testing.T) {
	_, _ = newClusterTestService(t)
	seedMetricsHistory(t, "lb_cancel_orphan", 1)
	counter, restore := wrapMetricsDBWithDeleteCounter(t)
	t.Cleanup(restore)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	counter.afterExec = func(n int) {
		if n == 1 {
			cancel()
		}
	}

	deletedRules, err := PurgeOrphanMetricsHistory(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got %v", err)
	}
	if deletedRules != 1 {
		t.Fatalf("deletedRules=%d, want 1（已清空的规则须计入真实部分计数）", deletedRules)
	}
}

// deleteCountingProbe 统计 metrics_history DELETE 语句数（Prepare 面覆盖
// ExecContext 回退路径：包装 conn 只暴露 driver.Conn 基础接口）。
type deleteCountingProbe struct {
	mu      sync.Mutex
	deletes int
	// failAfter >0 时第 failAfter+1 条 DELETE 起注入错误（钉失败路径的
	// 部分计数：已完整清空的规则数必须如实返回）。
	failAfter int
	// afterExec 在第 n 条 DELETE 执行完成后回调（关停窗口注入点：句柄置
	// nil / ctx 取消发生在批与批之间，而不是语句执行之前）。
	afterExec func(n int)
	// match 是计入的目标表名（空=metrics_history）：同一条注入缝供指标孤儿
	// 清理与审计保留清理两族共用（两族都是「每批重读句柄 + 批间复检 ctx」）。
	match string
}

func (p *deleteCountingProbe) record(query string) int {
	table := p.match
	if table == "" {
		table = "metrics_history"
	}
	if !strings.Contains(strings.ToLower(query), "delete from "+table) {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deletes++
	return p.deletes
}

func (p *deleteCountingProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.deletes
}

type deleteCountingConnector struct {
	dsn   string
	inner driver.Driver
	probe *deleteCountingProbe
}

func (c deleteCountingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &deleteCountingConn{Conn: conn, probe: c.probe}, nil
}

func (c deleteCountingConnector) Driver() driver.Driver { return c.inner }

type deleteCountingConn struct {
	driver.Conn
	probe *deleteCountingProbe
}

func (c *deleteCountingConn) Prepare(query string) (driver.Stmt, error) {
	n := c.probe.record(query)
	if n > 0 && c.probe.failAfter > 0 && n > c.probe.failAfter {
		return nil, errors.New("injected delete failure")
	}
	stmt, err := c.Conn.Prepare(query)
	if err != nil {
		return nil, err
	}
	return &deleteCountingStmt{Stmt: stmt, probe: c.probe, index: n}, nil
}

// deleteCountingStmt 只在 driver.Stmt 基础接口上再包一层 Exec：不实现
// StmtExecContext，保持 database/sql 的「Prepare+Exec」回退路径（与上面
// 计数面同一条路径），从而能在语句真正执行完成后回调。
type deleteCountingStmt struct {
	driver.Stmt
	probe *deleteCountingProbe
	index int
}

func (s *deleteCountingStmt) Exec(args []driver.Value) (driver.Result, error) {
	result, err := s.Stmt.Exec(args)
	if s.probe.afterExec != nil {
		s.probe.afterExec(s.index)
	}
	return result, err
}

// wrapMetricsDBWithDeleteCounter 用同一 metrics 库文件挂计数包装句柄。
func wrapMetricsDBWithDeleteCounter(t *testing.T) (*deleteCountingProbe, func()) {
	t.Helper()
	var seq int
	var name, file string
	if err := db.MetricsDB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("read metrics db path: %v", err)
	}
	if file == "" {
		t.Fatal("metrics 测试库不是文件库，无法附加计数句柄")
	}
	previous := db.MetricsDB
	probe := &deleteCountingProbe{}
	wrapped := sql.OpenDB(deleteCountingConnector{
		dsn:   file + "?_pragma=busy_timeout(30000)",
		inner: &sqlitedriver.Driver{},
		probe: probe,
	})
	db.MetricsDB = wrapped
	return probe, func() {
		_ = wrapped.Close()
		db.MetricsDB = previous
	}
}

// Given metrics 库不可用。
// When 执行孤儿清理。
// Then 错误显式上抛（task_runs 落 failed），不得假成功。
func TestPurgeOrphanMetricsHistory_surfacesMetricsDBError(t *testing.T) {
	_, _ = newClusterTestService(t)
	broken, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open scratch metrics db: %v", err)
	}
	if err := broken.Close(); err != nil {
		t.Fatalf("close scratch metrics db: %v", err)
	}
	previous := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = previous })

	if _, err := PurgeOrphanMetricsHistory(t.Context()); err == nil {
		t.Fatal("metrics 库不可用时必须返回错误（task_runs 落 failed），不得静默成功")
	}
}

// Given 两条孤儿规则、第二条规则的 DELETE 注入失败。When 执行清理。
// Then 错误上抛且返回真实的部分计数（1 条规则已完整清空）——任务日志的
// 「本轮已清理 N 个规则后中止」必须反映实际进度，否则失败轮无法区分「反复
// 失败原地打转」与「在推进」（与审计保留清理的部分计数同口径）。
func TestPurgeOrphanMetricsHistory_failureReturnsPartialCount(t *testing.T) {
	_, _ = newClusterTestService(t)
	seedMetricsHistory(t, "lb_partial_1", 1)
	seedMetricsHistory(t, "lb_partial_2", 1)
	counter, restore := wrapMetricsDBWithDeleteCounter(t)
	t.Cleanup(restore)
	counter.failAfter = 1

	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())
	if err == nil {
		t.Fatal("DELETE 失败必须上抛（不得当作清理完成）")
	}
	if deletedRules != 1 {
		t.Fatalf("deletedRules=%d, want 1（失败路径必须返回真实部分计数）", deletedRules)
	}
	if got := countMetricsHistory(t, "rule_id='lb_partial_1'"); got != 0 {
		t.Fatalf("已清空规则残留=%d, want 0", got)
	}
	if got := countMetricsHistory(t, "rule_id='lb_partial_2'"); got != 1 {
		t.Fatalf("失败规则行=%d, want 1（删除失败不得报告已清理）", got)
	}
}

// Given 主库/指标库句柄未初始化（启动早期，或关停尾部 db.Close 置 nil）
// When 执行孤儿清理
// Then 返回可见错误而非 (0, nil)：任务体据 err 分流，nil 会写「清理完成：删除 0 个」
// 并落 task_runs success，与「已收敛无残留」同形，也与兄弟族 PurgeOrphanRuleLogs
// 的 ScanError 口径相反。
func TestPurgeOrphanMetricsHistory_nilDatabaseIsLoud(t *testing.T) {
	_, _ = newClusterTestService(t)
	previousDB, previousMetrics := db.DB, db.MetricsDB
	db.DB = nil
	db.MetricsDB = nil
	t.Cleanup(func() { db.DB, db.MetricsDB = previousDB, previousMetrics })

	deletedRules, err := PurgeOrphanMetricsHistory(t.Context())

	if err == nil {
		t.Fatal("库未初始化时必须返回错误（本轮清理未执行，不得报成功）")
	}
	if !errors.Is(err, errMetricsDBUnavailable) {
		t.Fatalf("err=%v, want errMetricsDBUnavailable（与孤儿规则日志清理族同口径）", err)
	}
	if deletedRules != 0 {
		t.Fatalf("deletedRules=%d, want 0", deletedRules)
	}
}
