package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

func TestGetConfigSourceSection(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{source: "basic", want: "基础设置"},
		{source: "cluster", want: "集群管理"},
		{source: "acme", want: "ACME配置"},
		{source: "caddy", want: "Caddy配置"},
		{source: "", want: "全局配置"},
		{source: "unknown", want: "全局配置"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := GetConfigSourceSection(tt.source); got != tt.want {
				t.Fatalf("GetConfigSourceSection(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

// （过度修复审查 REMOVE：TestFormatAuditActionDirectConfigReload 已删除——
// 其断言被 TestAuditGenericRoutesExactlyOnce 的 /config/reload 子测试完全吸收
//（B/D 双域独立确认零覆盖）；决策文档化于 auditlog.go FormatAuditAction
// 注释与 genericRouteRegistry。）

func TestRecordAuditLogWritesToIndependentDatabase(t *testing.T) {
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}

	RecordAuditLog("system", "测试", "审计", "同步写入", "127.0.0.1")

	var count int
	if err := auditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE detail='同步写入'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit DB count = %d, want 1", count)
	}
}

func TestFormatAuditActionAuthAndNodeRegistration(t *testing.T) {
	// 原断言 /nodes/register 映射——该路由实际注册为 /cluster/register，
	// 映射从未可达（死映射）；/auth/login 为 Explicit（handler 记录 登录成功/失败）。
	// 两者现均须为空。
	action, resource, _ := FormatAuditAction("/api/v1/auth/login")
	if action != "" || resource != "" {
		t.Fatalf("login mapping = (%q, %q), want 空", action, resource)
	}
	action, resource, _ = FormatAuditAction("/api/v1/nodes/register")
	if action != "" || resource != "" {
		t.Fatalf("node registration mapping = (%q,%q), want 空（原为指向不存在路由的死映射）", action, resource)
	}
}

func TestGetAuditLogSizeBytes_cachesThresholdWithinTTL(t *testing.T) {
	// 2s 轮转 tick 此前在日志非空时每轮都查主库取阈值。
	// getAuditLogSizeBytes 现带 60s TTL 缓存：窗口内配置变更不观察（有界
	// 陈旧），过期后重查；读失败不入缓存（回退值不钉死整个窗口）。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	// 包级缓存隔离：进入与退出均重置，测试间互不串扰
	auditLogSizeValueCache.invalidate()
	t.Cleanup(auditLogSizeValueCache.invalidate)
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_log_size_mb=5 WHERE id=1`); err != nil {
		t.Fatal(err)
	}

	// When/Then：首查命中 DB 并缓存
	if got := getAuditLogSizeBytes(); got != 5<<20 {
		t.Fatalf("first=%d, want %d", got, 5<<20)
	}
	// When/Then：窗口内变更配置不观察（有界陈旧）
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_log_size_mb=7 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if got := getAuditLogSizeBytes(); got != 5<<20 {
		t.Fatalf("cached=%d, want %d (TTL not yet expired)", got, 5<<20)
	}
	// When/Then：过期后重查，观察新阈值
	auditLogSizeValueCache.mu.Lock()
	auditLogSizeValueCache.at = time.Now().Add(-auditLogSizeCacheTTL - time.Second)
	auditLogSizeValueCache.mu.Unlock()
	if got := getAuditLogSizeBytes(); got != 7<<20 {
		t.Fatalf("refreshed=%d, want %d after TTL expiry", got, 7<<20)
	}
}

// AuditUserPart(2026-09-11 裁定):用户相关审计详情显示完整标识
// 「用户 12（zhang）」;用户名空回退「用户 12」。
func TestAuditUserPart(t *testing.T) {
	if got := AuditUserPart(12, "zhang"); got != "用户 12（zhang）" {
		t.Errorf("AuditUserPart(12,\"zhang\")=%q, want 用户 12（zhang）", got)
	}
	if got := AuditUserPart(7, ""); got != "用户 7" {
		t.Errorf("AuditUserPart(7,\"\")=%q, want 用户 7 (empty username fallback)", got)
	}
}

// 「审计保留月数」读取失败三态分裂统一——
// CleanupAuditLogs 读取失败（含 global_config 行缺失 ErrNoRows）回退默认
// 3 月继续清理 + warn 留痕（曾静默 return 0：audit-retention 任务每 24h
// 报「清理 0 条」而 audit_log 永久不清，三消费点中最坏分支）。
func TestCleanupAuditLogs_fallsBackToDefaultOnMissingConfigRow(t *testing.T) {
	// Given global_config 行缺失（ErrNoRows 形态）+ 超 3 月的陈旧审计行
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY CHECK (id = 1), audit_retention_months INTEGER DEFAULT 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource, created_at) VALUES ('u','登录','认证','2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	oldWriter := log.Writer()
	var buf strings.Builder
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When
	n, err := CleanupAuditLogs(t.Context())
	if err != nil {
		t.Fatalf("CleanupAuditLogs() error=%v, want nil（默认 3 月回退后应正常清理）", err)
	}

	// Then 默认 3 月口径删除陈旧行（曾静默跳过）+ warn 留痕
	if n != 1 {
		t.Fatalf("CleanupAuditLogs()=%d, want 1（默认 3 月回退清理）", n)
	}
	if !strings.Contains(buf.String(), "审计保留月数") {
		t.Fatalf("读取失败应 warn 留痕，日志=%q", buf.String())
	}
}

// 保留清理分批执行：单条巨型 DELETE 会长时间持写锁阻塞审计写入。批尺寸
// 缩到 3、种 7 条过期行（需 3 批）+1 条保留行，断言循环删净且保留行不动。
func TestCleanupAuditLogs_deletesInBatches(t *testing.T) {
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY CHECK (id = 1), audit_retention_months INTEGER DEFAULT 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := mainDB.Exec(`INSERT INTO global_config (id, audit_retention_months) VALUES (1, 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	// 7 条过期 + 1 条新鲜（created_at 默认当前时间）
	if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource, created_at)
		WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 7)
		SELECT 'u', '登录', '认证', '2020-01-01 00:00:00' FROM seq`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource) VALUES ('u', '登录', '认证')`); err != nil {
		t.Fatal(err)
	}

	oldBatch := auditCleanupBatchSize
	auditCleanupBatchSize = 3
	t.Cleanup(func() { auditCleanupBatchSize = oldBatch })

	n, err := CleanupAuditLogs(t.Context())
	if err != nil {
		t.Fatalf("CleanupAuditLogs() error=%v, want nil", err)
	}
	if n != 7 {
		t.Fatalf("CleanupAuditLogs()=%d, want 7（分批循环须删净全部过期行）", n)
	}
	var remaining int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 1 {
		t.Fatalf("剩余行=%d, want 1（保留期内行不得被删）", remaining)
	}
}

// 中途失败必须返回已删除的真实条数：前几批删除不可逆，摘要若恒报 0 会
// 误导排障（与 security-events-retention 同口径）。
func TestCleanupAuditLogs_reportsPartialCountOnMidwayFailure(t *testing.T) {
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := mainDB.Exec(`CREATE TABLE global_config (id INTEGER PRIMARY KEY CHECK (id = 1), audit_retention_months INTEGER DEFAULT 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := mainDB.Exec(`INSERT INTO global_config (id, audit_retention_months) VALUES (1, 3)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource, created_at)
		WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 8)
		SELECT 'u', '登录', '认证', '2020-01-01 00:00:00' FROM seq`); err != nil {
		t.Fatal(err)
	}
	// 第 5 条删除时注入失败（前 4 条已被永久删除）。
	if _, err := auditDB.Exec(`CREATE TRIGGER block_delete BEFORE DELETE ON audit_log
		WHEN OLD.id = 5 BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	oldBatch := auditCleanupBatchSize
	auditCleanupBatchSize = 1
	t.Cleanup(func() { auditCleanupBatchSize = oldBatch })

	// When
	n, err := CleanupAuditLogs(t.Context())

	// Then：错误上抛且返回真实部分计数（不是 0）
	if err == nil {
		t.Fatal("DELETE 失败必须上抛")
	}
	if n != 4 {
		t.Fatalf("CleanupAuditLogs()=%d, want 4（已删除批次必须计入）", n)
	}
	var remaining int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 4 {
		t.Fatalf("剩余行=%d, want 4（失败点及其后保留）", remaining)
	}
}

// 保留月数读取的「非 ErrNoRows」失败必须跳过本轮删除：不可逆删除不得在
// 口径未知时按更短默认（3 月）执行——用户配置 12 月保留时一次配置表瞬断
// 会让当日清理永久删掉 3~12 月前的审计证据。
func TestCleanupAuditLogs_skipsDeletionWhenRetentionReadFails(t *testing.T) {
	// Given：审计库有超 3 月陈旧行；主库查询恒失败（非 ErrNoRows 形态）
	oldDB, oldAuditDB := db.DB, db.AuditDB
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}
	if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource, created_at) VALUES ('u','登录','认证','2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	db.AuditDB = auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		_ = auditDB.Close()
	})
	swapBrokenDB(t)

	// When
	n, err := CleanupAuditLogs(t.Context())

	// Then：本轮不删除任何行，失败上抛（任务面落 failed）
	if err == nil {
		t.Fatal("保留月数读取失败必须返回错误（不得按默认 3 月静默删除）")
	}
	if n != 0 {
		t.Fatalf("CleanupAuditLogs()=%d, want 0（口径未知时不得删除）", n)
	}
	var rows int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("审计证据行数=%d, want 1（不得删除）", rows)
	}
}

// newAuditCleanupFixture 建独立主库（保留 3 月）与审计库，种 oldRows 条过期
// 审计行，批尺寸收窄为 batch。返回审计库句柄；清理时恢复全局句柄与批尺寸。
func newAuditCleanupFixture(t *testing.T, oldRows, batch int) *sql.DB {
	t.Helper()
	setupIsolatedDB(t)
	auditDB := db.AuditDB
	oldBatch := auditCleanupBatchSize
	auditCleanupBatchSize = batch
	t.Cleanup(func() {
		auditCleanupBatchSize = oldBatch
	})
	if _, err := db.DB.Exec(`UPDATE global_config SET audit_retention_months=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if oldRows > 0 {
		if _, err := auditDB.Exec(`INSERT INTO audit_log (username, action, resource, created_at)
			WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < ?)
			SELECT 'u', '登录', '认证', '2020-01-01 00:00:00' FROM seq`, oldRows); err != nil {
			t.Fatal(err)
		}
	}
	return auditDB
}

// wrapAuditDBWithDeleteCounter 用同一 audit 库文件挂 DELETE 计数包装句柄
// （与指标孤儿清理同一条注入缝：afterExec 在批与批之间注入关停置 nil / ctx
// 取消，而不是语句执行之前）。
func wrapAuditDBWithDeleteCounter(t *testing.T) (*deleteCountingProbe, func()) {
	t.Helper()
	var seq int
	var name, file string
	if err := db.AuditDB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("read audit db path: %v", err)
	}
	if file == "" {
		t.Fatal("audit 测试库不是文件库，无法附加计数句柄")
	}
	previous := db.AuditDB
	probe := &deleteCountingProbe{match: "audit_log"}
	wrapped := sql.OpenDB(deleteCountingConnector{
		dsn:   file + "?_pragma=busy_timeout(30000)",
		inner: &sqlitedriver.Driver{},
		probe: probe,
	})
	db.AuditDB = wrapped
	return probe, func() {
		_ = wrapped.Close()
		db.AuditDB = previous
	}
}

// Given 过期审计行跨多条 DELETE 批，第一批执行完成后审计库句柄被关停置 nil
// （关停排空超时后 db.Close 执行，在途清理轮仍在下一批）。
// When 执行保留清理。
// Then 返回可见错误而非 nil 解引用 panic；已删除批次不可逆，计数如实。
func TestCleanupAuditLogs_auditDBClosedMidRunDoesNotPanic(t *testing.T) {
	newAuditCleanupFixture(t, 7, 3)
	counter, restore := wrapAuditDBWithDeleteCounter(t)
	t.Cleanup(restore)
	counter.afterExec = func(n int) {
		if n == 1 {
			db.AuditDB = nil // 关停尾部 db.Close() 的等价形态
		}
	}

	n, err := CleanupAuditLogs(t.Context())

	if err == nil {
		t.Fatal("审计库关停后必须返回错误（任务落 failed），不得静默成功")
	}
	if n != 3 {
		t.Fatalf("CleanupAuditLogs()=%d, want 3（已删除批次必须计入真实部分计数）", n)
	}
}

// Given 过期审计行跨多条 DELETE 批，第一批执行完成后 ctx 被取消（任务取消/
// 关停）。
// When 执行保留清理。
// Then 返回 context.Canceled + 已删除批次真实计数——批间复检让关停能中断本轮，
// 且不得把部分删除报成清理完成。
func TestCleanupAuditLogs_cancelBetweenBatchesReturnsContextError(t *testing.T) {
	newAuditCleanupFixture(t, 7, 3)
	counter, restore := wrapAuditDBWithDeleteCounter(t)
	t.Cleanup(restore)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	counter.afterExec = func(n int) {
		if n == 1 {
			cancel()
		}
	}

	n, err := CleanupAuditLogs(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got %v", err)
	}
	if n != 3 {
		t.Fatalf("CleanupAuditLogs()=%d, want 3（已删除批次必须计入真实部分计数）", n)
	}
}

// blockableConnector 用同一主库文件挂「查询闸门」包装句柄：release 关闭前
// 每次查询都停在闸门，ctx 取消则立即返回该错误——用于钉住保留月数读取
// 不再脱离 ctx（关停/导入取消不得被主库慢查询拖过预算）。
type blockableConnector struct {
	dsn   string
	inner driver.Driver
	gate  *queryGate
}

// queryGate entered 报告查询已到达闸门（缓冲 1，只报首次），release 关闭后
// 放行真实查询。
type queryGate struct {
	entered chan struct{}
	release chan struct{}
}

func newQueryGate() *queryGate {
	return &queryGate{entered: make(chan struct{}, 1), release: make(chan struct{})}
}

func (c blockableConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &blockableConn{Conn: conn, gate: c.gate}, nil
}

func (c blockableConnector) Driver() driver.Driver { return c.inner }

type blockableConn struct {
	driver.Conn
	gate *queryGate
}

func (c *blockableConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	select {
	case c.gate.entered <- struct{}{}:
	default:
	}
	select {
	case <-c.gate.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if q, ok := c.Conn.(driver.QueryerContext); ok {
		return q.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

// installBlockableMainDB 把 db.DB 换成同一主库文件上的闸门句柄（本用例结束
// 时恢复原句柄）。
func installBlockableMainDB(t *testing.T) *queryGate {
	t.Helper()
	var seq int
	var name, file string
	if err := db.DB.QueryRow("PRAGMA database_list").Scan(&seq, &name, &file); err != nil {
		t.Fatalf("read main db path: %v", err)
	}
	if file == "" {
		t.Fatal("主库测试库不是文件库，无法附加闸门句柄")
	}
	previous := db.DB
	gate := newQueryGate()
	wrapped := sql.OpenDB(blockableConnector{
		dsn:   file + "?_pragma=busy_timeout(30000)",
		inner: &sqlitedriver.Driver{},
		gate:  gate,
	})
	db.DB = wrapped
	t.Cleanup(func() {
		_ = wrapped.Close()
		db.DB = previous
	})
	return gate
}

// seedPurgeableTaskRuns 在主库建最小 task_runs 表并种一条 2020 年的过期行。
func seedPurgeableTaskRuns(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`DROP TABLE IF EXISTS task_runs`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`CREATE TABLE task_runs (id INTEGER PRIMARY KEY AUTOINCREMENT, task_id TEXT, started_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, started_at) VALUES ('audit-retention', '2020-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
}

func purgeableTaskRunRows(t *testing.T) int {
	t.Helper()
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM task_runs`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	return rows
}

// Given 保留月数读取停在主库查询上（慢查询/写锁），随后任务被取消。
// When 执行保留清理。
// Then 读取按 ctx 立即返回 context.Canceled，且不进入任何 DELETE——关停/
// 导入排空不得被首段无 ctx 查询拖过预算。
func TestCleanupAuditLogs_retentionQueryHonorsContext(t *testing.T) {
	auditDB := newAuditCleanupFixture(t, 7, 3)
	counter, restore := wrapAuditDBWithDeleteCounter(t)
	t.Cleanup(restore)
	gate := installBlockableMainDB(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	done := make(chan struct{})
	var (
		n   int
		err error
	)
	go func() {
		n, err = CleanupAuditLogs(ctx)
		close(done)
	}()

	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("保留月数查询未到达注入点（首段读取未走可取消句柄）")
	}
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("取消后保留月数读取仍在阻塞（关停被拖过预算）")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got %v", err)
	}
	if n != 0 {
		t.Fatalf("CleanupAuditLogs()=%d, want 0（取消后不得进入 DELETE）", n)
	}
	if got := counter.count(); got != 0 {
		t.Fatalf("DELETE 次数=%d, want 0（首段取消不得触发删除）", got)
	}
	var rows int
	if err := auditDB.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 7 {
		t.Fatalf("审计行=%d, want 7（取消后一条都不删）", rows)
	}
}

// Given 过期审计行跨多批，第一批完成后任务被取消。
// When 执行一轮审计保留清理。
// Then 第二段任务历史删除不启动：task_runs 过期行仍在，计数 0，错误为取消。
func TestAuditRetentionRound_skipsTaskRunPurgeAfterCancel(t *testing.T) {
	newAuditCleanupFixture(t, 7, 3)
	counter, restore := wrapAuditDBWithDeleteCounter(t)
	t.Cleanup(restore)
	seedPurgeableTaskRuns(t)

	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)
	counter.afterExec = func(n int) {
		if n == 1 {
			cancel()
		}
	}

	auditDeleted, runsDeleted, err := auditRetentionRound(ctx)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got %v", err)
	}
	if auditDeleted != 3 {
		t.Fatalf("auditDeleted=%d, want 3（已删批次计数如实）", auditDeleted)
	}
	if runsDeleted != 0 {
		t.Fatalf("runsDeleted=%d, want 0（取消后不得启动第二段删除）", runsDeleted)
	}
	if got := purgeableTaskRunRows(t); got != 1 {
		t.Fatalf("task_runs 行=%d, want 1（取消后不得删除任务历史）", got)
	}
}

// Given 主库存在过期任务运行行。
// When 以已取消 ctx 调用任务历史清理。
// Then 不执行 DELETE，返回取消错误，过期行仍在。
func TestPurgeTaskRuns_canceledContextSkipsDelete(t *testing.T) {
	newAuditCleanupFixture(t, 0, 3)
	seedPurgeableTaskRuns(t)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	n, err := taskengine.PurgeTaskRuns(ctx, 90)

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("取消后应返回 context.Canceled, got %v", err)
	}
	if n != 0 {
		t.Fatalf("PurgeTaskRuns()=%d, want 0（取消后不得删除）", n)
	}
	if got := purgeableTaskRunRows(t); got != 1 {
		t.Fatalf("task_runs 行=%d, want 1（取消后不得删除）", got)
	}
}

// Given 过期与未过期任务运行行各一条。
// When 按 90 天保留期清理。
// Then 只删除过期行并返回真实删除计数，保留行不受影响。
func TestPurgeTaskRuns_deletesOnlyExpiredRows(t *testing.T) {
	newAuditCleanupFixture(t, 0, 3)
	seedPurgeableTaskRuns(t)
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, started_at) VALUES ('recent-task', '2999-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}

	n, err := taskengine.PurgeTaskRuns(t.Context(), 90)

	if err != nil {
		t.Fatalf("PurgeTaskRuns: %v", err)
	}
	if n != 1 {
		t.Fatalf("PurgeTaskRuns()=%d, want 1", n)
	}
	var remaining string
	if err := db.DB.QueryRow(`SELECT task_id FROM task_runs`).Scan(&remaining); err != nil {
		t.Fatalf("read remaining task run: %v", err)
	}
	if remaining != "recent-task" {
		t.Fatalf("remaining task_id=%q, want recent-task", remaining)
	}
}

// 非正保留期是显式 no-op：即使上下文已取消也不得误删或报错。
func TestPurgeTaskRuns_nonPositiveRetentionIsNoOp(t *testing.T) {
	for _, days := range []int{0, -1} {
		t.Run(fmt.Sprint(days), func(t *testing.T) {
			newAuditCleanupFixture(t, 0, 3)
			seedPurgeableTaskRuns(t)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			n, err := taskengine.PurgeTaskRuns(ctx, days)

			if err != nil || n != 0 {
				t.Fatalf("PurgeTaskRuns(days=%d)=(%d,%v), want (0,nil)", days, n, err)
			}
			if got := purgeableTaskRunRows(t); got != 1 {
				t.Fatalf("task_runs rows=%d, want 1", got)
			}
		})
	}
}

// SQLite 拒绝 DELETE 时错误必须上抛、计数归零且目标行保留，禁止把失败写成成功。
func TestPurgeTaskRuns_deleteFailureIsReported(t *testing.T) {
	newAuditCleanupFixture(t, 0, 3)
	seedPurgeableTaskRuns(t)
	if _, err := db.DB.Exec(`CREATE TRIGGER reject_task_run_delete BEFORE DELETE ON task_runs BEGIN SELECT RAISE(ABORT, 'injected delete failure'); END`); err != nil {
		t.Fatal(err)
	}

	n, err := taskengine.PurgeTaskRuns(t.Context(), 90)

	if err == nil || !strings.Contains(err.Error(), "injected delete failure") {
		t.Fatalf("PurgeTaskRuns error=%v, want injected delete failure", err)
	}
	if n != 0 {
		t.Fatalf("PurgeTaskRuns()=%d, want 0 after DELETE failure", n)
	}
	if got := purgeableTaskRunRows(t); got != 1 {
		t.Fatalf("task_runs rows=%d, want 1 after DELETE failure", got)
	}
}

// 正常保留链必须把任务历史的真实删除计数传回调用方，而非仅覆盖取消分支。
func TestAuditRetentionRound_reportsPurgedTaskRuns(t *testing.T) {
	newAuditCleanupFixture(t, 0, 3)
	seedPurgeableTaskRuns(t)

	auditDeleted, runsDeleted, err := auditRetentionRound(t.Context())

	if err != nil {
		t.Fatalf("auditRetentionRound: %v", err)
	}
	if auditDeleted != 0 || runsDeleted != 1 {
		t.Fatalf("deleted=(audit:%d,runs:%d), want (0,1)", auditDeleted, runsDeleted)
	}
	if got := purgeableTaskRunRows(t); got != 0 {
		t.Fatalf("task_runs rows=%d, want 0", got)
	}
}
