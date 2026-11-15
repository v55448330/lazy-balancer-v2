package handlers

// 摄取错误可重试判定钉：
//  1. 真实 SQLITE_BUSY（独立连接持写锁 + busy_timeout=0）必须判可重试
//     （503→写侧 spool 补采），按驱动类型化错误码判定；
//  2. 过宽裸子串收敛——错误消息恰好含 "busy"/"locked" 单词但非锁类错误
//     （如规则文本/URI 回显）不得误判可重试（永久失败 500，写侧不 spool
//     毒批无限重试）；
//  3. 真实锁类措辞（database is locked/busy）与临时 IO（disk i/o error、
//     no space left）兜底仍判可重试。

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// TestSecurityEventsIngestRetryable_realBusyIsRetryable：真实失败机制——
// 独立连接开 BEGIN IMMEDIATE 持主库写锁，当前库 busy_timeout=0 形态的写入
// 立即 SQLITE_BUSY；该错误必须判可重试。
func TestSecurityEventsIngestRetryable_realBusyIsRetryable(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ctx := context.Background()
	// 预建表必须先提交：locker 事务内建表对独立连接不可见（no such table
	// 会顶替 BUSY，夹具失效）。
	if _, err := db.DB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ingest_busy_probe (id INTEGER)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	locker, err := db.DB.BeginTx(ctx, nil) // DSN _txlock=immediate：开始即持写锁
	if err != nil {
		t.Fatalf("begin locker tx: %v", err)
	}
	defer locker.Rollback()
	if _, err := locker.ExecContext(ctx, `INSERT INTO ingest_busy_probe (id) VALUES (0)`); err != nil {
		t.Fatalf("locker write: %v", err)
	}

	// 同文件独立连接、busy_timeout=0：写锁被持有时立即返回 SQLITE_BUSY。
	rows, err := db.DB.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatalf("database_list: %v", err)
	}
	var path string
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "main" {
			path = file
		}
	}
	rows.Close()
	conn, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("open no-wait conn: %v", err)
	}
	defer conn.Close()
	_, busyErr := conn.ExecContext(ctx, `INSERT INTO ingest_busy_probe (id) VALUES (1)`)
	if busyErr == nil {
		t.Fatal("夹具失效：持锁期间写入必须 SQLITE_BUSY")
	}
	if !strings.Contains(strings.ToUpper(busyErr.Error()), "BUSY") && !strings.Contains(strings.ToLower(busyErr.Error()), "locked") {
		t.Fatalf("夹具错误=%v, want SQLITE_BUSY/locked", busyErr)
	}
	if !securityEventsIngestErrorRetryable(busyErr) {
		t.Fatalf("真实 SQLITE_BUSY 必须判可重试, err=%v", busyErr)
	}
	// 包装链穿透（database/sql 与 fmt.Errorf 包装后仍命中驱动码）。
	if !securityEventsIngestErrorRetryable(fmt.Errorf("ingest batch: %w", busyErr)) {
		t.Fatal("包装后的 SQLITE_BUSY 必须判可重试（errors.As 穿透）")
	}
}

// TestSecurityEventsIngestRetryable_bareSubstringsNotRetryable：过宽裸
// busy/locked 子串收敛——非锁类错误消息含这两个单词不得误判可重试。
func TestSecurityEventsIngestRetryable_bareSubstringsNotRetryable(t *testing.T) {
	for _, msg := range []string{
		`security events: rule text "the server is busy processing" rejected`,
		`security events: uri /account-locked contains invalid segment`,
		`security events: parse error near "busy"`,
	} {
		if securityEventsIngestErrorRetryable(errors.New(msg)) {
			t.Fatalf("非锁类错误误判可重试（裸子串过宽）: %s", msg)
		}
	}
}

// TestSecurityEventsIngestRetryable_lockAndIOFallbacks：真实锁类措辞与
// 临时 IO 故障的兜底判定保持可重试（驱动消息措辞变化不得漏判）。
func TestSecurityEventsIngestRetryable_lockAndIOFallbacks(t *testing.T) {
	for _, msg := range []string{
		"database is locked (5) (SQLITE_BUSY)",
		"database is busy",
		"disk I/O error",
		"no space left on device",
	} {
		if !securityEventsIngestErrorRetryable(errors.New(msg)) {
			t.Fatalf("锁/IO 类错误必须判可重试: %s", msg)
		}
	}
	// 回归：依赖未就绪 sentinel 不经本函数（handleIngest 单独 errors.Is），
	// 普通错误不得误判。
	if securityEventsIngestErrorRetryable(errors.New("constraint failed: UNIQUE")) {
		t.Fatal("约束类永久失败不得判可重试")
	}
}

// TestSecurityEventsIPCHandler_busyReturns503：HTTP 面——真实写锁下的摄取
// 失败必须 503（写侧据此 spool 补采），不得 500（毒批语义）。夹具：预建表
// 已提交，独立事务持写锁（WAL 单写者），busy_timeout=0 连接写入立即 BUSY。
func TestSecurityEventsIPCHandler_busyReturns503(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	ctx := context.Background()
	if _, err := db.MetricsDB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS ingest_busy_probe_m (id INTEGER)`); err != nil {
		t.Fatalf("create probe table: %v", err)
	}
	locker, err := db.MetricsDB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin metrics locker: %v", err)
	}
	defer locker.Rollback()
	if _, err := locker.ExecContext(ctx, `INSERT INTO ingest_busy_probe_m (id) VALUES (0)`); err != nil {
		t.Fatalf("locker write: %v", err)
	}
	rows, err := db.MetricsDB.Query(`PRAGMA database_list`)
	if err != nil {
		t.Fatalf("database_list: %v", err)
	}
	var path string
	for rows.Next() {
		var seq int
		var name, file string
		if err := rows.Scan(&seq, &name, &file); err != nil {
			t.Fatalf("scan: %v", err)
		}
		if name == "main" {
			path = file
		}
	}
	rows.Close()
	conn, err := sql.Open("sqlite", path+"?_txlock=immediate&_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatalf("open no-wait conn: %v", err)
	}
	defer conn.Close()
	_, busyErr := conn.ExecContext(ctx, `INSERT INTO ingest_busy_probe_m (id) VALUES (1)`)
	if busyErr == nil {
		t.Fatal("夹具失效：持锁期间写入必须 SQLITE_BUSY")
	}
	code := http.StatusInternalServerError
	if securityEventsIngestErrorRetryable(busyErr) {
		code = http.StatusServiceUnavailable
	}
	if code != http.StatusServiceUnavailable {
		t.Fatalf("busy 映射=%d, want 503（写侧 spool 补采契约）, err=%v", code, busyErr)
	}
}
