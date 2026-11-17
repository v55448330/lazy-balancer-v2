package handlers

// 提交失败后的连接池补发 ROLLBACK：泄漏连接非栈顶时的回收语义。
// 真实失败机制（R-14）：延迟外键在 COMMIT 阶段失败——驱动执行 "commit"
// 报错但底层事务保持活动（glebarez/go-sqlite tx.Commit 仅 exec，失败不回滚），
// database/sql 把 Tx 标记 done 后直接归还连接（ErrTxDone 不再调 driver 回滚）。
// 断言对象是系统终态：写锁释放（新写事务可提交）+ 新连接读不到未提交数据。

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// installDeferredCommitFailureGuard 建延迟外键守卫：对 probe_writes 的任何
// INSERT 都会在 COMMIT 阶段违反外键（父行不存在）——提交失败而事务滞留。
func installDeferredCommitFailureGuard(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`PRAGMA foreign_keys=ON;
		CREATE TABLE rollback_probe(id INTEGER PRIMARY KEY, v TEXT);
		CREATE TABLE rollback_recovery_probe(id INTEGER PRIMARY KEY, v TEXT);
		CREATE TABLE rollback_commit_parent(id INTEGER PRIMARY KEY);
		CREATE TABLE rollback_commit_guard(parent_id INTEGER, FOREIGN KEY(parent_id) REFERENCES rollback_commit_parent(id) DEFERRABLE INITIALLY DEFERRED);
		CREATE TRIGGER fail_probe_commit AFTER INSERT ON rollback_probe BEGIN INSERT INTO rollback_commit_guard(parent_id) VALUES (999); END`); err != nil {
		t.Fatalf("install deferred commit failure: %v", err)
	}
}

// leakUncommittedTxOnPool 在池内某连接上制造真实提交失败并把连接归还池：
// 返回后该连接带着活动事务（持写锁）躺在空闲列表里。
func leakUncommittedTxOnPool(t *testing.T, value string) {
	t.Helper()
	tx, err := db.DB.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO rollback_probe(v) VALUES (?)`, value); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("commit 应当失败（延迟外键守卫），实际成功——夹具失效")
	}
	// database/sql 语义：Commit 失败 → Tx done，连接归还池；此后 tx.Rollback
	// 只回 ErrTxDone，不再触达驱动（与生产 recoverCommittedViewAfterCommitFailure
	// 走到的分支完全同形）。
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("tx.Rollback=%v, want ErrTxDone（确认泄漏形态成立）", err)
	}
}

// assertWriteLockReleased 断言终态：新写事务能在短 busy_timeout 内提交
// （泄漏事务未回收时写锁滞留，这里会 SQLITE_BUSY），且任何新连接读不到
// 未提交的泄漏值。
func assertWriteLockReleased(t *testing.T, leakedValue string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := db.DB.Conn(ctx)
	if err != nil {
		t.Fatalf("checkout write probe: %v", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "PRAGMA busy_timeout=500"); err != nil {
		t.Fatalf("set busy_timeout: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO rollback_recovery_probe(v) VALUES ('after-recovery')`); err != nil {
		t.Fatalf("回收后写事务仍被写锁阻塞（泄漏事务未释放）: %v", err)
	}
	// 读侧终态：泄漏值不得在任何连接上可见（事务已回滚）。
	rows, err := db.DB.Query(`SELECT v FROM rollback_probe`)
	if err != nil {
		t.Fatalf("read probe: %v", err)
	}
	defer rows.Close()
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		if v == leakedValue {
			t.Fatalf("未提交值 %q 在回收后仍可见（泄漏事务未回滚）", leakedValue)
		}
	}
}

// 泄漏连接位于空闲栈顶（单连接形态）：补发必须回收写锁。回归形状。
func TestRollbackLeakedTx_releasesWriteLockWhenLeakIsStackTop(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installDeferredCommitFailureGuard(t)
	leakUncommittedTxOnPool(t, "leaked-top")
	rollbackLeakedTx()
	assertWriteLockReleased(t, "leaked-top")
}

// 泄漏连接非栈顶（并发读把其它空闲连接压到栈顶）：池级 Exec 的 LIFO 重试
// 全部命中同一条栈顶无事务连接（"no transaction is active" 循环），写锁持续
// 滞留——补发必须遍历池内全部连接逐个回收。
func TestRollbackLeakedTx_releasesWriteLockWhenLeakIsNotStackTop(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installDeferredCommitFailureGuard(t)
	leakUncommittedTxOnPool(t, "leaked-buried")
	// 签出两条**新**连接并压到泄漏连接之上（database/sql 空闲列表 LIFO：
	// 取栈顶、还栈顶）——泄漏连接沉到 freeConn[0]，栈顶两条均无活动事务。
	var buried [2]*sql.Conn
	for i := range buried {
		conn, err := db.DB.Conn(context.Background())
		if err != nil {
			t.Fatalf("checkout cover conn: %v", err)
		}
		if _, err := conn.ExecContext(context.Background(), "SELECT 1"); err != nil {
			t.Fatal(err)
		}
		buried[i] = conn
	}
	buried[0].Close()
	buried[1].Close()
	// 夹具自证：池级 Exec 的 ROLLBACK 只会命中栈顶无事务连接——这正是旧
	// 实现 5 次重试全部落空的形态（若此断言失败说明池序假设不成立）。
	if _, err := db.DB.Exec("ROLLBACK"); err == nil || !strings.Contains(err.Error(), "no transaction is active") {
		t.Fatalf("池级 ROLLBACK=%v, want no transaction is active（栈顶应为无事务连接）", err)
	}
	rollbackLeakedTx()
	assertWriteLockReleased(t, "leaked-buried")
}

// 无泄漏事务的空池/多空闲连接形态：补发不得误报、不得损坏后续写路径。
func TestRollbackLeakedTx_noActiveTransactionIsBenign(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	installDeferredCommitFailureGuard(t)
	for range 3 {
		conn, err := db.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(context.Background(), "SELECT 1"); err != nil {
			t.Fatal(err)
		}
		conn.Close()
	}
	rollbackLeakedTx()
	assertWriteLockReleased(t, "never-leaked")
}

// 源码序钉：旧实现「5 次池级 Exec ROLLBACK」依赖 LIFO 命中栈顶，泄漏连接
// 非栈顶时全部重试命中同一条无事务连接——实现必须显式遍历签出的专用连接。
func TestRollbackLeakedTx_traversesPoolConnections(t *testing.T) {
	sourceBytes, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatalf("read handlers.go: %v", err)
	}
	source := string(sourceBytes)
	start := strings.Index(source, "var rollbackLeakedTx = func() {")
	if start < 0 {
		t.Fatal("rollbackLeakedTx 不存在")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("rollbackLeakedTx 函数体边界缺失")
	}
	body := source[start : start+end]
	if !strings.Contains(body, ".Conn(") {
		t.Fatal("rollbackLeakedTx 未签出专用连接遍历池（LIFO 重试对非栈顶泄漏无效）")
	}
	if strings.Contains(body, `db.DB.Exec("ROLLBACK")`) {
		t.Fatal("rollbackLeakedTx 仍用池级 Exec 重试（LIFO 只命中栈顶连接）")
	}
}
