package db

// RollbackLeakedTx 行为钉：真实泄漏注入（延迟外键 COMMIT 失败——driver 层
// 事务保持活动，Tx 标记 done 归还连接）+ 并发读掩埋泄漏连接（非栈顶形态），
// 断言补发后写锁释放。镜像 handlers/rollback_leaked_tx_pool_test 手法。

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// leakUncommittedTx 在池上制造真实泄漏写事务：延迟外键约束使 COMMIT 失败，
// driver 事务保持活动；Tx 已 done，连接归还池仍持写锁。
// foreign_keys 驱动默认 OFF 且连接级独立——用专用 conn 建表+插入保证
// 同一连接上 pragma 生效，Commit 失败后 conn 不 Close（归还池=泄漏形态）。
func leakUncommittedTx(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := database.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS leak_parent (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS leak_child (id INTEGER PRIMARY KEY, pid INTEGER REFERENCES leak_parent(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO leak_child (pid) VALUES (999)`); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err == nil {
		t.Fatal("延迟外键 COMMIT 必须失败（泄漏注入前提）")
	}
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("tx.Rollback=%v, want ErrTxDone（确认泄漏形态成立）", err)
	}
	// conn.Close 归还池——泄漏事务随连接躺在空闲列表（持写锁）。
	_ = conn.Close()
}

func assertWriteLockReleased(t *testing.T, database *sql.DB) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		tx, err := database.BeginTx(ctx, nil)
		if err != nil {
			done <- err
			return
		}
		_, err = tx.Exec(`INSERT INTO leak_parent (id) VALUES (1)`)
		if err == nil {
			err = tx.Commit()
		} else {
			_ = tx.Rollback()
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("补发后写锁未释放: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("补发后写事务仍阻塞（写锁滞留）")
	}
}

func openLeakTestDB(t *testing.T, name string) *sql.DB {
	t.Helper()
	database, err := openSQLiteDB(filepath.Join(t.TempDir(), name), sqlitePoolConfig{maxOpen: 5, maxIdle: 5, connMaxLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return database
}

func TestRollbackLeakedTx_releasesNonTopLeakedConn(t *testing.T) {
	database := openLeakTestDB(t, "leak.db")
	leakUncommittedTx(t, database)
	// 签出两条新连接压到泄漏连接之上（空闲列表 LIFO：取栈顶还栈顶）——
	// 泄漏连接沉底，栈顶两条均无活动事务（确定性非栈顶形态）。
	ctx := context.Background()
	var buried [2]*sql.Conn
	for i := range buried {
		conn, err := database.Conn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ExecContext(ctx, "SELECT 1"); err != nil {
			t.Fatal(err)
		}
		buried[i] = conn
	}
	buried[0].Close()
	buried[1].Close()
	// 夹具自证：池级 Exec ROLLBACK 只命中栈顶无事务连接（旧算法落空形态）。
	if _, err := database.Exec("ROLLBACK"); err == nil || !strings.Contains(err.Error(), "no transaction is active") {
		t.Fatalf("池级 ROLLBACK=%v, want no transaction is active（栈顶应为无事务连接）", err)
	}
	RollbackLeakedTx(database, 5)
	assertWriteLockReleased(t, database)
}

func TestRollbackLeakedTx_nilAndZeroPoolNoop(t *testing.T) {
	RollbackLeakedTx(nil, 5)
	RollbackLeakedTx(nil, 0)
}

func TestRollbackLeakedTx_noLeakIsBenign(t *testing.T) {
	database := openLeakTestDB(t, "clean.db")
	if _, err := database.Exec(`CREATE TABLE leak_parent (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	RollbackLeakedTx(database, 5)
	assertWriteLockReleased(t, database)
}

// TestRollbackLeakedTx_givesUpQuicklyWhenPoolSaturated：池被在用连接占满时
// 补发必须快速放弃——池满说明泄漏连接（提交失败刚归还空闲）已被后续请求
// 签出在用（其上仍是泄漏事务，等待复用者完成无上界）。500ms 饱和探测预算
// 内拿不到空闲连接即 break + WARN 留痕；旧实现 30s 固定预算会在池饱和时
// 阻塞调用方整整一个超时周期。
func TestRollbackLeakedTx_givesUpQuicklyWhenPoolSaturated(t *testing.T) {
	database, err := openSQLiteDB(filepath.Join(t.TempDir(), "saturated.db"), sqlitePoolConfig{maxOpen: 1, maxIdle: 1, connMaxLifetime: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	// 占满唯一连接：Conn 无空闲可签出，只能等在用连接释放。
	conn, err := database.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// 放弃分支必须留痕（否则泄漏锁滞留期间运维只见连环 busy 失败，无锚点）。
	var logBuf bytes.Buffer
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	start := time.Now()
	RollbackLeakedTx(database, 1)
	elapsed := time.Since(start)
	if elapsed >= 5*time.Second {
		t.Fatalf("池饱和时补发耗时 %v：必须快速放弃（预算 <5s，旧实现阻塞 ~30s）", elapsed)
	}
	if !strings.Contains(logBuf.String(), "泄漏事务未回收") {
		t.Fatalf("放弃分支缺 WARN 留痕，日志=%q", logBuf.String())
	}
}
