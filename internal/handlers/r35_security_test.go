package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// TestBindDeleteRace_serializableIsolationBlocksConcurrentDelete 串行模拟 R35 D1
// 交错：绑定事务的存在性 COUNT 之后、INSERT 之前，并发的策略删除不得提交。
// 可序列化隔离（BEGIN IMMEDIATE）下 COUNT 即持写锁，删除只能等绑定事务结束后执行。
func TestBindDeleteRace_serializableIsolationBlocksConcurrentDelete(t *testing.T) {
	// Given a policy and a rule eligible for binding
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	policyID := createTestPolicy(t, router, map[string]any{"name": "竞态策略", "mode": "blocking", "enabled": true})
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_race1', '竞态规则', 'http', 8081)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}

	ctx := context.Background()
	// bind 侧事务：与 BindRuleToPolicy 相同的可序列化隔离 + 存在性 COUNT
	bindTx, err := db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin bind tx: %v", err)
	}
	defer bindTx.Rollback()
	var n int
	if err := bindTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM lb_rules WHERE caddy_id='lb_race1'").Scan(&n); err != nil || n == 0 {
		t.Fatalf("rule count in tx: n=%d err=%v", n, err)
	}

	// delete 侧事务（同 DeleteSecurityPolicy 语义：删除策略）在 bind 事务持锁期间发起；
	// BEGIN IMMEDIATE 需要写锁，故 BeginTx 本身就会被写锁阻塞（busy_timeout 内等待）。
	type delResult struct {
		tx  *sql.Tx
		err error
	}
	delDone := make(chan delResult, 1)
	go func() {
		dt, err := db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
		if err != nil {
			delDone <- delResult{err: err}
			return
		}
		if _, err := dt.ExecContext(ctx, "DELETE FROM security_policies WHERE id=?", policyID); err != nil {
			delDone <- delResult{tx: dt, err: err}
			return
		}
		delDone <- delResult{tx: dt}
	}()

	// Then the concurrent delete is blocked by the write lock: it cannot complete
	// between bind's COUNT and INSERT（回归：R35 D1 写窗口）
	select {
	case res := <-delDone:
		t.Fatalf("并发删除在 bind 事务持锁期间完成: %v（回归：R35 D1 写窗口）", res.err)
	case <-time.After(200 * time.Millisecond):
	}

	// bind 事务完成绑定 INSERT + Commit
	if _, err := bindTx.ExecContext(ctx, "INSERT OR IGNORE INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_race1', ?)", policyID); err != nil {
		t.Fatalf("insert binding: %v", err)
	}
	if err := bindTx.Commit(); err != nil {
		t.Fatalf("commit bind tx: %v", err)
	}

	// 删除事务此时才能完成（含绑定清理，同 DeleteSecurityPolicy）
	var res delResult
	select {
	case res = <-delDone:
	case <-time.After(10 * time.Second):
		t.Fatal("并发删除在 bind 提交后仍被阻塞")
	}
	if res.err != nil {
		t.Fatalf("delete after bind commit: %v", res.err)
	}
	if _, err := res.tx.ExecContext(ctx, "DELETE FROM security_policy_bindings WHERE policy_id=?", policyID); err != nil {
		t.Fatalf("clean bindings: %v", err)
	}
	if err := res.tx.Commit(); err != nil {
		t.Fatalf("commit delete tx: %v", err)
	}

	// And no dangling binding survives the interleave
	var dangling int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings b LEFT JOIN security_policies p ON p.id=b.policy_id WHERE p.id IS NULL`).Scan(&dangling); err != nil {
		t.Fatalf("count dangling: %v", err)
	}
	if dangling != 0 {
		t.Fatalf("dangling bindings=%d, want 0（R35 D1）", dangling)
	}
}

// failingMetricsConnector 返回一个每次查询都失败的 *sql.DB，用于注入
// metrics 库故障（R35 D2）。
type failingMetricsConnector struct{}

func (failingMetricsConnector) Connect(context.Context) (driver.Conn, error) {
	return failingMetricsConn{}, nil
}

func (failingMetricsConnector) Driver() driver.Driver { return failingMetricsDriver{} }

type failingMetricsDriver struct{}

func (failingMetricsDriver) Open(string) (driver.Conn, error) { return failingMetricsConn{}, nil }

type failingMetricsConn struct{}

func (failingMetricsConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("注入的 metrics 库查询失败")
}

func (failingMetricsConn) Close() error { return nil }

func (failingMetricsConn) Begin() (driver.Tx, error) {
	return nil, errors.New("注入的 metrics 库查询失败")
}

// TestGetSecurityOverview_metricsDBErrorReturns500 验证 metrics 库查询失败时
// 安全总览显式返回 500，而不是静默给出全零「无攻击」面板（R35 D2）。
func TestGetSecurityOverview_metricsDBErrorReturns500(t *testing.T) {
	// Given a working security DB but a failing metrics store
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	broken := sql.OpenDB(failingMetricsConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = orig })

	// When the overview is requested while the metrics store is down
	recorder := getRequest(t, router, "/security/overview")

	// Then it fails loudly instead of returning an all-zero "no attacks" dashboard
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "安全总览查询失败") {
		t.Fatalf("body=%s, want explicit overview failure message", recorder.Body.String())
	}
}

// TestListSecurityEvents_scanErrorReturns500 验证行 Scan 失败时事件列表显式
// 返回 500，而不是把部分零值的事件行当作真实事件返回（R35 D3）。
func TestListSecurityEvents_scanErrorReturns500(t *testing.T) {
	// Given a metrics row whose anomaly_score cannot scan into int
	// （SQLite 动态类型下向 INTEGER 列写入了文本）
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, method, uri, action, anomaly_score)
		VALUES ('2099-01-01 00:00:00', '192.0.2.1', 'GET', '/bad', 'blocked', 'not-a-number')`); err != nil {
		t.Fatalf("seed bogus event: %v", err)
	}

	// When the events list is requested
	recorder := getRequest(t, router, "/security/events")

	// Then the scan failure surfaces as 500 instead of a zero-valued event row
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "安全事件查询失败") {
		t.Fatalf("body=%s, want explicit query failure message", recorder.Body.String())
	}
}
