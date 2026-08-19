package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// TestDeleteCustomRuleRace_serializableIsolationBlocksConcurrentPolicyEnable
// 串行模拟 R37 I1 交错：删除事务的引用检查 SELECT 之后、DELETE 之前，并发的
// 策略启用（UpdateSecurityPolicy 语义）不得提交。BEGIN IMMEDIATE 下引用检查即
// 持写锁，策略启用只能等删除事务提交后执行——检查与删除之间不存在插队窗口。
func TestDeleteCustomRuleRace_serializableIsolationBlocksConcurrentPolicyEnable(t *testing.T) {
	// Given a custom rule referenced only by a disabled policy (delete allowed)
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('竞态规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('竞态策略', ?, 0)`, fmt.Sprintf("[%d]", ruleID)); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	var policyID int
	if err := db.DB.QueryRow("SELECT id FROM security_policies WHERE name='竞态策略'").Scan(&policyID); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// delete 侧事务（同修复后 DeleteSecurityCustomRule 语义）：引用检查 SELECT 即持写锁
	delTx, err := db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin delete tx: %v", err)
	}
	defer delTx.Rollback()
	rows, err := delTx.QueryContext(ctx, `SELECT custom_rules FROM security_policies WHERE enabled=1`)
	if err != nil {
		t.Fatalf("reference check: %v", err)
	}
	var referenced int
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("scan custom_rules: %v", err)
		}
		var ids []int
		if json.Unmarshal([]byte(raw), &ids) == nil {
			for _, rid := range ids {
				if rid == int(ruleID) {
					referenced++
				}
			}
		}
	}
	rows.Close()
	if referenced != 0 {
		t.Fatalf("referenced=%d, want 0 (policy disabled)", referenced)
	}

	// 并发策略启用（使引用生效）在检查之后、删除之前发起
	updateDone := make(chan error, 1)
	go func() {
		_, err := db.DB.Exec("UPDATE security_policies SET enabled=1 WHERE id=?", policyID)
		updateDone <- err
	}()

	// Then the concurrent enable is blocked by the write lock: it cannot commit
	// between the reference check and the DELETE（回归：R37 I1 写窗口）
	select {
	case err := <-updateDone:
		t.Fatalf("并发策略启用已在检查与删除之间完成: %v（回归：R37 I1 写窗口）", err)
	case <-time.After(200 * time.Millisecond):
	}

	// delete 侧完成 DELETE + Commit
	if _, err := delTx.ExecContext(ctx, "DELETE FROM security_custom_rules WHERE id=?", ruleID); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if err := delTx.Commit(); err != nil {
		t.Fatalf("commit delete tx: %v", err)
	}

	// 并发启用此时才能提交（删除已提交，无死锁）
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("并发策略启用: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("并发策略启用被永久阻塞")
	}

	// And the rule is deleted；引用检查与删除之间不存在交错窗口
	var rules int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_custom_rules WHERE id=?", ruleID).Scan(&rules); err != nil {
		t.Fatal(err)
	}
	if rules != 0 {
		t.Fatalf("custom rule rows=%d, want 0（删除已提交）", rules)
	}
}

// TestDeleteBlockPageRace_serializableIsolationBlocksConcurrentPolicyEnable
// 同 R37 I1 模拟，针对 DeleteSecurityBlockPage：引用 COUNT 检查与 DELETE 同事务，
// 并发的策略启用无法插队到检查与 DELETE 之间。
func TestDeleteBlockPageRace_serializableIsolationBlocksConcurrentPolicyEnable(t *testing.T) {
	// Given a block page referenced only by a disabled policy (delete allowed)
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO security_block_pages (name, content, is_default) VALUES ('竞态页面', '<html></html>', 0)`)
	if err != nil {
		t.Fatalf("seed block page: %v", err)
	}
	pageID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, block_page_id, enabled) VALUES ('竞态页面策略', ?, 0)`, pageID); err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	var policyID int
	if err := db.DB.QueryRow("SELECT id FROM security_policies WHERE name='竞态页面策略'").Scan(&policyID); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// delete 侧事务（同修复后 DeleteSecurityBlockPage 语义）：默认页检查 + 引用 COUNT 即持写锁
	delTx, err := db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin delete tx: %v", err)
	}
	defer delTx.Rollback()
	var isDefault bool
	if err := delTx.QueryRowContext(ctx, "SELECT is_default FROM security_block_pages WHERE id=?", pageID).Scan(&isDefault); err != nil {
		t.Fatalf("is_default check: %v", err)
	}
	if isDefault {
		t.Fatal("page must not be default")
	}
	var referenced int
	if err := delTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_policies WHERE block_page_id=? AND enabled=1", pageID).Scan(&referenced); err != nil {
		t.Fatalf("reference count: %v", err)
	}
	if referenced != 0 {
		t.Fatalf("referenced=%d, want 0 (policy disabled)", referenced)
	}

	// 并发策略启用（使引用生效）在检查之后、删除之前发起
	updateDone := make(chan error, 1)
	go func() {
		_, err := db.DB.Exec("UPDATE security_policies SET enabled=1 WHERE id=?", policyID)
		updateDone <- err
	}()

	// Then the concurrent enable is blocked: it cannot commit between the
	// reference COUNT and the DELETE（回归：R37 I1 写窗口）
	select {
	case err := <-updateDone:
		t.Fatalf("并发策略启用已在检查与删除之间完成: %v（回归：R37 I1 写窗口）", err)
	case <-time.After(200 * time.Millisecond):
	}

	// delete 侧完成 DELETE + Commit
	if _, err := delTx.ExecContext(ctx, "DELETE FROM security_block_pages WHERE id=?", pageID); err != nil {
		t.Fatalf("delete page: %v", err)
	}
	if err := delTx.Commit(); err != nil {
		t.Fatalf("commit delete tx: %v", err)
	}

	// 并发启用此时才能提交
	select {
	case err := <-updateDone:
		if err != nil {
			t.Fatalf("并发策略启用: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("并发策略启用被永久阻塞")
	}

	// And the page is deleted；引用检查与删除之间不存在交错窗口
	var pages int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_block_pages WHERE id=?", pageID).Scan(&pages); err != nil {
		t.Fatal(err)
	}
	if pages != 0 {
		t.Fatalf("block page rows=%d, want 0（删除已提交）", pages)
	}
}

// routedFakeConnector 返回一个按查询内容路由的假 db.DB：不同查询注入不同的
// 行集行为（Scan 失败 / 迭代失败 / 正常），用于注入 ListSecurityPolicies 与
// GetAllSecurityBindings 的循环故障（R37 S1/S2，同 R36 F2 的假连接器模式）。
type routedFakeConnector struct {
	rowsByKind map[string]driver.Rows
}

func (c routedFakeConnector) Connect(context.Context) (driver.Conn, error) {
	return routedFakeConn{rowsByKind: c.rowsByKind}, nil
}

func (routedFakeConnector) Driver() driver.Driver { return routedFakeDriver{} }

type routedFakeDriver struct{}

func (routedFakeDriver) Open(string) (driver.Conn, error) { return routedFakeConn{}, nil }

type routedFakeConn struct{ rowsByKind map[string]driver.Rows }

func (routedFakeConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (routedFakeConn) Close() error { return nil }

func (routedFakeConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (c routedFakeConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	for sub, rows := range c.rowsByKind {
		if strings.Contains(query, sub) {
			return rows, nil
		}
	}
	return &fakeQueryRows{}, nil
}

// fakeQueryRows 是注入用的假行集：依次返回 values 中的行，之后（可选）先空转
// failAfter 次再返回 err（模拟迭代中途失败，只有 rows.Err() 能发现）。
type fakeQueryRows struct {
	values    [][]driver.Value
	failAfter int
	err       error
	i         int
}

func (r *fakeQueryRows) Columns() []string {
	if len(r.values) > 0 {
		return make([]string, len(r.values[0]))
	}
	return []string{"c"}
}

func (fakeQueryRows) Close() error { return nil }

func (r *fakeQueryRows) Next(dest []driver.Value) error {
	if r.i < len(r.values) {
		copy(dest, r.values[r.i])
		r.i++
		return nil
	}
	if r.i-len(r.values) < r.failAfter {
		r.i++
		return nil
	}
	if r.err != nil {
		return r.err
	}
	return io.EOF
}

// fakeDB returns a *sql.DB backed by routedFakeConnector and restores db.DB on cleanup.
func fakeDB(t *testing.T, rowsByKind map[string]driver.Rows) {
	t.Helper()
	fake := sql.OpenDB(routedFakeConnector{rowsByKind: rowsByKind})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })
}

// TestListSecurityPolicies_bindingRowsScanFailureReturns500 验证绑定计数循环的
// Scan 失败使列表显式返回 500，而不是忽略错误以 200 返回（R37 S1）。
func TestListSecurityPolicies_bindingRowsScanFailureReturns500(t *testing.T) {
	// Given a db whose binding-count query delivers a non-integer policy_id
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	fakeDB(t, map[string]driver.Rows{
		"GROUP BY": &fakeQueryRows{values: [][]driver.Value{{[]byte("bad"), int64(1)}}},
	})

	// When the policy list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the binding scan failure surfaces as 500
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

// TestListSecurityPolicies_policyRowsIterationFailureReturns500 验证策略行循环的
// rows.Err() 使列表显式返回 500，而不是「空/部分列表 + 200」（R37 S1，R36 F2 标准）。
func TestListSecurityPolicies_policyRowsIterationFailureReturns500(t *testing.T) {
	// Given a db whose policy query fails mid-iteration（第一步即失败）
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	fakeDB(t, map[string]driver.Rows{
		"GROUP BY":                     &fakeQueryRows{},
		"FROM security_policies ORDER": &fakeQueryRows{err: errors.New("注入的策略行迭代失败")},
	})

	// When the policy list is requested
	recorder := getRequest(t, router, "/security/policies")

	// Then the iteration error surfaces as 500 instead of an empty/partial list + 200
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}

// TestGetAllSecurityBindings_scanFailureSkipsZeroValueBinding 验证单行 Scan 失败
// 时跳过该行而非写入零值绑定（policy_id=0/mode="" 会把规则错误呈现为
// 「已绑定到空策略」）（R37 S2）。
func TestGetAllSecurityBindings_scanFailureSkipsZeroValueBinding(t *testing.T) {
	// Given one binding row whose policy_id cannot scan and one healthy row
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	router.GET("/security/bindings", (&Handlers{}).GetAllSecurityBindings)
	fakeDB(t, map[string]driver.Rows{
		"FROM security_policy_bindings b JOIN": &fakeQueryRows{values: [][]driver.Value{
			{"lb_bad", []byte("bad"), "坏策略", "blocking", int64(1), int64(1)},
			{"lb_ok", int64(7), "好策略", "blocking", int64(1), int64(0)},
		}},
	})

	// When all bindings are requested
	recorder := getRequest(t, router, "/security/bindings")

	// Then the bad row is skipped and only the healthy binding is returned
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data map[string]struct {
			PolicyID int `json:"policy_id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse bindings response: %v", err)
	}
	if resp.Code != 0 {
		t.Fatalf("code=%d body=%s", resp.Code, recorder.Body.String())
	}
	if len(resp.Data) != 1 {
		t.Fatalf("bindings=%+v, want only the healthy row（坏行不得写入零值绑定）", resp.Data)
	}
	if entry, ok := resp.Data["lb_ok"]; !ok || entry.PolicyID != 7 {
		t.Fatalf("lb_ok=%+v, want policy_id=7", entry)
	}
}

// TestGetAllSecurityBindings_iterationFailureReturns500 验证绑定循环的 rows.Err()
// 使接口显式返回 500，而不是「部分绑定 + 200」（R37 S2）。
func TestGetAllSecurityBindings_iterationFailureReturns500(t *testing.T) {
	// Given a binding query that fails mid-iteration（一行之后迭代报错）
	setupSecurityPolicyTestDB(t)
	router := securityR29Router(t)
	router.GET("/security/bindings", (&Handlers{}).GetAllSecurityBindings)
	fakeDB(t, map[string]driver.Rows{
		"FROM security_policy_bindings b JOIN": &fakeQueryRows{
			values: [][]driver.Value{{"lb_ok", int64(7), "好策略", "blocking", int64(1), int64(0)}},
			err:    errors.New("注入的绑定迭代失败"),
		},
	})

	// When all bindings are requested
	recorder := getRequest(t, router, "/security/bindings")

	// Then the iteration error surfaces as 500 instead of a partial map + 200
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
}
