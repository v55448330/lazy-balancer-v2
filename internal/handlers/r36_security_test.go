package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// aggregateFailingConnector 返回一个假 metrics 库：GROUP BY 聚合查询「语句执行
// 成功、迭代第一步即失败」，标量 COUNT 查询正常返回 0。用于注入聚合循环的
// rows.Err() 故障（R36 F2）。
type aggregateFailingConnector struct{}

func (aggregateFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return aggregateFailingConn{}, nil
}

func (aggregateFailingConnector) Driver() driver.Driver { return aggregateFailingDriver{} }

type aggregateFailingDriver struct{}

func (aggregateFailingDriver) Open(string) (driver.Conn, error) { return aggregateFailingConn{}, nil }

type aggregateFailingConn struct{}

func (aggregateFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (aggregateFailingConn) Close() error { return nil }

func (aggregateFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (aggregateFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "GROUP BY") {
		// 聚合语句成功返回行集，但迭代失败：只有检查 rows.Err() 才能被发现，
		// 否则表现为「部分数据 + 200」
		return aggregateFailingRows{}, nil
	}
	return &scalarZeroRows{}, nil
}

type aggregateFailingRows struct{}

func (aggregateFailingRows) Columns() []string { return []string{"c"} }

func (aggregateFailingRows) Close() error { return nil }

func (aggregateFailingRows) Next([]driver.Value) error {
	return errors.New("注入的聚合迭代失败")
}

type scalarZeroRows struct{ done bool }

func (r *scalarZeroRows) Columns() []string { return []string{"c"} }

func (r *scalarZeroRows) Close() error { return nil }

func (r *scalarZeroRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = int64(0)
	return nil
}

// TestGetSecurityOverview_aggregateIterationFailureReturns500 验证聚合循环的
// 迭代错误（rows.Err()）使总览显式返回 500，而不是部分数据 + 200（R36 F2，
// 与 R35 D3 在 ListSecurityEvents 建立的标准一致）。
func TestGetSecurityOverview_aggregateIterationFailureReturns500(t *testing.T) {
	// Given a metrics store whose aggregate queries fail mid-iteration
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	broken := sql.OpenDB(aggregateFailingConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.MetricsDB
	db.MetricsDB = broken
	t.Cleanup(func() { db.MetricsDB = orig })

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the iteration error surfaces as 500 instead of partial data + 200
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "安全总览查询失败") {
		t.Fatalf("body=%s, want explicit overview failure message", recorder.Body.String())
	}
}

// securityRowsErrConnector：按语句路由的假库——让批量绑定/拆分迁移的前置
// 查询成功返回既定行，仅 security_policy_bindings 迭代「语句成功、迭代即
// 失败」，注入 R71-⑬ 两个 rows.Err() 缺口（R36/R37 口径）。
type securityRowsErrConnector struct{}

func (securityRowsErrConnector) Connect(context.Context) (driver.Conn, error) {
	return securityRowsErrConn{}, nil
}

func (securityRowsErrConnector) Driver() driver.Driver { return securityRowsErrDriver{} }

type securityRowsErrDriver struct{}

func (securityRowsErrDriver) Open(string) (driver.Conn, error) { return securityRowsErrConn{}, nil }

type securityRowsErrConn struct{}

func (securityRowsErrConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (securityRowsErrConn) Close() error { return nil }

func (securityRowsErrConn) Begin() (driver.Tx, error) { return rowsErrNoOpTx{}, nil }

func (securityRowsErrConn) ExecContext(_ context.Context, _ string, _ []driver.NamedValue) (driver.Result, error) {
	return rowsErrNoOpResult{}, nil
}

func (securityRowsErrConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "SELECT COUNT(*), COALESCE(MAX(protocol)"):
		return &rowsErrFixedRows{cols: []string{"c", "p"}, rows: [][]driver.Value{{int64(1), "http"}}}, nil
	case strings.Contains(query, "FROM security_policies WHERE id=?"):
		// 空 mixed 策略（特征组全空）：不触发生成子策略，直达绑定行查询
		return &rowsErrFixedRows{cols: securityRowsErrPolicyColumns, rows: [][]driver.Value{{
			int64(1), "混拆迁移", "", "off", int64(5), "", "[]", int64(0), int64(1), "[]", "[]",
			int64(0), int64(0), int64(0), "[]", "[]", "[]", int64(0), int64(0), int64(1), int64(0),
			"", "", "[]", "off", int64(0), "[]", int64(0), int64(0), "[]", "[]", "mixed", int64(0),
		}}}, nil
	case strings.Contains(query, "FROM security_policy_bindings"):
		return rowsErrFailingRows{cols: []string{"x"}}, nil
	default:
		return nil, fmt.Errorf("unexpected query: %s", query)
	}
}

var securityRowsErrPolicyColumns = []string{
	"id", "name", "description", "mode", "anomaly_threshold", "ip_acl_mode", "ip_acl_list", "ip_acl_enabled",
	"ip_whitelist_enabled", "ip_whitelist", "ip_blacklist", "rate_limit_enabled", "rate_limit_rps", "rate_limit_burst",
	"crs_rule_groups", "crs_excluded_rules", "custom_rules", "block_page_id", "block_status_code", "enabled",
	"updated_by", "created_at", "updated_at", "geoip_countries", "geoip_mode", "geoip_crawler_exempt", "geoip_crawler_engines",
	"waf_check_response", "log_request_body", "ip_acl_list_refs", "ip_whitelist_refs", "policy_type", "trust_detection",
}

type rowsErrNoOpTx struct{}

func (rowsErrNoOpTx) Commit() error   { return nil }
func (rowsErrNoOpTx) Rollback() error { return nil }

type rowsErrNoOpResult struct{}

func (rowsErrNoOpResult) LastInsertId() (int64, error) { return 0, nil }
func (rowsErrNoOpResult) RowsAffected() (int64, error) { return 0, nil }

type rowsErrFixedRows struct {
	cols []string
	rows [][]driver.Value
}

func (r *rowsErrFixedRows) Columns() []string { return r.cols }
func (r *rowsErrFixedRows) Close() error      { return nil }

func (r *rowsErrFixedRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	row := r.rows[0]
	r.rows = r.rows[1:]
	copy(dest, row)
	return nil
}

type rowsErrFailingRows struct{ cols []string }

func (r rowsErrFailingRows) Columns() []string { return r.cols }
func (r rowsErrFailingRows) Close() error      { return nil }

func (r rowsErrFailingRows) Next([]driver.Value) error {
	return errors.New("注入的策略绑定迭代失败")
}

// R71-⑬：批量绑定 existingRows 迭代失败须显式 500——漏查 rows.Err() 会把
// 「部分读取（空 existing）」当成功继续 merge/写入，静默丢绑定差异。
func TestBatchBindSecurityPolicies_existingIterationFailureReturns500(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	broken := sql.OpenDB(securityRowsErrConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.DB
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	router := gin.New()
	router.POST("/security/policies/batch-bind", handler.BatchBindSecurityPolicies)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/security/policies/batch-bind",
		strings.NewReader(`{"rule_ids":["lb_rows_err"],"policy_ids":[],"mode":"merge"}`))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "注入的策略绑定迭代失败") {
		t.Fatalf("body=%s, want injected iteration error surfaced", recorder.Body.String())
	}
}

// R71-⑬：拆分迁移 ruleRows 迭代失败须显式 500——漏查会以「零绑定规则」走完
// 全量重映射并删除原策略，静默丢防护绑定。
func TestSplitSecurityPolicy_ruleIterationFailureReturns500(t *testing.T) {
	handler, _ := newStageBatchTestHandlers(t)
	broken := sql.OpenDB(securityRowsErrConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	orig := db.DB
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	router := gin.New()
	router.POST("/security/policies/:id/split", handler.SplitSecurityPolicy)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/security/policies/1/split", nil)
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "注入的策略绑定迭代失败") {
		t.Fatalf("body=%s, want injected iteration error surfaced", recorder.Body.String())
	}
}
