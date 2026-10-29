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

// aggregateFailingConnector 返回一个假 metrics 库：按语句语义路由——rollup
// 状态/覆盖起点返回可扫描的字符串、标量计数与趋势返回数字零值、类型聚合返回
// 空集，仅综合攻击 Top IP 的维度聚合「语句执行成功、迭代第一步即失败」。
// 前置查询全部给出本用例需要的合法形状，确保唯一失败源是聚合循环的
// rows.Err() 检查：若该检查缺失，端点会以「部分数据 + 200」通过。
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

// QueryContext 只按「返回形状」路由，不依赖具体列清单：前置标量必须先给出
// 与生产同形的可扫描值，否则更早的类型不匹配错误会掩盖聚合迭代失败。
func (aggregateFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	q := strings.Join(strings.Fields(query), " ")
	switch {
	case strings.Contains(q, "MIN(event_time)"):
		// 原始事件覆盖起点：空表 = 空串。
		return scratchRowsOf([]string{"earliest"}, driver.Value("")), nil
	case strings.Contains(q, "FROM metrics_state"):
		// rollup 水位/代际状态：空串 = 未初始化（走原始表回退分支）。
		return scratchRowsOf([]string{"value"}, driver.Value("")), nil
	case strings.Contains(q, "GROUP BY client_ip"):
		// 综合攻击 Top IP 维度聚合：语句成功、迭代即失败。只有检查
		// rows.Err() 才能发现，否则表现为「部分数据 + 200」。
		return aggregateFailingRows{}, nil
	case strings.Contains(q, "GROUP BY action"):
		// rollup 按 action 汇总（本用例走不到，给同形空集兜底）。
		return scratchRowsOf([]string{"action", "total"}), nil
	case strings.Contains(q, "GROUP BY rule_triggered"):
		// 攻击类型/攻击族聚合：空集。
		return scratchRowsOf([]string{"rule_triggered", "rule_msg", "cnt"}), nil
	case strings.Contains(q, "SUM(CASE WHEN action='blocked'"):
		// 7 日趋势单日两列计数。
		return scratchRowsOf([]string{"blocked", "detected"}, int64(0), int64(0)), nil
	default:
		// 标量计数（今日拦截/检测等）。
		return scratchRowsOf([]string{"c"}, int64(0)), nil
	}
}

type aggregateFailingRows struct{}

func (aggregateFailingRows) Columns() []string {
	return []string{"client_ip", "blocked", "detected", "last_time"}
}

func (aggregateFailingRows) Close() error { return nil }

func (aggregateFailingRows) Next([]driver.Value) error {
	return errors.New("注入的聚合迭代失败")
}

// scratchRowsOf 返回一次性固定行集：cols 决定列数，values 为唯一一行；
// 无 values 时是合法空集。
func scratchRowsOf(cols []string, values ...driver.Value) *scratchRows {
	return &scratchRows{cols: cols, row: values}
}

type scratchRows struct {
	cols []string
	row  []driver.Value
}

func (r *scratchRows) Columns() []string { return r.cols }

func (r *scratchRows) Close() error { return nil }

func (r *scratchRows) Next(dest []driver.Value) error {
	if r.row == nil {
		return io.EOF
	}
	row := r.row
	r.row = nil
	copy(dest, row)
	return nil
}

// TestGetSecurityOverview_aggregateIterationFailureReturns500 验证聚合循环的
// 迭代错误（rows.Err()）使总览显式返回 500，而不是部分数据 + 200
// 与在 ListSecurityEvents 建立的标准一致）。
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
// 查询成功返回既定行，仅 security_policy_bindings 的迭代「语句成功、迭代即
// 报错」，用于钉住「迭代失败必须显式 500、不得以零绑定继续」。
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
		// 携带信任条目的 mixed 策略（trustEntriesNonEmpty=true）：拆分门
		// 「无可拆特征组 400」必须放行，才能到达绑定行查询——空特征形态已由
		// 「specs 构造后即 400」的判定拦截（绑定查询不再执行，见
		// TestSplitSecurityPolicy_emptyFeaturesRejectsBeforeAnyQuery）。
		return &rowsErrFixedRows{cols: securityRowsErrPolicyColumns, rows: [][]driver.Value{{
			int64(1), "混拆迁移", "", "off", int64(5), "", "[]", int64(0), int64(1), `["203.0.113.7"]`, "[]",
			int64(0), int64(0), int64(0), "[]", "[]", "[]", int64(0), int64(0), int64(1), int64(0),
			"", "", "[]", "off", int64(0), "[]", int64(0), int64(0), "[]", "[]", "mixed", int64(0),
		}}}, nil
	case strings.Contains(query, "FROM security_policies WHERE name=? AND policy_type=?"):
		// 同名子策略解析：无存量 → 复用判定为 0（待插入）。
		return &rowsErrFixedRows{cols: securityRowsErrPolicyColumns}, nil
	case strings.Contains(query, "SELECT COUNT(*) FROM security_policies"):
		// 全局策略数量门：0 条 → 不触上限。
		return &rowsErrFixedRows{cols: []string{"c"}, rows: [][]driver.Value{{int64(0)}}}, nil
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
	// 500 文案按安全域口径泛化（存储层错误只进服务端日志，不外泄表名/SQL
	// 片段）：本用例的判据是「迭代失败必须 500、不得以部分绑定 200 放行」，
	// 错误原文由 serverErrMsg 落日志。
	if strings.Contains(recorder.Body.String(), "注入的策略绑定迭代失败") {
		t.Fatalf("body=%s, 不得向调用方回传存储层错误原文", recorder.Body.String())
	}
}

// 「无可拆特征组」400 判定已前移到 specs 构造之后、任何查询/插入之前：
// 空特征 mixed 策略拆分必须 400 且零子策略、零绑定查询（判定只依赖
// features/trustEntriesNonEmpty，与绑定行无关）。
func TestSplitSecurityPolicy_emptyFeaturesRejectsBeforeAnyQuery(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode,ip_acl_enabled,rate_limit_enabled,block_page_id,block_status_code,policy_type,enabled)
		VALUES ('empty-mix','off',0,0,0,403,'mixed',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := res.LastInsertId()

	router := splitRouter(t)
	recorder := postSplit(t, router, int(id))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "没有可拆分的特征组") {
		t.Fatalf("body=%s, want 点名无可拆特征组", recorder.Body.String())
	}
	var policies, bindings int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies").Scan(&policies); err != nil {
		t.Fatal(err)
	}
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policy_bindings").Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if policies != 1 || bindings != 0 {
		t.Fatalf("拆分副作用 policies=%d bindings=%d, want 1/0（零子策略）", policies, bindings)
	}
}

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
	// 500 文案按安全域口径泛化（存储层错误只进服务端日志，不外泄表名/SQL
	// 片段）：本用例的判据是「迭代失败必须 500、不得以部分绑定 200 放行」，
	// 错误原文由 serverErrMsg 落日志。
	if strings.Contains(recorder.Body.String(), "注入的策略绑定迭代失败") {
		t.Fatalf("body=%s, 不得向调用方回传存储层错误原文", recorder.Body.String())
	}
}
