package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

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
