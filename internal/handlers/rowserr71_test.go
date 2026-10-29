package handlers

// 历史域 A（rows.Err 家族收敛）：三处 RED 钉测——
//   GetThreatLib 迭代错误 → 500
//   GetAuditLogOptions fetchDistinct 迭代/Scan 失败须 warn+不写缓存
//   DeleteUser 级联 Key 清单迭代失败须 warn（白名单缓存清扫缺口留痕）

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// rowsErrStubConnector 通用「语句执行成功、迭代第一步即失败」驱动：match 命中
// 的查询返回失败行集（cols 列），其余查询返回空行集——只有循环后检查
// rows.Err() 才能发现，否则表现为「部分数据 + 200」（与 security_regression_02_test.go
// 的 aggregateFailingConnector 同型，注入面通用化）。
type rowsErrStubConnector struct {
	match func(query string) bool
	cols  int
}

func (c rowsErrStubConnector) Connect(context.Context) (driver.Conn, error) {
	return &rowsErrStubConn{match: c.match, cols: c.cols}, nil
}
func (rowsErrStubConnector) Driver() driver.Driver { return rowsErrStubDriver{} }

type rowsErrStubDriver struct{}

func (rowsErrStubDriver) Open(string) (driver.Conn, error) {
	return &rowsErrStubConn{}, nil
}

type rowsErrStubConn struct {
	match func(query string) bool
	cols  int
}

func (c *rowsErrStubConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (c *rowsErrStubConn) Close() error              { return nil }
func (c *rowsErrStubConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (c *rowsErrStubConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if c.match != nil && c.match(query) {
		cols := make([]string, c.cols)
		for i := range cols {
			cols[i] = fmt.Sprintf("c%d", i)
		}
		return rowsErrFailRows{cols: cols}, nil
	}
	return rowsErrZeroRows{}, nil
}

type rowsErrFailRows struct{ cols []string }

func (r rowsErrFailRows) Columns() []string       { return r.cols }
func (rowsErrFailRows) Close() error              { return nil }
func (rowsErrFailRows) Next([]driver.Value) error { return errors.New("注入的迭代失败") }

type rowsErrZeroRows struct{}

func (rowsErrZeroRows) Columns() []string         { return []string{"c"} }
func (rowsErrZeroRows) Close() error              { return nil }
func (rowsErrZeroRows) Next([]driver.Value) error { return io.EOF }

// captureLog 捕获标准库日志输出（services.Logf 的 warn/error 落点）。
func captureLog(t *testing.T) *strings.Builder {
	t.Helper()
	preserveApplicationLogLevel(t, "info")
	var buf strings.Builder
	old := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return &buf
}

// GetThreatLib 主查询迭代错误（rows.Err）
// 时此前仍以「部分/空列表 + 200」返回——与在 GetSecurityOverview/
// ListSecurityEvents 建立的「残缺列表不得以 200」口径冲突。修复：循环后补
// rows.Err() → 500（与 Scan 失败分支同响应形）。
func TestThreatLib_listIterationFailureReturns500(t *testing.T) {
	router := newThreatTestRouter(t)

	orig := db.DB
	broken := sql.OpenDB(rowsErrStubConnector{
		match: func(q string) bool { return strings.Contains(q, "FROM security_threat_sources") },
		cols:  12,
	})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/security/threat-lib", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（迭代错误不得以部分数据 + 200 返回）", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "读取威胁情报库失败") {
		t.Fatalf("body=%s, want 显式失败消息", rec.Body.String())
	}
}

// fetchDistinct 单行 Scan 失败此前静默丢行、迭代错误
// （rows.Err）更整段吞掉且 fetchErr 不置位——空下拉会被缓存门放行
// 写入 60s 缓存。修复：Scan 失败 warn；rows.Err 上抛 fetchErr（响应仍 200 部分
// 数据，但缓存门按口径拦下故障轮）。本测试钉「迭代失败轮不毒化
// 缓存」+ warn 留痕（与 audit_options_regression_01_test.go 的查询失败形状互补）。
func TestAuditLogOptions_iterationErrorRoundDoesNotPoisonCache(t *testing.T) {
	router, _ := newAuditLogRouter(t)
	t.Cleanup(resetAuditOptionsCacheForTest)
	resetAuditOptionsCacheForTest()

	if _, err := db.AuditDB.Exec(`INSERT INTO audit_log (username, action, resource, detail, ip_address) VALUES ('iter-recover', '登录', '用户认证', '', '1.1.1.1')`); err != nil {
		t.Fatal(err)
	}
	buf := captureLog(t)
	get := func() []string {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit-logs/options", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("options status=%d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			Data struct {
				Usernames []struct {
					Value string `json:"value"`
				} `json:"usernames"`
			} `json:"data"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		out := []string{}
		for _, u := range resp.Data.Usernames {
			out = append(out, u.Value)
		}
		return out
	}

	// 第一轮：三条 GROUP BY 全部「执行成功、迭代失败」→ 空选项
	healthy := db.AuditDB
	broken := sql.OpenDB(rowsErrStubConnector{
		match: func(q string) bool { return strings.Contains(q, "GROUP BY") },
		cols:  2,
	})
	t.Cleanup(func() { _ = broken.Close() })
	db.AuditDB = broken
	first := get()
	db.AuditDB = healthy
	if len(first) != 0 {
		t.Fatalf("迭代失败轮应返回空选项, got %v", first)
	}
	if !strings.Contains(buf.String(), "审计日志下拉") {
		t.Fatalf("迭代失败须 warn 留痕, log=%q", buf.String())
	}

	// 第二轮（60s 缓存窗口内）：不得命中故障轮写下的空缓存
	second := get()
	found := false
	for _, v := range second {
		if v == "iter-recover" {
			found = true
		}
	}
	if !found {
		t.Fatalf("60s 窗口内第二次 options 须重新拉取真实数据（迭代失败轮不得写缓存）, got %v", second)
	}
}

// deleteKeyIterFailConnector：DeleteUser 事务链驱动桩——目标用户单行查询
// 正常返回、api_keys 级联清单「执行成功、迭代失败」、Exec 恒成功、Begin/Commit
// 恒成功。用于注入 keyRows 迭代错误。
type deleteKeyIterFailConnector struct{}

func (deleteKeyIterFailConnector) Connect(context.Context) (driver.Conn, error) {
	return &deleteKeyIterFailConn{}, nil
}
func (deleteKeyIterFailConnector) Driver() driver.Driver { return deleteKeyIterFailDriver{} }

type deleteKeyIterFailDriver struct{}

func (deleteKeyIterFailDriver) Open(string) (driver.Conn, error) {
	return &deleteKeyIterFailConn{}, nil
}

type deleteKeyIterFailConn struct{}

func (deleteKeyIterFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (deleteKeyIterFailConn) Close() error { return nil }
func (deleteKeyIterFailConn) Begin() (driver.Tx, error) {
	return deleteKeyFakeTx{}, nil
}
func (deleteKeyIterFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	// 保护标记查询（DeleteUser 前置门）必须与目标用户行查询分判：标记缺失
	// （零行）按缺省判定处理，不影响本用例要验证的级联清单迭代失败路径。
	case strings.Contains(query, "is_setup_admin"):
		return rowsErrZeroRows{}, nil
	case strings.Contains(query, "FROM users WHERE id"):
		return &deleteTargetUserRows{}, nil
	case strings.Contains(query, "FROM api_keys WHERE created_by"):
		return rowsErrFailRows{cols: []string{"id"}}, nil
	}
	return rowsErrZeroRows{}, nil
}
func (deleteKeyIterFailConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return driver.RowsAffected(1), nil
}

type deleteKeyFakeTx struct{}

func (deleteKeyFakeTx) Commit() error   { return nil }
func (deleteKeyFakeTx) Rollback() error { return nil }

type deleteTargetUserRows struct{ done bool }

func (deleteTargetUserRows) Columns() []string {
	return []string{"username", "role", "is_enabled", "auth_provider"}
}
func (*deleteTargetUserRows) Close() error { return nil }
func (r *deleteTargetUserRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0], dest[1], dest[2], dest[3] = "victim", "user", int64(1), "local"
	return nil
}

// DeleteUser 级联 Key 清单迭代失败此前静默——部分
// 删除的 Key 白名单解析缓存不清扫（孤儿缓存驻留）。修复：keyRows.Err() warn
// 留痕（删除照常——warn-only 口径，与 fail-closed 不同：本清单仅驱动
// 缓存清扫，孤儿缓存无越权面）。
func TestDeleteUser_cascadeKeyIterationErrorWarns(t *testing.T) {
	h := newBackupTestHandlers(t)
	buf := captureLog(t)

	orig := db.DB
	broken := sql.OpenDB(deleteKeyIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	response := serveUserMutation(h, http.MethodDelete, "/users/2", "", 1, h.DeleteUser)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（迭代失败 warn-only，删除照常）", response.Code, response.Body.String())
	}
	if !strings.Contains(buf.String(), "级联 Key 清单") {
		t.Fatalf("级联 Key 清单迭代失败须 warn 留痕, log=%q", buf.String())
	}
}
