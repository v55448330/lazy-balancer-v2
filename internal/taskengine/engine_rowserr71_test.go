package taskengine

// 历史域 A（rows.Err 家族收敛，taskengine 侧）：
//   History 迭代错误/Scan 失败须 warn 留痕（此前静默 continue）
//   Stats24hHourlySeries 同族（与 services/certificates.go 的
//     reconcileMissingCertFiles 正面对照——本文件两处为此前唯二漏网点）

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// taskRowsIterFailConnector：task_runs 查询「语句执行成功、迭代第一步即失败」
// ——只有循环后检查 rows.Err() 才能发现，否则表现为部分/空数据静默返回。
type taskRowsIterFailConnector struct{}

func (taskRowsIterFailConnector) Connect(context.Context) (driver.Conn, error) {
	return taskRowsIterFailConn{}, nil
}
func (taskRowsIterFailConnector) Driver() driver.Driver { return taskRowsIterFailDriver{} }

type taskRowsIterFailDriver struct{}

func (taskRowsIterFailDriver) Open(string) (driver.Conn, error) { return taskRowsIterFailConn{}, nil }

type taskRowsIterFailConn struct{}

func (taskRowsIterFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (taskRowsIterFailConn) Close() error              { return nil }
func (taskRowsIterFailConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (taskRowsIterFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	cols := 0
	switch {
	case strings.Contains(query, "GROUP BY"):
		cols = 3 // Stats24hHourlySeries 聚合列
	case strings.Contains(query, "FROM task_runs"):
		cols = 10 // History 行列
	default:
		return taskIterZeroRows{}, nil
	}
	names := make([]string, cols)
	for i := range names {
		names[i] = fmt.Sprintf("c%d", i)
	}
	return taskIterFailRows{cols: names}, nil
}

type taskIterFailRows struct{ cols []string }

func (r taskIterFailRows) Columns() []string { return r.cols }
func (taskIterFailRows) Close() error        { return nil }
func (taskIterFailRows) Next([]driver.Value) error {
	return errors.New("注入的 task_runs 迭代失败")
}

type taskIterZeroRows struct{}

func (taskIterZeroRows) Columns() []string         { return []string{"c"} }
func (taskIterZeroRows) Close() error              { return nil }
func (taskIterZeroRows) Next([]driver.Value) error { return io.EOF }

// taskRowsQueryFailConnector 在 Query 阶段直接失败，与上面的迭代失败
// 连接器互补：用于钉住 History/HourlySeries 的 rows, err := Query 分支。
type taskRowsQueryFailConnector struct{}

func (taskRowsQueryFailConnector) Connect(context.Context) (driver.Conn, error) {
	return taskRowsQueryFailConn{}, nil
}
func (taskRowsQueryFailConnector) Driver() driver.Driver { return taskRowsIterFailDriver{} }

type taskRowsQueryFailConn struct{ taskRowsIterFailConn }

func (taskRowsQueryFailConn) QueryContext(context.Context, string, []driver.NamedValue) (driver.Rows, error) {
	return nil, errors.New("注入的 task_runs 查询失败")
}

type syncEngineLogBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *syncEngineLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *syncEngineLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// captureEngineLog 捕获标准库日志；异步引擎 goroutine 与断言可同时读写。
func captureEngineLog(t *testing.T) *syncEngineLogBuffer {
	t.Helper()
	buf := &syncEngineLogBuffer{}
	old := log.Writer()
	log.SetOutput(buf)
	t.Cleanup(func() { log.SetOutput(old) })
	return buf
}

// History 循环 rows.Err() 未检查——迭代错误表现为
// 「部分历史 + 静默」；Scan 失败同样静默 continue。修复：两者均 warn 留痕
// （返回形状不变——历史页降级展示已读行，与 taskmonitor 读取侧容错一致）。
func TestEngine_History_iterationErrorWarns(t *testing.T) {
	e := newTestEngine(t)
	buf := captureEngineLog(t)

	orig := db.DB
	broken := sql.OpenDB(taskRowsIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	runs := e.History("t-x", 20)
	if len(runs) != 0 {
		t.Fatalf("迭代失败轮 runs=%d, want 0（无行可读）", len(runs))
	}
	if !strings.Contains(buf.String(), "任务历史") {
		t.Fatalf("History 迭代错误须 warn 留痕, log=%q", buf.String())
	}
}

// Stats24hHourlySeries 聚合循环 rows.Err() 未检查+
// Scan 静默——同批触碰未同步收敛。修复：warn 留痕，24 桶
// 零填形状不变（图表降级为空序列，不崩不缺桶）。
func TestEngine_Stats24hHourlySeries_iterationErrorWarns(t *testing.T) {
	e := newTestEngine(t)
	buf := captureEngineLog(t)

	orig := db.DB
	broken := sql.OpenDB(taskRowsIterFailConnector{})
	t.Cleanup(func() { _ = broken.Close() })
	db.DB = broken
	t.Cleanup(func() { db.DB = orig })

	series := e.Stats24hHourlySeries()
	if len(series) != 24 {
		t.Fatalf("迭代失败轮桶数=%d, want 24（形状不变）", len(series))
	}
	if !strings.Contains(buf.String(), "24h") {
		t.Fatalf("Stats24hHourlySeries 迭代错误须 warn 留痕, log=%q", buf.String())
	}
}

func TestEngine_QueryErrorWarns(t *testing.T) {
	e := newTestEngine(t)
	tests := []struct {
		name   string
		invoke func() int
		want   int
	}{
		{name: "History", invoke: func() int { return len(e.History("t-x", 20)) }, want: 0},
		{name: "Stats24hHourlySeries", invoke: func() int { return len(e.Stats24hHourlySeries()) }, want: 24},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			buf := captureEngineLog(t)
			orig := db.DB
			broken := sql.OpenDB(taskRowsQueryFailConnector{})
			t.Cleanup(func() { _ = broken.Close() })
			db.DB = broken
			t.Cleanup(func() { db.DB = orig })

			if got := tc.invoke(); got != tc.want {
				t.Fatalf("查询失败后的返回形状大小=%d, want %d", got, tc.want)
			}
			if !strings.Contains(buf.String(), "查询失败") {
				t.Fatalf("Query 错误必须 warn 留痕, log=%q", buf.String())
			}
		})
	}
}
