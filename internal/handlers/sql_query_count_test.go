package handlers

// 主库/指标库语句计数钉测基础设施：用包装驱动统计真实 SQLite 上发出的语句
// （同 system_task_logs_test.go 的连接器范式），而不是按源码字面量估算。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
)

// sqlQueryRecorder 记录经计数连接执行过的语句文本。
type sqlQueryRecorder struct {
	mu      sync.Mutex
	queries []string
}

func (r *sqlQueryRecorder) record(query string) {
	r.mu.Lock()
	r.queries = append(r.queries, query)
	r.mu.Unlock()
}

// reset 丢弃已记录语句（只统计断言窗口内的语句）。
func (r *sqlQueryRecorder) reset() {
	r.mu.Lock()
	r.queries = nil
	r.mu.Unlock()
}

// count 统计匹配 match 的语句条数。
func (r *sqlQueryRecorder) count(match func(query string) bool) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	matched := 0
	for _, query := range r.queries {
		if match(query) {
			matched++
		}
	}
	return matched
}

type queryCountingConnector struct {
	dsn   string
	inner driver.Driver
	rec   *sqlQueryRecorder
}

func (c queryCountingConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &queryCountingConn{Conn: conn, rec: c.rec}, nil
}

func (c queryCountingConnector) Driver() driver.Driver { return c.inner }

// queryCountingConn 只统计 Prepare：database/sql 在 conn 未实现
// Queryer/Execer 接口时一律经 Prepare 执行语句（每条语句计一次）。
type queryCountingConn struct {
	driver.Conn
	rec *sqlQueryRecorder
}

func (c *queryCountingConn) Prepare(query string) (driver.Stmt, error) {
	c.rec.record(query)
	return c.Conn.Prepare(query)
}

// countingDB 用同目录同文件的计数连接替换指定句柄（由 swap 决定），并接管
// 三库句柄的清理与还原。
func countingDB(t *testing.T, filename string, swap func(counting *sql.DB)) *sqlQueryRecorder {
	t.Helper()
	dataDir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(dataDir); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatalf("initialize metrics database: %v", err)
	}
	recorder := &sqlQueryRecorder{}
	swap(sql.OpenDB(queryCountingConnector{
		dsn:   filepath.Join(dataDir, filename) + "?_pragma=busy_timeout(30000)",
		inner: &sqlitedriver.Driver{},
		rec:   recorder,
	}))
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
	return recorder
}

// countingMainDB 主库换成语句计数连接。
func countingMainDB(t *testing.T) *sqlQueryRecorder {
	t.Helper()
	return countingDB(t, "lazy-balancer.db", func(counting *sql.DB) {
		original := db.DB
		db.DB = counting
		db.SetDB(counting)
		if err := original.Close(); err != nil {
			t.Fatalf("close original handle: %v", err)
		}
	})
}

// countingMetricsDB 指标库换成语句计数连接。
func countingMetricsDB(t *testing.T) *sqlQueryRecorder {
	t.Helper()
	return countingDB(t, db.MetricsDBFilename, func(counting *sql.DB) {
		original := db.MetricsDB
		db.MetricsDB = counting
		if err := original.Close(); err != nil {
			t.Fatalf("close original metrics handle: %v", err)
		}
	})
}

// policyRowReadMatch 命中「对 security_policies 的单行读」（更新端点读取面）。
func policyRowReadMatch(query string) bool {
	return strings.HasPrefix(strings.TrimSpace(query), "SELECT") && strings.Contains(query, "FROM security_policies")
}
