package services

// 摄取批次提交失败的事务恢复：提交失败时 database/sql 会把 Tx 标记 done
// 并把仍持活动事务的连接归还池（driver.Rollback 不再被调用）——泄漏的写事务
// 让后续 tick 持续 "database is locked"。本文件用驱动层替身真实复现该形态，
// 钉住「提交失败必须补发 ROLLBACK」。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	gosqlite "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
)

const commitFailDriverName = "sqlite-commit-fail-recovery-test"

// commitFailDriver 包装 sqlite 驱动：fail 置位时驱动层 Commit 返回错误而
// 不做任何提交（底层事务保持活动）——与 SQLite deferred 约束/IO 类提交失败
// 的可观测后果一致。
type commitFailDriver struct {
	inner gosqlite.Driver
	fail  atomic.Bool
}

func (d *commitFailDriver) Open(name string) (driver.Conn, error) {
	conn, err := d.inner.Open(name)
	if err != nil {
		return nil, err
	}
	return &commitFailConn{Conn: conn, owner: d}, nil
}

type commitFailConn struct {
	driver.Conn
	owner *commitFailDriver
}

func (c *commitFailConn) Begin() (driver.Tx, error) {
	tx, err := c.Conn.Begin()
	if err != nil {
		return nil, err
	}
	return &commitFailTx{Tx: tx, owner: c.owner}, nil
}

func (c *commitFailConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	inner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return c.Begin()
	}
	tx, err := inner.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	return &commitFailTx{Tx: tx, owner: c.owner}, nil
}

type commitFailTx struct {
	driver.Tx
	owner *commitFailDriver
}

func (t *commitFailTx) Commit() error {
	if t.owner.fail.Load() {
		return errors.New("injected commit failure")
	}
	return t.Tx.Commit()
}

var (
	commitFailDriverOnce sync.Once
	commitFailDriverInst = &commitFailDriver{}
)

func registerCommitFailDriver(t *testing.T) *commitFailDriver {
	t.Helper()
	commitFailDriverOnce.Do(func() { sql.Register(commitFailDriverName, commitFailDriverInst) })
	return commitFailDriverInst
}

func TestSecurityEventsIngestion_commitFailureReleasesLeakedTransaction(t *testing.T) {
	// Given 指标库文件（真实 schema）与一条可摄取事务。
	dataDir := t.TempDir()
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	originalMetrics := db.MetricsDB
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldCurrent)
	})
	driverStub := registerCommitFailDriver(t)
	driverStub.fail.Store(false)
	wrapped, err := sql.Open(commitFailDriverName, filepath.Join(dataDir, db.MetricsDBFilename)+"?_pragma=busy_timeout(30000)")
	if err != nil {
		t.Fatal(err)
	}
	// 单连接池：泄漏事务若未回滚，下一轮查询必然落在同一连接上看见未提交行。
	wrapped.SetMaxOpenConns(1)
	db.MetricsDB = wrapped
	t.Cleanup(func() {
		_ = wrapped.Close()
		db.MetricsDB = originalMetrics
	})

	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	noID := strings.Replace(securityEventsFixtureBlocked, `"id": "tx-blocked-1",`, `"id": "",`, 1)
	withDropped := strings.TrimSuffix(securityEventsFixtureBlocked, "}") + `,"messages_dropped":4}`
	if err := os.WriteFile(logPath, []byte(noID+"\n"+withDropped+"\n"), 0o644); err != nil {
	}
	oldAuditLog, oldAuditOffset := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	resetSecurityEventsPollState(t)
	SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath = oldAuditLog, oldAuditOffset
		SecurityEventsSetIngestionHealthForTest(SecurityEventsIngestionStatus{})
	})

	// When 提交失败（驱动层错误，事务保持活动）。
	driverStub.fail.Store(true)
	if got, _ := SecurityEventsPollOnce(); got != 0 {
		t.Fatalf("提交失败轮摄取=%d, want 0（未提交的行不得计入）", got)
	}
	status := SecurityEventsIngestionHealthSnapshot()
	if status.LastError == "" {
		t.Fatalf("提交失败必须进入健康快照: %+v", status)
	}
	if status.MessagesDropped != 0 || status.SkippedRegions != 0 {
		t.Fatalf("failed commit published health deltas early: messages=%d skipped=%d, want 0/0", status.MessagesDropped, status.SkippedRegions)
	}

	// Then 失败分支已补发 ROLLBACK——池上不残留未提交行，连接可继续服务。
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatalf("提交失败后查询失败（泄漏事务未被回滚?）: %v", err)
	}
	if count != 0 {
		t.Fatalf("提交失败后可见行=%d, want 0（泄漏事务必须补发 ROLLBACK）", count)
	}

	// 恢复后下一轮正常摄取（写锁未滞留：偏移未推进，同一事务重放）。
	driverStub.fail.Store(false)
	got, _ := SecurityEventsPollOnce()
	if got != 1 {
		t.Fatalf("恢复轮摄取=%d, want 1", got)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatalf("恢复轮查询失败: %v", err)
	}
	if count != 1 {
		t.Fatalf("恢复轮行数=%d, want 1", count)
	}
	status = SecurityEventsIngestionHealthSnapshot()
	if status.MessagesDropped != 4 || status.SkippedRegions != 1 || !status.DataLoss {
		t.Fatalf("committed health: messages=%d skipped=%d data_loss=%v, want 4/1/true", status.MessagesDropped, status.SkippedRegions, status.DataLoss)
	}
}
