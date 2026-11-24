package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	sqlitedriver "github.com/glebarez/go-sqlite"

	"lazy-balancer-v2/internal/db"
)

var errMFAInjectedRowsAffected = errors.New("injected RowsAffected failure")

type mfaRowsAffectedErrorResult struct{}

func (mfaRowsAffectedErrorResult) LastInsertId() (int64, error) { return 0, nil }
func (mfaRowsAffectedErrorResult) RowsAffected() (int64, error) {
	return 0, errMFAInjectedRowsAffected
}

// 全量失败形态：Exec 成功，但驱动给不出影响行数。
type mfaRowsAffectedErrorConnector struct{}

func (mfaRowsAffectedErrorConnector) Connect(context.Context) (driver.Conn, error) {
	return mfaRowsAffectedErrorConn{}, nil
}
func (mfaRowsAffectedErrorConnector) Driver() driver.Driver { return mfaRowsAffectedErrorDriver{} }

type mfaRowsAffectedErrorDriver struct{}

func (mfaRowsAffectedErrorDriver) Open(string) (driver.Conn, error) {
	return mfaRowsAffectedErrorConn{}, nil
}

type mfaRowsAffectedErrorConn struct{}

func (mfaRowsAffectedErrorConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare")
}
func (mfaRowsAffectedErrorConn) Close() error { return nil }
func (mfaRowsAffectedErrorConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected Begin")
}
func (mfaRowsAffectedErrorConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return mfaRowsAffectedErrorResult{}, nil
}

// 混合形态：读走真实 SQLite，只有激活的 CAS UPDATE 给不出影响行数。
type mfaActivateRowsFailConnector struct {
	dsn   string
	inner driver.Driver
}

func (c mfaActivateRowsFailConnector) Connect(context.Context) (driver.Conn, error) {
	conn, err := c.inner.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &mfaActivateRowsFailConn{Conn: conn}, nil
}
func (c mfaActivateRowsFailConnector) Driver() driver.Driver { return c.inner }

type mfaActivateRowsFailConn struct{ driver.Conn }

func (c *mfaActivateRowsFailConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	if qc, ok := c.Conn.(driver.QueryerContext); ok {
		return qc.QueryContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

func (c *mfaActivateRowsFailConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "UPDATE users SET mfa_enabled=1") {
		return mfaRowsAffectedErrorResult{}, nil
	}
	if ec, ok := c.Conn.(driver.ExecerContext); ok {
		return ec.ExecContext(ctx, query, args)
	}
	return nil, driver.ErrSkip
}

// 影响行数读取失败是基础设施错误：必须原样上抛，不得当成「0 行」误报
// 「用户不存在」（登录二步验证签发挑战）——管理员会按账号问题排障而错过
// 数据库故障。
func TestMFAIssueChallenge_reportsRowsAffectedFailure(t *testing.T) {
	newClusterTestService(t)
	realDB := db.DB
	fake := sql.OpenDB(mfaRowsAffectedErrorConnector{})
	db.DB = fake
	t.Cleanup(func() { db.DB = realDB; _ = fake.Close() })

	_, err := MFAIssueChallenge(1)
	if err == nil || !errors.Is(err, errMFAInjectedRowsAffected) {
		t.Fatalf("影响行数读取失败必须原样上抛，不得误报「用户不存在」: %v", err)
	}
}

// 同族：激活的二步验证（CAS 把 pending 密钥转正）在影响行数读取失败时
// 不得误报「密钥已变更」。
func TestMFAActivate_reportsRowsAffectedFailure(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB, oldCurrent := db.DB, db.MetricsDB, db.AuditDB, db.GetDB()
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		restoreGlobalDBHandles(oldDB, oldMetricsDB, oldAuditDB, oldCurrent)
	})
	mfaSeedUser(t, 7)
	if _, err := db.DB.Exec(`UPDATE users SET mfa_pending_secret='JBSWY3DPEHPK3PXP' WHERE id=7`); err != nil {
		t.Fatal(err)
	}

	hybrid := sql.OpenDB(mfaActivateRowsFailConnector{dsn: filepath.Join(dataDir, "lazy-balancer.db"), inner: &sqlitedriver.Driver{}})
	db.DB = hybrid
	t.Cleanup(func() { _ = hybrid.Close() })

	_, err := MFAActivate(7)
	if err == nil || !errors.Is(err, errMFAInjectedRowsAffected) {
		t.Fatalf("影响行数读取失败必须原样上抛，不得误报「密钥已变更」: %v", err)
	}
}
