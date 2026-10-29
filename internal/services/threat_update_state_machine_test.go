package services

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// 降级零写 裁定（从节点零写优先）：节点降级途中的中止不再给源行落终态——
// 从节点 DB 由集群同步收敛，中止仅以任务日志「降级中止」留痕；源行滞留
// running 由下次主节点同步覆盖（旧形态写 skipped 终态，违反从节点只读不变量）。
func TestThreatUpdate_demoteMidRun_doesNotWriteSourceRow(t *testing.T) {
	overrideWafDirForTest(t)
	newClusterTestService(t)
	setupThreatTest(t, nil, nil, nil)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.DB.Exec(`UPDATE global_config SET is_master=1 WHERE id=1`) })

	var id int
	var url string
	if err := db.DB.QueryRow(`SELECT id, url FROM security_threat_sources WHERE name='ustc'`).Scan(&id, &url); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	changed, failed, _ := GetThreatUpdateManager().updateOneSource(ctx, threatSourceRow{id: id, name: "ustc", url: url}, "manual", "2026.10.20 00:00:00")

	if changed || failed {
		t.Fatalf("changed=%v failed=%v, want (false,false)（demote 中止非故障）", changed, failed)
	}
	var status, message string
	if err := db.DB.QueryRow(`SELECT update_status, COALESCE(message,'') FROM security_threat_sources WHERE id=?`, id).Scan(&status, &message); err != nil {
		t.Fatal(err)
	}
	// 源行保持中止前由 running 标记写入的状态——降级中止零写（ skipped
	// 终态落库已随「从节点零写优先」裁定退役）。
	if status != "running" {
		t.Fatalf("status=%q, want running（demote 中止不得写源行终态，从节点零写）", status)
	}
	if message != "" {
		t.Fatalf("message=%q, want 空（降级中止不写库，留痕仅走任务日志）", message)
	}
}

// （错误传播）：成功状态落库失败不得让任务仍报 success。
func TestMarkSourceSuccess_returnsStoreError(t *testing.T) {
	if err := initSecurityEventsTestDB(t, t.TempDir()); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.DB.QueryRow(`SELECT id FROM security_threat_sources WHERE name='ustc'`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	orig := db.DB
	fake := sql.OpenDB(threatUpdateFailConnector{})
	db.DB = fake
	t.Cleanup(func() {
		db.DB = orig
		_ = fake.Close()
	})

	if err := markSourceSuccess(id, 3, "2026.10.20 00:00:00", "manual"); err == nil {
		t.Fatal("落库失败必须以错误返回（否则任务终态 success 掩盖状态机不闭环）")
	}
}

type threatUpdateFailConnector struct{}

func (threatUpdateFailConnector) Connect(context.Context) (driver.Conn, error) {
	return threatUpdateFailConn{}, nil
}

func (threatUpdateFailConnector) Driver() driver.Driver { return threatUpdateFailDriver{} }

type threatUpdateFailDriver struct{}

func (threatUpdateFailDriver) Open(string) (driver.Conn, error) { return nil, errors.New("not used") }

type threatUpdateFailConn struct{}

func (threatUpdateFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (threatUpdateFailConn) Close() error { return nil }

func (threatUpdateFailConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (threatUpdateFailConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	if strings.Contains(query, "security_threat_sources") {
		return nil, errors.New("注入的读故障")
	}
	return &fakeEmptyRows{columns: []string{"x"}}, nil
}

func (threatUpdateFailConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	return nil, errors.New("注入的写故障")
}
