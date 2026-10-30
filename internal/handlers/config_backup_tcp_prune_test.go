package handlers

// TCP 规则 L4 不支持绑定清理（pruneTCPUnsupportedBindings，SQL 单源=
// db.TCPRuleUnsupportedBindingPruneSQL）的三形态：
//   - 正常库：只删「含 G2（限流）/G3（WAF）特征」策略的 TCP 绑定，stage0/1
//     合法绑定与 HTTP 绑定不动（L4 阶段 0/1 语义）；
//   - 计数读取失败：DELETE 已成功，错误不得独吞——按 0 计并在日志留痕；
//   - 谓词粒度=（规则,策略）对：同一规则上任一违规绑定不牵连同规则的
//     stage0/1 合法绑定。

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"log"
	"strings"
	"sync"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestPruneTCPUnsupportedBindings_keepsStage01DropsG23(t *testing.T) {
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,listen_port) VALUES
		('lb_prune_tcp','prune-tcp','tcp',9000),
		('lb_prune_http','prune-http','http',80)`); err != nil {
		t.Fatalf("seed rules: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode) VALUES
		(1,'prune-blocking','blocking'),
		(2,'prune-stage0','off'),
		(3,'prune-ratelimit','off')`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_policies SET ip_whitelist='["10.9.9.9/32"]' WHERE id=2;
		UPDATE security_policies SET rate_limit_enabled=1, rate_limit_rps=50 WHERE id=3`); err != nil {
		t.Fatalf("seed policy features: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_prune_tcp',1),('lb_prune_tcp',2),('lb_prune_tcp',3),('lb_prune_http',1)`); err != nil {
		t.Fatalf("seed bindings: %v", err)
	}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()
	dropped, err := pruneTCPUnsupportedBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	// 仅 TCP 规则上的 G3（blocking）与 G2（限流）绑定被清理。
	if dropped != 2 {
		t.Fatalf("dropped=%d, want 2（TCP 的 G2/G3 绑定）", dropped)
	}
	rows, err := tx.Query(`SELECT rule_caddy_id, policy_id FROM security_policy_bindings ORDER BY rule_caddy_id, policy_id`)
	if err != nil {
		t.Fatalf("read remaining: %v", err)
	}
	defer rows.Close()
	type binding struct {
		rule string
		pid  int
	}
	remaining := []binding{}
	for rows.Next() {
		var b binding
		if err := rows.Scan(&b.rule, &b.pid); err != nil {
			t.Fatal(err)
		}
		remaining = append(remaining, b)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := []binding{{"lb_prune_http", 1}, {"lb_prune_tcp", 2}}
	if len(remaining) != len(want) {
		t.Fatalf("remaining=%v, want %v（stage0 与 HTTP 绑定保留）", remaining, want)
	}
	for i, b := range remaining {
		if b != want[i] {
			t.Fatalf("remaining[%d]=%v, want %v", i, b, want[i])
		}
	}
}

// tcpPruneCountFailConn 模拟「Exec 成功但读不出影响行数」的驱动形态：
// 事务提交与否无关，用例只走 Exec + RowsAffected 两步。
type tcpPruneCountFailConn struct{}

func (tcpPruneCountFailConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}
func (tcpPruneCountFailConn) Close() error              { return nil }
func (tcpPruneCountFailConn) Begin() (driver.Tx, error) { return tcpPruneCountFailTx{}, nil }
func (tcpPruneCountFailConn) BeginTx(context.Context, driver.TxOptions) (driver.Tx, error) {
	return tcpPruneCountFailTx{}, nil
}
func (tcpPruneCountFailConn) ExecContext(context.Context, string, []driver.NamedValue) (driver.Result, error) {
	return tcpPruneCountFailResult{}, nil
}

type tcpPruneCountFailTx struct{}

func (tcpPruneCountFailTx) Commit() error   { return nil }
func (tcpPruneCountFailTx) Rollback() error { return nil }

type tcpPruneCountFailResult struct{}

func (tcpPruneCountFailResult) LastInsertId() (int64, error) {
	return 0, errors.New("no last insert id")
}
func (tcpPruneCountFailResult) RowsAffected() (int64, error) {
	return 0, errors.New("rows affected unavailable")
}

type tcpPruneCountFailDriver struct{}

func (tcpPruneCountFailDriver) Open(string) (driver.Conn, error) { return tcpPruneCountFailConn{}, nil }

var tcpPruneCountFailRegister sync.Once

func TestPruneTCPUnsupportedBindings_warnsWhenRowsAffectedFails(t *testing.T) {
	tcpPruneCountFailRegister.Do(func() { sql.Register("tcp-prune-count-fail", tcpPruneCountFailDriver{}) })
	database, err := sql.Open("tcp-prune-count-fail", "")
	if err != nil {
		t.Fatalf("open fake driver: %v", err)
	}
	defer database.Close()
	tx, err := database.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer tx.Rollback()

	var logs strings.Builder
	oldWriter := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(oldWriter)

	dropped, err := pruneTCPUnsupportedBindings(context.Background(), tx)
	if err != nil {
		t.Fatalf("计数失败不得把已成功的清理判为失败: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped=%d, want 0（计数失败按 0 计）", dropped)
	}
	out := logs.String()
	if !strings.Contains(out, "读取影响行数失败") || !strings.Contains(out, "TCP") {
		t.Fatalf("计数失败必须留痕（warn 点名 TCP 绑定清理），got %q", out)
	}
}
