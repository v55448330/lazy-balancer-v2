package handlers

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// TestPolicyWriteTx_serializableIsolationBlocksConcurrentRuleDelete 串行模拟
// R38 三-3 交错（R37 I1 的镜像方向）：策略写入事务的引用校验 SELECT 之后、
// INSERT 之前，并发的规则删除不得提交。BEGIN IMMEDIATE 下校验即持写锁，删除
// 只能等写入事务提交后执行——校验与写入之间不存在插队窗口，写入的策略绝不会
// 引用「校验与写入之间」被删的规则（悬空引用）。
func TestPolicyWriteTx_serializableIsolationBlocksConcurrentRuleDelete(t *testing.T) {
	// Given a custom rule referenced by no policy yet (delete would be legal)
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled) VALUES ('竞态规则', '[]', 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed custom rule: %v", err)
	}
	ruleID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	// 写入侧事务（同修复后 CreateSecurityPolicy 语义）：引用校验 SELECT 即持写锁
	polTx, err := db.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		t.Fatalf("begin policy tx: %v", err)
	}
	defer polTx.Rollback()
	var exists int
	if err := polTx.QueryRowContext(ctx, "SELECT COUNT(*) FROM security_custom_rules WHERE id=?", ruleID).Scan(&exists); err != nil {
		t.Fatalf("reference check: %v", err)
	}
	if exists != 1 {
		t.Fatalf("rule exists=%d, want 1", exists)
	}

	// 并发删除规则（无引用策略，本应合法）在校验之后、INSERT 之前发起
	deleteDone := make(chan error, 1)
	go func() {
		_, err := db.DB.Exec("DELETE FROM security_custom_rules WHERE id=?", ruleID)
		deleteDone <- err
	}()

	// Then the concurrent delete is blocked by the write lock: it cannot commit
	// between the reference check and the INSERT（回归：R38 三-3 写窗口）
	select {
	case err := <-deleteDone:
		t.Fatalf("并发删除已在校验与写入之间完成: %v（回归：R38 三-3 写窗口）", err)
	case <-time.After(200 * time.Millisecond):
	}

	// 写入侧完成 INSERT + Commit（提交时规则必然仍在，无悬空引用）
	if _, err := polTx.ExecContext(ctx, "INSERT INTO security_policies (name, custom_rules, enabled) VALUES ('竞态写入策略', ?, 1)", fmt.Sprintf("[%d]", ruleID)); err != nil {
		t.Fatalf("insert policy: %v", err)
	}
	if err := polTx.Commit(); err != nil {
		t.Fatalf("commit policy tx: %v", err)
	}

	// 并发删除此时才能提交（写入已提交，无死锁）
	select {
	case err := <-deleteDone:
		if err != nil {
			t.Fatalf("并发删除: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("并发删除被永久阻塞")
	}

	// And the enabled policy references a rule that existed at write time —
	// the delete could only commit after the write, never between check and write
	var enabledPolicies int
	if err := db.DB.QueryRow("SELECT COUNT(*) FROM security_policies WHERE enabled=1 AND custom_rules LIKE ?", fmt.Sprintf("%%[%d]%%", ruleID)).Scan(&enabledPolicies); err != nil {
		t.Fatal(err)
	}
	if enabledPolicies != 1 {
		t.Fatalf("enabled policies referencing rule=%d, want 1", enabledPolicies)
	}
}
