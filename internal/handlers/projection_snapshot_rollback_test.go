package handlers

// 投影快照 IO 失败的写路径收口钉：快照不完整=渲染不可回滚，按乱填保障回滚
// （500+未提交变更不落库+运行配置回已提交视图），绝不按「校验器不可用」
// 退化提交。故障注入为真实只读投影目录（chmod 000 → ReadDir 失败），
// 不用 mock 返回值。

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestFinishTxApply_projectionSnapshotFailureRollsBack(t *testing.T) {
	h := newBackupTestHandlers(t)
	recorder, fake := newApplyThenDropServer(t)
	h.caddyService = services.NewCaddyService(fake.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	seedCommittedRuleForApplyTest(t, "lb_snap", "committed.example.test")

	dir := t.TempDir()
	oldDir := services.IPListDataDir
	services.IPListDataDir = dir
	t.Cleanup(func() {
		services.IPListDataDir = oldDir
		_ = os.Chmod(dir, 0o755) // 恢复可写，t.TempDir 清理才能删除
	})
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod projection dir: %v", err)
	}
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("目录 000 仍可列举（特权运行？），无法构造真实快照失败")
	}

	tx := beginPendingDomainTx(t, "lb_snap")
	c, rec := newApplyTestContext()

	h.finishTxApply(c, tx, txApplyFinish{Resource: "安全策略", AuditAction: "更新", AuditDetail: "策略保存", SuccessMsg: "已保存"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("快照失败必须回滚收口 500, status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if strings.Contains(body, "已保存") || strings.Contains(body, "未生效") {
		t.Fatalf("快照失败不得按退化提交回报「已保存」: %s", body)
	}
	if err := tx.Rollback(); !errors.Is(err, sql.ErrTxDone) {
		t.Fatalf("失败分支必须已回滚事务, Rollback err=%v", err)
	}
	var domain string
	if err := db.DB.QueryRow("SELECT domain FROM lb_rules WHERE caddy_id='lb_snap'").Scan(&domain); err != nil {
		t.Fatalf("read rule: %v", err)
	}
	if domain != "committed.example.test" {
		t.Fatalf("快照失败后未提交变更落库: domain=%q", domain)
	}
	recorder.mu.Lock()
	loads := append([]string(nil), recorder.loads...)
	recorder.mu.Unlock()
	for _, load := range loads {
		if strings.Contains(load, "pending.example.test") {
			t.Fatalf("快照失败不得把候选视图 /load: %s", load)
		}
	}
	var auditCount int
	if err := db.AuditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='更新失败' AND resource='安全策略' AND detail LIKE '%投影快照失败%'").Scan(&auditCount); err != nil {
		t.Fatalf("count audit: %v", err)
	}
	if auditCount == 0 {
		t.Fatal("快照失败分支缺少操作审计")
	}
}

// 严格形态（applyFromTxNote 直调，规则×5/UpdateConfig 通道）：快照失败必须以
// 错误上抛（调用方回滚事务），不得吞成「校验器不可用」放行事务内应用。
func TestApplyFromTxNote_projectionSnapshotFailureReturnsError(t *testing.T) {
	h := newBackupTestHandlers(t)
	_, fake := newApplyThenDropServer(t)
	h.caddyService = services.NewCaddyService(fake.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return nil })
	seedCommittedRuleForApplyTest(t, "lb_snap_strict", "committed.example.test")

	dir := t.TempDir()
	oldDir := services.IPListDataDir
	services.IPListDataDir = dir
	t.Cleanup(func() {
		services.IPListDataDir = oldDir
		_ = os.Chmod(dir, 0o755)
	})
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod projection dir: %v", err)
	}
	if _, err := os.ReadDir(dir); err == nil {
		t.Skip("目录 000 仍可列举（特权运行？），无法构造真实快照失败")
	}

	tx, err := db.DB.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	c, _ := newApplyTestContext()

	note, err := h.applyFromTxNote(c, tx, "快照失败钉", false)
	if err == nil {
		if note != nil {
			note.finalize()
		}
		t.Fatal("严格通道快照失败必须上抛错误（调用方回滚），不得放行事务内应用")
	}
	if !errors.Is(err, services.ErrProjectionSnapshot) {
		t.Fatalf("上抛错误必须携带快照哨兵: %v", err)
	}
}
