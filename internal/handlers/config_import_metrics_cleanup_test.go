package handlers

// 提交后产物清理的两条逐项真实性契约：
//  ① 指标删除失败必须与证书文件/规则日志/证书日志同形——逐项进审计页，
//     不能只有运行日志（运维在审计台账看不到哪条规则的指标残留）。
//  ② importCleanupBudget 是真实 ctx 截止：预算耗尽分支必须能被真实超时
//     驱动（而非仅 stub stop 旗标），未处理项的文件必须保留在磁盘。

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given 消失规则的指标删除遭遇真实驱动级故障（表被改名 → no such table）。
// When 提交后清理执行。
// Then 逐项审计恰一条点名该规则指标失败；摘要不得断言「已清理」。
func TestRunPostCommitCleanup_metricsFailureAuditedPerRule(t *testing.T) {
	newBackupTestHandlers(t)
	const ruleID = "lb_metrics_cleanup_fail"
	if _, err := db.MetricsDB.Exec(`ALTER TABLE metrics_history RENAME TO metrics_history_bak`); err != nil {
		t.Fatalf("inject metrics failure: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.MetricsDB.Exec(`ALTER TABLE metrics_history_bak RENAME TO metrics_history`)
	})

	session := &configImportSession{ctx: context.Background()}
	session.runPostCommitCleanup(&importArtifactCleanupPlan{disappeared: []string{ruleID}})

	if got := countAuditMatching(t, `action='清理失败' AND resource='指标' AND detail LIKE '%`+ruleID+` 的指标失败%'`); got != 1 {
		t.Fatalf("指标删除失败逐项审计=%d, want 1（与证书文件/日志同形，不能只有运行日志）", got)
	}
	if got := countAuditMatching(t, `detail LIKE '%已清理其证书文件、指标与日志%'`); got != 0 {
		t.Fatalf("失败轮仍写「已清理」摘要 %d 条（审计真实性）", got)
	}
	if got := countAuditMatching(t, `action='清理失败' AND resource='证书产物' AND detail LIKE '%产物清理未全部完成%指标失败 1%'`); got != 1 {
		t.Fatalf("部分失败摘要审计=%d, want 1（点名指标失败计数）", got)
	}
}

// Given 两条消失规则各有真实证书文件，清理预算被缩到 50ms，首条规则的
// 日志清理耗时 100ms（真实 ctx 在循环中途超时——停止判定仍来自 ctx.Err()，
// 不是 stub 旗标）。
// When 提交后清理执行。
// Then 预算内处理的首条文件真的消失；预算耗尽后的次条文件保留，审计点名
// 未处理条数（真实注入 importCleanupBudget 的超时路径，而非仅 stop 缝）。
func TestRunPostCommitCleanup_realBudgetExpiryKeepsRemainingFiles(t *testing.T) {
	withIsolatedGlobal(t)
	newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	ids := []string{"lb_realbudget_a", "lb_realbudget_b"}
	for _, id := range ids {
		if err := services.WriteCertFiles(id, "CERT_"+id, "KEY_"+id); err != nil {
			t.Fatalf("seed cert files for %s: %v", id, err)
		}
	}

	oldBudget := importCleanupBudget
	importCleanupBudget = 50 * time.Millisecond
	t.Cleanup(func() { importCleanupBudget = oldBudget })
	// 首条规则的日志清理慢于预算：真实超时落在循环中途（复核查询在预算内）。
	oldRemoveRuleLog := removeImportRuleLogFiles
	removeImportRuleLogFiles = func(id string) error {
		if id == ids[0] {
			time.Sleep(100 * time.Millisecond)
		}
		return oldRemoveRuleLog(id)
	}
	t.Cleanup(func() { removeImportRuleLogFiles = oldRemoveRuleLog })

	session := &configImportSession{ctx: context.Background()}
	session.runPostCommitCleanup(&importArtifactCleanupPlan{disappeared: ids})

	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, ids[0]+suffix)); !os.IsNotExist(err) {
			t.Fatalf("预算内规则 %s 的 %s 未被删除（stat=%v）", ids[0], suffix, err)
		}
		if _, err := os.Stat(filepath.Join(certDir, ids[1]+suffix)); err != nil {
			t.Fatalf("预算耗尽后规则 %s 的 %s 被删除: %v（未处理项文件必须保留）", ids[1], suffix, err)
		}
	}
	if got := countAuditMatching(t, `action='清理失败' AND detail LIKE '%产物清理预算%耗尽：剩余 1 条%'`); got != 1 {
		t.Fatalf("真实预算耗尽审计=%d, want 1（点名剩余 1 条）", got)
	}
	if got := countAuditMatching(t, `action='清理失败' AND resource='证书产物' AND detail LIKE '%产物清理未全部完成%预算耗尽未处理 1 条%'`); got != 1 {
		t.Fatalf("预算耗尽摘要审计=%d, want 1", got)
	}
	if got := countAuditMatching(t, `detail LIKE '%已清理其证书文件、指标与日志%'`); got != 0 {
		t.Fatalf("预算耗尽轮仍写「已清理」摘要 %d 条", got)
	}
}
