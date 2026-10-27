package handlers

// 提交后产物清理的两条真实性契约：
//  ① 提交结果不确定（Commit 报错）时，事务内收集的清理计划不得被丢弃——
//     若提交其实已落地，规则行已消失，本计划是这些规则私钥/指标/日志的
//     唯一清理线索；若实际回滚，按已提交视图复核后判定集为空、零删除。
//  ② 清理摘要审计必须按实际结果给口径：证书文件删除失败要有独立审计，
//     预算耗尽要有未处理计数，不得无条件断言「已清理」。

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// installCommitSeam 注入提交失败形态：commitFirst=true 模拟「实际已提交但
// 确认丢失」；false 模拟「确实回滚」。
func installCommitSeam(t *testing.T, commitFirst bool) {
	t.Helper()
	previous := txCommitForTest
	txCommitForTest = func(tx *sql.Tx) error {
		if commitFirst {
			if err := tx.Commit(); err != nil {
				return err
			}
		} else if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
			return err
		}
		return errCommitInjected
	}
	t.Cleanup(func() { txCommitForTest = previous })
}

// seedDisappearingRule 播种一条会在导入后消失的规则及其证书文件。证书用
// 真实可解析的 PEM：提交不确定态会按已提交视图重渲染并物化存活规则证书，
// 假字节会让恢复阶段自身报错，掩盖被测语义。
func seedDisappearingRule(t *testing.T, ruleID string) {
	t.Helper()
	certPEM, keyPEM, err := generateTestCert(ruleID+".example.test", time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	if err != nil {
		t.Fatalf("generate test cert: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled,enable_tls,tls_source,tls_cert,tls_key) VALUES (?,?,?,'http',8575,1,1,'manual',?,?)`,
		ruleID, ruleID, ruleID+".example.test", certPEM, keyPEM); err != nil {
		t.Fatalf("seed disappearing rule: %v", err)
	}
	if err := services.WriteCertFiles(ruleID, certPEM, keyPEM); err != nil {
		t.Fatalf("write cert files: %v", err)
	}
}

func postV1Import(t *testing.T, h *Handlers, name string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/config/import/v1", h.ImportV1Config)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/config/import/v1", strings.NewReader(v1ImportFailureBackup(name)))
	request.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(recorder, request)
	return recorder
}

func countAuditMatching(t *testing.T, where string, args ...any) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE `+where, args...).Scan(&count); err != nil {
		t.Fatalf("count audit rows (%s): %v", where, err)
	}
	return count
}

func TestImportV1_indeterminateCommitStillCleansDisappearedRuleArtifacts(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	const ruleID = "lb_indeterminate_gone"
	seedDisappearingRule(t, ruleID)
	installCommitSeam(t, true) // 提交已落地，但确认丢失

	recorder := postV1Import(t, h, "v1-indeterminate-committed")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if !strings.Contains(body, "提交结果不确定") {
		t.Fatalf("body=%s, want 提交结果不确定 文案", body)
	}
	// 披露：已按已提交视图确认消失规则数（清理未静默丢弃）。
	if !strings.Contains(body, "已按已提交视图确认本次导入移除的 1 条规则") {
		t.Fatalf("body=%s, want 不确定态产物清理披露", body)
	}
	// 清理确实执行：消失规则的证书/私钥被删除（旧实现计划被丢弃，文件永留）。
	waitImportCleanup()
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(filepath.Join(certDir, ruleID+suffix)); !os.IsNotExist(err) {
			t.Fatalf("%s 未被清理（stat=%v）：不确定态下清理计划被丢弃", ruleID+suffix, err)
		}
	}
	if got := countAuditMatching(t, `action='清理' AND resource='证书产物' AND detail LIKE '%导入移除 1 条规则%'`); got != 1 {
		t.Fatalf("清理摘要审计=%d, want 1", got)
	}
	if got := countAuditMatching(t, `detail LIKE '%提交结果不确定：已按已提交视图确认%'`); got != 1 {
		t.Fatalf("不确定态披露审计=%d, want 1", got)
	}
}

func TestImportV1_indeterminateCommitActualRollbackKeepsLiveRuleArtifacts(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	const ruleID = "lb_indeterminate_live"
	seedDisappearingRule(t, ruleID)
	installCommitSeam(t, false) // 确实回滚

	recorder := postV1Import(t, h, "v1-indeterminate-rolled-back")
	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
	}
	if body := recorder.Body.String(); !strings.Contains(body, "无需清理产物") {
		t.Fatalf("body=%s, want 提交实际未落地（无需清理）披露", body)
	}
	waitImportCleanup()
	// 规则仍在库内 → 其证书文件必须保留（复核后判定集为空，零删除）。
	if _, err := os.Stat(filepath.Join(certDir, ruleID+".crt")); err != nil {
		t.Fatalf("实际回滚后存活规则证书被删除: %v", err)
	}
	var rows int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id=?`, ruleID).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("实际回滚后规则行数=%d, want 1", rows)
	}
	if got := countAuditMatching(t, `action='清理' AND resource='证书产物' AND detail LIKE '%导入移除%'`); got != 0 {
		t.Fatalf("实际回滚仍记录「已清理」摘要 %d 条", got)
	}
}

func TestImportV1_cleanupSummaryReportsPartialFailureWhenCertRemovalFails(t *testing.T) {
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	if os.Geteuid() == 0 {
		t.Skip("root 无视目录写权限，无法注入证书文件删除失败")
	}
	const ruleID = "lb_cleanup_cert_fails"
	seedDisappearingRule(t, ruleID)
	// 只读目录（0555）：快照/渲染仍可读取证书内容，但 os.Remove 必然 EACCES。
	if err := os.Chmod(certDir, 0o555); err != nil {
		t.Fatalf("make cert dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(certDir, 0o700) })

	recorder := postV1Import(t, h, "v1-cleanup-partial")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（清理失败不否决已提交导入）", recorder.Code, recorder.Body.String())
	}
	waitImportCleanup()
	// 单条失败必须有独立审计（与「无材料规则」路径同口径，不再只有 warn）。
	if got := countAuditMatching(t, `action='清理失败' AND resource='证书产物' AND detail LIKE '%`+ruleID+` 的证书文件失败%'`); got != 1 {
		t.Fatalf("证书文件删除失败审计=%d, want 1", got)
	}
	// 摘要不得无条件断言「已清理」。
	if got := countAuditMatching(t, `detail LIKE '%已清理其证书文件、指标与日志%'`); got != 0 {
		t.Fatalf("失败轮仍写「已清理」摘要 %d 条（审计真实性）", got)
	}
	if got := countAuditMatching(t, `action='清理失败' AND resource='证书产物' AND detail LIKE '%产物清理未全部完成%证书文件失败 1%'`); got != 1 {
		t.Fatalf("部分失败摘要审计=%d, want 1", got)
	}
}

func TestImportV1_cleanupBudgetStopsPerRuleLoopAndReportsRemaining(t *testing.T) {
	withIsolatedGlobal(t)
	h := newBackupTestHandlers(t)
	certDir := t.TempDir()
	t.Cleanup(services.SetCertDirForTest(certDir))
	const ruleID = "lb_cleanup_budget_out"
	seedDisappearingRule(t, ruleID)
	// 预算在逐规则循环前即耗尽（文件/日志删除不消费 ctx，只靠循环内检查）。
	previousStop := importCleanupShouldStop
	importCleanupShouldStop = func(context.Context) bool { return true }
	t.Cleanup(func() { importCleanupShouldStop = previousStop })

	recorder := postV1Import(t, h, "v1-cleanup-budget")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	waitImportCleanup()
	// 预算耗尽：不得再删文件，且审计点名未处理条数。
	if _, err := os.Stat(filepath.Join(certDir, ruleID+".crt")); err != nil {
		t.Fatalf("预算耗尽后仍删除了证书文件: %v", err)
	}
	if got := countAuditMatching(t, `action='清理失败' AND detail LIKE '%产物清理预算%耗尽：剩余%条规则的证书文件/指标/日志未处理%'`); got != 1 {
		t.Fatalf("预算耗尽审计=%d, want 1", got)
	}
	if got := countAuditMatching(t, `action='清理失败' AND detail LIKE '%产物清理未全部完成%预算耗尽未处理%条%'`); got != 1 {
		t.Fatalf("预算耗尽摘要审计=%d, want 1", got)
	}
	if got := countAuditMatching(t, `detail LIKE '%已清理其证书文件、指标与日志%'`); got != 0 {
		t.Fatalf("预算耗尽轮仍写「已清理」摘要 %d 条", got)
	}
}
