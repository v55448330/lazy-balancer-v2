package handlers

// 提交后失败/补偿失败留痕的三条契约：
//   - LKG 钉回失败恰好留一行「补偿失败」审计：helper 时代由 helper 与统一写点
//     各写一次，运维按行数会读成两起问题；
//   - 设置族/逃生口的同一失败必须有审计（此前只有可能被日志级别过滤的 warn）；
//   - 审计动作列必须与失败对象匹配：提交失败/证书清理/任务入队不得沿用
//     「应用失败」（按动作过滤的人会被引向 Caddy 配置内容这个错误方向）；
//   - CLI 校验不可用分支的库态失败（未提交事务回滚失败）不得被写成运行配置
//     恢复失败——同一次响应的正文与审计/日志会自相矛盾。

import (
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// installPinFailure 注入 LKG 钉回失败（测试缝生产恒为 nil）。
func installPinFailure(t *testing.T, err error) {
	withIsolatedGlobal(t)
	t.Helper()
	previous := pinLastGoodForTest
	pinLastGoodForTest = func() error { return err }
	t.Cleanup(func() { pinLastGoodForTest = previous })
}

// installRollbackFailure 注入「未提交事务回滚失败」：测试实现先真正回滚再返回
// 错误（与 txCommitForTest 同型），否则恢复路径读已提交视图会撞在泄漏写锁上。
func installRollbackFailure(t *testing.T, err error) {
	withIsolatedGlobal(t)
	t.Helper()
	previous := txRollbackForTest
	txRollbackForTest = func(tx *sql.Tx) error {
		if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
			return rbErr
		}
		return err
	}
	t.Cleanup(func() { txRollbackForTest = previous })
}

func countCompensationAudits(t *testing.T) int {
	t.Helper()
	var rows int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='补偿失败'`).Scan(&rows); err != nil {
		t.Fatalf("统计补偿失败审计: %v", err)
	}
	return rows
}

// 规则族：同一次 LKG 钉回失败只能产生一行补偿失败审计，且 detail 点名 LKG。
func TestRuleApplyFailure_pinFailureAuditedExactlyOnce(t *testing.T) {
	h := newBackupTestHandlers(t)
	installPinFailure(t, errors.New("render committed view failed"))
	c, _ := newApplyTestContext()

	h.respondRuleApplyError(c, errors.New("apply failed"), nil, h.pinLastGoodAfterCompensation(), "更新")

	if rows := countCompensationAudits(t); rows != 1 {
		t.Fatalf("补偿失败审计行数=%d, want 1（同一次失败不得双写）", rows)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='补偿失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取补偿失败审计: %v", err)
	}
	if !strings.Contains(detail, "last-known-good 钉回失败") {
		t.Fatalf("补偿失败审计 detail=%q, want 点名 LKG 钉回失败", detail)
	}
}

// 设置族：回弹成功但 LKG 钉回失败必须留审计（此前只有 warn 日志）。
func TestUpdateConfig_applyFailurePinFailureAudited(t *testing.T) {
	handler, _ := newFailingLoadHandlers(t)
	installPinFailure(t, errors.New("render committed view failed"))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(`{"request_body_max_size_mb":9}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（候选 /load 失败）", response.Code, response.Body.String())
	}
	if rows := countCompensationAudits(t); rows != 1 {
		t.Fatalf("设置族补偿失败审计行数=%d, want 1（LKG 钉回失败必须留痕）", rows)
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='补偿失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取补偿失败审计: %v", err)
	}
	if !strings.Contains(detail, "last-known-good 钉回失败") {
		t.Fatalf("设置族补偿失败 detail=%q, want 点名 LKG 钉回失败", detail)
	}
}

// 审计动作/事件对象必须随失败对象变化（动作列恒为「应用失败」= 错称）。
func TestApplyFailureBanner_auditActionMatchesObject(t *testing.T) {
	h := newBackupTestHandlers(t)
	cases := []struct {
		name     string
		subject  applyFailureSubject
		action   string
		resource string
	}{
		{"提交失败", commitSaveFailedSubject, "保存失败", "Caddy配置"},
		{"证书文件清理失败", certFileCleanupFailedSubject, "清理失败", "证书文件"},
		{"证书任务入队失败", certJobEnqueueFailedSubject, "创建失败", "证书任务"},
		{"配置应用失败", caddyApplyFailureSubject("Caddy 配置应用失败"), "应用失败", "Caddy配置"},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			marker := "marker-" + strings.Repeat("x", index+1)
			h.writeApplyFailureBanner(tc.subject, errors.New(marker), nil)
			var action, resource, detail string
			if err := db.AuditDB.QueryRow(`SELECT action, resource, detail FROM audit_log WHERE detail LIKE ? ORDER BY id DESC LIMIT 1`, "%"+marker+"%").Scan(&action, &resource, &detail); err != nil {
				t.Fatalf("读取失败审计: %v", err)
			}
			if action != tc.action || resource != tc.resource {
				t.Fatalf("审计动作/对象=%q/%q, want %q/%q", action, resource, tc.action, tc.resource)
			}
			if !strings.Contains(detail, tc.subject.object) {
				t.Fatalf("审计 detail=%q, want 含失败对象 %q", detail, tc.subject.object)
			}
		})
	}
}

// CLI 校验不可用 + 未提交事务回滚失败 + 运行配置恢复成功：
// 正文与审计必须只说「回滚未提交事务失败」，不得声称运行配置回滚失败。
func TestFinishTxApply_unvalidatedApplyRollbackFailureChannelSeparated(t *testing.T) {
	h := newBackupTestHandlers(t)
	_, fake := newApplyThenDropServer(t, 1)
	h.caddyService = services.NewCaddyService(fake.URL)
	h.caddyService.SetCLIValidatorForTest(func([]byte) error { return services.ErrCLIValidatorUnavailable })
	seedCommittedRuleForApplyTest(t, "lb_p3c", "committed-p3c.example.test")
	tx := beginPendingDomainTx(t, "lb_p3c")
	c, rec := newApplyTestContext()
	installRollbackFailure(t, errors.New("injected rollback failure"))

	h.finishTxApply(c, tx, txApplyFinish{Resource: "安全策略", AuditAction: "更新", AuditDetail: "策略保存", SuccessMsg: "已保存"})

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", rec.Code, rec.Body.String())
	}
	// 运行配置恢复成功：响应的恢复说明必须是「已回滚」。
	if !strings.Contains(rec.Body.String(), "已回滚到已提交运行配置") {
		t.Fatalf("响应未说明运行配置已回滚: %s", rec.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='更新失败' AND resource='安全策略' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取更新失败审计: %v", err)
	}
	if strings.Contains(detail, "回滚到已提交运行配置失败") {
		t.Fatalf("库态失败被写成运行配置恢复失败（与响应相反）: %q", detail)
	}
	if !strings.Contains(detail, "回滚未提交事务失败") {
		t.Fatalf("审计未点名真实的失败通道（未提交事务回滚）: %q", detail)
	}
	if banner := readApplyError(t); !strings.Contains(banner, "旧配置已保留") {
		t.Fatalf("横幅标签=%q, want 「旧配置已保留」（运行配置已恢复）", banner)
	}
}
