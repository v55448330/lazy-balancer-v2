package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 禁用方向的提交后失败必须把规则行与证书任务行一起回退。
//
// 事务内已经按「禁用」语义把任务行改为 disabled，补偿快照若在提交之后才取，
// 目标态就是 disabled：规则回滚为启用、任务行停留 disabled，而下一次任何渲染
// 都会因「规则启用但无可用证书」把整条规则摘除（fail-closed），用户唯一自觉的
// /enable 入口又因 disabled 任务被 409 挡住。快照必须来自请求前状态。
func TestUpdateRule_disableRestoresPausedCertJobsWhenPostCommitResolveFails(t *testing.T) {
	// Given：启用中的 ACME 规则 + 已签发任务行
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_disable_jobs", "before", "disable-jobs.example.test", 8080, true, "acme_dns", true)
	seedAuditUpstream(t, "lb_disable_jobs")
	acmeConfigID := seedR52CertificateConfig(t)
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=? WHERE caddy_id='lb_disable_jobs'`, acmeConfigID); err != nil {
		t.Fatalf("bind acme config: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,expires_at)
		VALUES ('lb_disable_jobs','disable-jobs.example.test','issued','CERT-PEM','KEY-PEM',datetime('now','+30 days'))`); err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(nil, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	// 放锁窗口内默认 CA 提供商消失 = 提交后解析失败（并发禁用/删除的等价形态）
	updateRuleLockWindowHook = func(caddyID string, window int) {
		if window != 1 {
			return
		}
		if _, err := db.DB.Exec("DELETE FROM ca_providers"); err != nil {
			t.Errorf("delete ca providers in lock window: %v", err)
		}
	}
	t.Cleanup(func() { updateRuleLockWindowHook = nil })
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_disable_jobs", strings.NewReader(`{"enabled":false}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, request)

	// Then：走到提交后 CA 解析失败分支
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "解析 CA 提供商失败") {
		t.Fatalf("update status=%d body=%s, want 500 解析 CA 提供商失败", response.Code, response.Body.String())
	}
	var enabled bool
	var jobStatus string
	if err := db.DB.QueryRow(`SELECT r.enabled, j.status FROM lb_rules r JOIN cert_jobs j ON j.rule_id = r.caddy_id
		WHERE r.caddy_id='lb_disable_jobs'`).Scan(&enabled, &jobStatus); err != nil {
		t.Fatalf("read compensated rule and cert job: %v", err)
	}
	if !enabled || jobStatus != "issued" {
		t.Fatalf("enabled=%v job status=%q, want enabled/issued（补偿必须把任务行一起回退到请求前状态）", enabled, jobStatus)
	}
}
