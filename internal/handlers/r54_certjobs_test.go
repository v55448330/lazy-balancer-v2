package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// R54 S-3：EnableCertJobResume 的 UPDATE 无状态 CAS 守卫——SELECT（规则启用
// 时的任务查询）与 UPDATE 之间任务行被删除时 0 行命中，「启用成功但任务行不
// 存在、续签链断」会被审计文案「证书仍有效，恢复使用现有证书」掩盖。必须核对
// RowsAffected==1，否则 failEnable 恢复规则与任务快照。
func TestEnableRule_fails_when_resume_target_row_disappears(t *testing.T) {
	// Given：禁用中的 acme_dns 规则持有一条 disabled 任务（证书 90 天后到期，
	// 不在续签窗口 → EnableCertJobResume 分支）
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedAuditRule(t, "lb_resume_race", "resume-race", "resume-race.example.test", 8080, false, "acme_dns", true)
	seedAuditUpstream(t, "lb_resume_race")
	var providerID int
	if err := db.DB.QueryRow("SELECT default_ca_provider_id FROM global_config WHERE id=1").Scan(&providerID); err != nil {
		t.Fatalf("read default provider: %v", err)
	}
	dnsResult, err := db.DB.Exec(`INSERT INTO certificate_configs (name,dns_provider,dns_credentials,enabled) VALUES ('r54-dns','dnspod','{"token":"x"}',1)`)
	if err != nil {
		t.Fatalf("seed dns config: %v", err)
	}
	dnsConfigID, err := dnsResult.LastInsertId()
	if err != nil {
		t.Fatalf("read dns config ID: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE lb_rules SET acme_config_id=?,ca_provider_id=? WHERE caddy_id='lb_resume_race'`, dnsConfigID, providerID); err != nil {
		t.Fatalf("bind acme config to rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,expires_at,ca_provider_id)
		VALUES ('lb_resume_race','resume-race.example.test','disabled',datetime('now','+90 days'),?)`, providerID); err != nil {
		t.Fatalf("seed disabled cert job: %v", err)
	}
	// 模拟 SELECT 与 UPDATE 之间任务行被并发删除（当前因 caddyOpMu 互斥不可达，
	// 本用例锁死 RowsAffected 校验以防未来路径变化引入静默断链）。
	oldHook := enableCertJobResumePreUpdateHook
	enableCertJobResumePreUpdateHook = func(jobID int) {
		if _, err := db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", jobID); err != nil {
			t.Errorf("simulate resume target disappearing: %v", err)
		}
	}
	t.Cleanup(func() { enableCertJobResumePreUpdateHook = oldHook })
	router := gin.New()
	router.POST("/rules/:caddy_id/enable", handler.EnableRule)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_resume_race/enable", nil))

	// Then：0 行命中必须 500 而非报成功；规则恢复禁用，任务行由快照补偿恢复。
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("enable status=%d body=%s, want 500（恢复目标行不存在不得报成功）", response.Code, response.Body.String())
	}
	var enabled bool
	if err := db.DB.QueryRow("SELECT enabled FROM lb_rules WHERE caddy_id='lb_resume_race'").Scan(&enabled); err != nil {
		t.Fatalf("read enabled state: %v", err)
	}
	if enabled {
		t.Fatal("failed enable must restore the rule to disabled")
	}
	var jobStatus string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE rule_id='lb_resume_race'").Scan(&jobStatus); err != nil {
		t.Fatalf("read compensated cert job: %v", err)
	}
	if jobStatus != "disabled" {
		t.Fatalf("compensated job status=%q, want disabled（快照恢复）", jobStatus)
	}
}
