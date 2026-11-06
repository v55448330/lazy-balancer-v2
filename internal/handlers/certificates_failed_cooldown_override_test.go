package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// failed 行的通用失败冷却只约束自动通道（续期巡检 / waiting_ca 补扫 / 批量全量
// 重签）；任务卡片/任务监控的「重签」已按同一裁定豁免（certjobs.go 的
// cooldown_override 越冷留痕）。定向「触发签发」是同等知情显式操作——冷却中
// 放行并留 cooldown_override 审计，不得再 429「失败后请等待 5 分钟再重试」。
func TestIssueCertificate_failedCooldownAllowsDirectedIssue(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_fail_cooling", "fail-cooling.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_fail_cooling','fail-cooling.example','failed',datetime('now','-2 minutes'))`); err != nil {
		t.Fatalf("seed failed job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_fail_cooling"}`)))

	// Then：200 + 重新入队（不再 429），且越冷走成功通道留 cooldown_override 审计
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（failed 行通用冷却不阻断定向重签）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), `"queued":1`) {
		t.Fatalf("body=%s, want queued=1（任务重新入队）", response.Body.String())
	}
	var detail string
	if err := db.AuditDB.QueryRow(`SELECT COALESCE(detail,'') FROM audit_log
		WHERE action='触发签发' AND detail LIKE '%结果：越过失败冷却%'
		ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("read override audit: %v", err)
	}
	if !strings.Contains(detail, "越过失败冷却") || !strings.Contains(detail, "规则：lb_fail_cooling") {
		t.Fatalf("audit detail=%q, want 越过失败冷却留痕（含规则范围）", detail)
	}
}

// 非 failed 行（在途 executing 形状）冷却照旧：豁免只针对 failed 行的通用
// 失败冷却，在途/退役/CA 退避语义不受影响。
func TestIssueCertificate_nonFailedCooldownStillBlocksDirectedIssue(t *testing.T) {
	h := newBackupTestHandlers(t)
	initIssueQueue(t)
	seedIssueRule(t, "lb_run_cooling", "run-cooling.example")
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_run_cooling','run-cooling.example','creating_order',datetime('now','-1 minute'))`); err != nil {
		t.Fatalf("seed in-flight job: %v", err)
	}
	router := gin.New()
	router.POST("/certificates/issue", h.IssueCertificate)

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/certificates/issue", strings.NewReader(`{"caddy_id":"lb_run_cooling"}`)))

	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "任务正在执行中") {
		t.Fatalf("status=%d body=%s, want 429 任务正在执行中（非 failed 行冷却照旧）", response.Code, response.Body.String())
	}
}
