package handlers

// cert-job 行手动调度（2026-10-11 用户裁定）：证书队列行视为触发任务——
// 可自动调度（签发守护消费）即可手动调度（证书可重签发），统一经
// POST /system/tasks/cert-job:<id>/trigger 入口（任务监控操作列「运行」）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// Given：failed 状态证书任务（超 5 分钟冷却）+ 有效 acme_dns 规则。
// When：POST /system/tasks/cert-job:1/trigger。Then：200 且任务重新入队 queued。
func TestTriggerSystemTask_certJobRowRetriesFailedJob(t *testing.T) {
	// 不起引擎（cert-job 分支为纯 handler+队列管理器路径）——引擎 cert-issuance
	// 守护会在入队后立刻消费并推进/打回 failed，断言窗口竞态（整包 flake 实证）。
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_trig','trig','http','trig.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_trig','trig.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-job:1/trigger", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（cert-job 行手动调度=重试入队）", response.Code, response.Body.String())
	}
	// 确定性契约=响应 200 +「Retry triggered」（仅 transition 成功落库才返回；
	// 入队后队列工作池毫秒级推进 queued→creating_account→（假 CA）failed，
	// DB 终态本身竞态，不断言瞬态/回退态）。
	if !strings.Contains(response.Body.String(), "Retry triggered") {
		t.Fatalf("body=%s, want 含 Retry triggered（重试被接受）", response.Body.String())
	}
}

// Given：disabled 证书任务。When：触发。Then：409（退役任务永久不可重试——复用重试门；
// 永久条件不得用 429，SDK/前端会按限流语义退避轮询）。
func TestTriggerSystemTask_certJobRowDisabledRejected(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dis','dis','http','dis.example.test',8080,1,1,'acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at) VALUES ('lb_dis','dis.example.test','disabled',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}

	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-job:1/trigger", nil))

	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（已退役证书任务不能重试）", response.Code, response.Body.String())
	}
	// 与日志/历史入口共用 TrimSpace+ParseInt 口径：空白归一后的同一 ID
	// 必须到达业务重试门，而不是在解析层提前 400。
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-job:%201/trigger", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("trimmed ID status=%d body=%s, want 409", response.Code, response.Body.String())
	}
}
