package handlers

// ACME 写守卫族的 enable_tls 读取必须与全仓 IIF(enable_tls IN ('1',1),1,0)
// 归一口径一致（单源 SQL 片段）。lb_rules.enable_tls 为 NUMERIC 亲和，
// '1'/1 入库即收敛为 INTEGER，裸比较与 IIF 对库内形态行为等价——本文件
// 钉住收敛后的守卫契约：TEXT '1' 带外写入形态下重试/部署重排/删除守卫
// 与批量候选全部按启用 TLS 处理。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 重试入队 CAS 的规则存在性守卫：TEXT '1' 形态的启用 ACME 规则必须命中，
// failed 任务重新入队（queued），不得误报不可重试。
func TestRetryCertJob_textFormEnableTLSRuleRequeues(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_retry_text','retry-text','http','retry-text.example.test',8080,1,'1','acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,updated_at)
		VALUES ('lb_retry_text','retry-text.example.test','failed',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed rule and job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（TEXT '1' 规则守卫必须命中）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Retry triggered") {
		t.Fatalf("body=%s, want 重新入队语义", response.Body.String())
	}
}

// 部署重排快速路径的规则守卫：TEXT '1' 形态必须命中——任务保持 downloaded、
// 材料保留、部署窗口推到 now；守卫漏检会回落整轮重签（丢弃已签发证书）。
func TestRetryCertJob_textFormEnableTLSReschedulesDeployment(t *testing.T) {
	h := newBackupTestHandlers(t)
	service := services.NewCertificateService()
	t.Cleanup(service.Stop)
	services.ResetCAQueueManagerForTest()
	services.InitCAQueueManager(func() error { return nil }, t.TempDir())
	services.GetCAQueueManager().Start()
	startCertQueueDispatchForTest(t)
	t.Cleanup(services.ResetCAQueueManagerForTest)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_dl_text','dl-text','http','dl-text.example.test',8080,1,'1','acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status,message,cert_pem,key_pem,updated_at,deployment_available_after)
		VALUES ('lb_dl_text','dl-text.example.test','downloaded','部署失败 [attempt=1/10]: boom','CERT-PEM','KEY-PEM',datetime('now','-10 minutes'),datetime('now','+5 minutes'))`); err != nil {
		t.Fatalf("seed downloaded job: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/1/retry", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Deployment retry triggered") {
		t.Fatalf("body=%s, want 部署重排语义（TEXT '1' 规则守卫必须命中）", response.Body.String())
	}
	var status, certPEM string
	var availableAfter time.Time
	if err := db.DB.QueryRow(`SELECT status, COALESCE(cert_pem,''), deployment_available_after FROM cert_jobs WHERE id=1`).Scan(&status, &certPEM, &availableAfter); err != nil {
		t.Fatalf("read job: %v", err)
	}
	if status != "downloaded" || certPEM != "CERT-PEM" {
		t.Fatalf("job=(%q,%q), want downloaded/材料保留", status, certPEM)
	}
	if time.Until(availableAfter) > 5*time.Second {
		t.Fatalf("deployment_available_after=%v, want 已推到 now", availableAfter)
	}
}

// 删除守卫：TEXT '1' 形态的启用 ACME 规则仍处自动签发状态，issued 任务
// 删除必须 409（守卫漏检会放行删除，续签链静默断）。
func TestDeleteCertJob_textFormEnableTLSRuleGuards(t *testing.T) {
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES ('lb_del_text','del-text','http','del-text.example.test',8080,1,'1','acme_dns');
		INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_del_text','del-text.example.test','issued')`); err != nil {
		t.Fatalf("seed rule and job: %v", err)
	}
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（TEXT '1' 启用 ACME 规则守卫必须命中）", response.Code, response.Body.String())
	}
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM cert_jobs WHERE id=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("guarded job deleted (count=%d)", count)
	}
}
