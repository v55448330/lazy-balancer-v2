package handlers

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// seedDeployLifecycleRetryJob 建「自动签发规则 + 指定状态任务（材料在库、
// 冷却已过）」的夹具，返回任务 id。
func seedDeployLifecycleRetryJob(t *testing.T, caddyID, domain, status string) int64 {
	t.Helper()
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled,enable_tls,tls_source)
		VALUES (?,?, 'http', ?, 8080, 1, 1, 'acme_dns')`, caddyID, caddyID, domain); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status,cert_pem,key_pem,updated_at,created_at)
		VALUES (?,?,?,'cert-material','key-material',datetime('now','-1 hour'),datetime('now','-2 hour'))`, caddyID, domain, status)
	if err != nil {
		t.Fatalf("seed job: %v", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("read job id: %v", err)
	}
	return id
}

// 部署生命周期（cleanup_dns/cleanup_warning）+ 材料在库的任务手动重试必须走
// 「部署重排」而不是回落 queued 重签：转 queued 会丢弃已签发证书并白烧 CA 配额。
func TestRetryCertJob_deployLifecycleReschedulesInsteadOfReissuing(t *testing.T) {
	for _, status := range []string{"cleanup_dns", "cleanup_warning"} {
		t.Run(status, func(t *testing.T) {
			h := newBackupTestHandlers(t)
			services.ResetCAQueueManagerForTest()
			t.Cleanup(services.ResetCAQueueManagerForTest)
			// 停掉证书服务 → RetryCertificateDeploymentNow 明确返回 ErrCertificateQueueInactive
			//（409 + 「已登记自动部署」），不会起部署定时器污染断言。
			service := services.NewCertificateService()
			service.Stop()

			id := seedDeployLifecycleRetryJob(t, "lb_"+status, status+".example.test", status)
			router := gin.New()
			router.POST("/jobs/:id/retry", h.RetryCertJob)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/"+strconv.FormatInt(id, 10)+"/retry", nil))

			if response.Code == http.StatusInternalServerError {
				t.Fatalf("status=%d body=%s（回落 queued 重签路径）", response.Code, response.Body.String())
			}
			if response.Code != http.StatusConflict {
				t.Fatalf("status=%d body=%s, want 409（部署重排已登记、服务停止）", response.Code, response.Body.String())
			}
			if !strings.Contains(response.Body.String(), "已登记自动部署") {
				t.Fatalf("响应未点明已登记自动部署: %s", response.Body.String())
			}
			var gotStatus string
			var availableAfter sql.NullTime
			if err := db.DB.QueryRow("SELECT status, deployment_available_after FROM cert_jobs WHERE id=?", id).Scan(&gotStatus, &availableAfter); err != nil {
				t.Fatalf("read job: %v", err)
			}
			if gotStatus != status {
				t.Fatalf("status=%q, want %q（部署生命周期行不得转 queued/failed）", gotStatus, status)
			}
			if !availableAfter.Valid {
				t.Fatal("deployment_available_after 未推到 now（补扫无法重新调度部署）")
			}
			if services.GetCAQueueManager() != nil {
				t.Fatal("测试前置失败：CA 队列应为 nil")
			}
		})
	}
}

// 反向：同类状态但材料缺失（脏行）才允许回落重新签发路径（此处队列为 nil
// → 500「CA queue manager not initialized」），不得被误判为部署重排。
func TestRetryCertJob_deployLifecycleWithoutMaterialFallsBackToIssuance(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)

	id := seedDeployLifecycleRetryJob(t, "lb_nomat", "nomat.example.test", "cleanup_dns")
	if _, err := db.DB.Exec(`UPDATE cert_jobs SET cert_pem='', key_pem='' WHERE id=?`, id); err != nil {
		t.Fatalf("clear material: %v", err)
	}
	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/"+strconv.FormatInt(id, 10)+"/retry", nil))
	if response.Code != http.StatusInternalServerError || !strings.Contains(response.Body.String(), "CA queue manager not initialized") {
		t.Fatalf("status=%d body=%s, want 500 回落重新入队路径", response.Code, response.Body.String())
	}
}

// 锁序铁律（同 DeleteCertJob「先 caddyOpMu 后 per-job 锁」的反向面）：重试
// 入口不得在持有 per-job 操作锁时登记立即部署。scheduleDeploymentRetry 对在途
// 部署回调做有界等待（≤30s），而在途回调要取 caddyOpMu 才能退出——并发「重试 +
// 删除」时删除方持全局锁等该 per-job 锁，全局面（规则写/Caddy 启停/配置导入）
// 最长排队 30s。登记必须与 IssueCertificate「锁内推进窗口、锁外登记」同构。
func TestRetryCertJob_registersDeploymentOutsideOperationLock(t *testing.T) {
	h := newBackupTestHandlers(t)
	services.ResetCAQueueManagerForTest()
	t.Cleanup(services.ResetCAQueueManagerForTest)

	id := seedDeployLifecycleRetryJob(t, "lb_lockorder", "lockorder.example.test", "downloaded")

	oldRegistrar := certJobDeploymentRetryRegistrar
	t.Cleanup(func() { certJobDeploymentRetryRegistrar = oldRegistrar })
	registrarCalled := false
	certJobDeploymentRetryRegistrar = func(jobID int, _ string) error {
		registrarCalled = true
		lock := certJobOperationLock(jobID)
		if !lock.TryLock() {
			t.Fatalf("per-job 操作锁在登记立即部署时仍被持有——删除方持 caddyOpMu 等该锁会把全局面阻塞至多 30s")
		}
		lock.Unlock()
		return nil
	}

	router := gin.New()
	router.POST("/jobs/:id/retry", h.RetryCertJob)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/jobs/"+strconv.FormatInt(id, 10)+"/retry", nil))

	if !registrarCalled {
		t.Fatalf("登记入口未被调用，status=%d body=%s", response.Code, response.Body.String())
	}
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（部署重排登记成功）", response.Code, response.Body.String())
	}
}
