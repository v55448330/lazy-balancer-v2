package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func TestDeleteCertJob_concurrent_status_change_returns_409(t *testing.T) {
	// R55 A-#3：在途态任务（S-2 放行的 escape-hatch 对象）删除时，worker 在
	// SELECT 与 disabled 翻转之间推进状态（如 validating→validated），CAS
	// 命中 0 行属并发竞争而非服务器故障——必须重读区分归因并返回 409
	// 刷新重试文案（对齐 RetryCertJob 模式），不得返回误导性 500。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_cas','cas.example.test','validating')`); err != nil {
		t.Fatalf("seed in-flight job: %v", err)
	}
	oldHook := deleteCertJobPreDisableHook
	deleteCertJobPreDisableHook = func(jobID int) {
		if _, err := db.DB.Exec("UPDATE cert_jobs SET status='validated', updated_at=datetime('now') WHERE id=?", jobID); err != nil {
			t.Errorf("simulate worker transition: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreDisableHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409（并发状态变更不得报 500）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "任务状态已变更，请刷新后重试") {
		t.Fatalf("body=%s, want 并发状态变更文案", response.Body.String())
	}
	var status string
	if err := db.DB.QueryRow("SELECT status FROM cert_jobs WHERE id=1").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "validated" {
		t.Fatalf("status=%q, want validated（worker 流转结果不应被删除流程覆盖）", status)
	}
}

func TestDeleteCertJob_row_disappearing_before_disable_returns_404(t *testing.T) {
	// R55 A-#3：CAS 命中 0 行且重读发现行已不存在（并发删除），按 handler 对
	// 缺失任务的既有语义返回 404，而非 500「Failed to verify disabled job」。
	// Given
	h := newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id,domain,status) VALUES ('lb_gone','gone.example.test','validating')`); err != nil {
		t.Fatalf("seed job: %v", err)
	}
	oldHook := deleteCertJobPreDisableHook
	deleteCertJobPreDisableHook = func(jobID int) {
		if _, err := db.DB.Exec("DELETE FROM cert_jobs WHERE id=?", jobID); err != nil {
			t.Errorf("simulate row disappearing: %v", err)
		}
	}
	t.Cleanup(func() { deleteCertJobPreDisableHook = oldHook })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/1", nil))

	// Then
	if response.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%s, want 404", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "Job not found") {
		t.Fatalf("body=%s, want Job not found", response.Body.String())
	}
}
