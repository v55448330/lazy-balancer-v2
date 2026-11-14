package handlers

// ≤30s）必须发生在全局 CaddyOpLock 临界区之外——原顺序（翻转→取消→删除，
// 取消在临界区内）使取消等待期全局 Caddy 写路径排队（与 rules.go 域名迁移
// 同型等待环）。钉法：注入 cancelCertJob 测试缝，在取消回调内 TryLock 全局
// CaddyOpLock——旧实现下本函数正持锁，TryLock 必败=红；新实现锁已释放，
// TryLock 成功。同时断言取消点行已删除（新顺序 删除→取消 的形态钉）。

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestDeleteCertJob_cancelRunsOutsideCaddyOpLock(t *testing.T) {
	withIsolatedGlobal(t)
	setupSecurityPolicyTestDB(t)
	res, err := db.DB.Exec(`INSERT INTO cert_jobs (rule_id, domain, status, message) VALUES ('lb_r76cancel', 'cancel.example.com', 'failed', '给定在途态')`)
	if err != nil {
		t.Fatalf("seed cert job: %v", err)
	}
	jobID, _ := res.LastInsertId()

	lockFreeAtCancel := false
	rowGoneAtCancel := false
	oldCancel := cancelCertJob
	cancelCertJob = func(id int) {
		lockFreeAtCancel = services.CaddyOpLock.TryLock()
		if lockFreeAtCancel {
			services.CaddyOpLock.Unlock()
		}
		var n int
		if err := db.DB.QueryRow(`SELECT COUNT(1) FROM cert_jobs WHERE id=?`, id).Scan(&n); err == nil {
			rowGoneAtCancel = n == 0
		}
	}
	t.Cleanup(func() { cancelCertJob = oldCancel })

	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.DELETE("/certificates/jobs/:id", h.DeleteCertJob)

	req := httptest.NewRequest(http.MethodDelete, "/certificates/jobs/"+strconv.FormatInt(jobID, 10), nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", rec.Code, rec.Body.String())
	}
	if !lockFreeAtCancel {
		t.Fatal("取消回调执行时全局 CaddyOpLock 必须已释放（旧行为：临界区内取消 → TryLock 失败 → 必红）")
	}
	if !rowGoneAtCancel {
		t.Fatal("取消点必须在 DELETE 之后（先取消后恢复的失败恢复语义依赖此序）")
	}
	var n int
	if err := db.DB.QueryRow(`SELECT COUNT(1) FROM cert_jobs WHERE id=?`, jobID).Scan(&n); err != nil || n != 0 {
		t.Fatalf("任务行应已删除，count=%d err=%v", n, err)
	}
}
