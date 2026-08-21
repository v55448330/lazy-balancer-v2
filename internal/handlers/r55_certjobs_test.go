package handlers

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// certJobRereadFailingConnector 返回一个按语句路由的假 db.DB：任务行 SELECT 正常
// 返回在途态行，CAS UPDATE 命中 0 行（模拟 worker 并发推进状态），重读 SELECT
// 注入瞬时 DB 故障（同 R36/R37 的假连接器模式）。
type certJobRereadFailingConnector struct{}

func (certJobRereadFailingConnector) Connect(context.Context) (driver.Conn, error) {
	return certJobRereadFailingConn{}, nil
}

func (certJobRereadFailingConnector) Driver() driver.Driver { return certJobRereadFailingDriver{} }

type certJobRereadFailingDriver struct{}

func (certJobRereadFailingDriver) Open(string) (driver.Conn, error) {
	return certJobRereadFailingConn{}, nil
}

type certJobRereadFailingConn struct{}

func (certJobRereadFailingConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected prepare")
}

func (certJobRereadFailingConn) Close() error { return nil }

func (certJobRereadFailingConn) Begin() (driver.Tx, error) { return nil, errors.New("no tx") }

func (certJobRereadFailingConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	switch {
	case strings.Contains(query, "rule_id, domain, status"):
		return &fakeQueryRows{values: [][]driver.Value{{"lb_reread_500", "reread.example.test", "validating", int64(1)}}}, nil
	case strings.Contains(query, "SELECT status FROM cert_jobs"):
		return nil, errors.New("注入的重读故障")
	default:
		return &fakeQueryRows{}, nil
	}
}

func (certJobRereadFailingConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	if strings.Contains(query, "UPDATE cert_jobs SET status='disabled'") {
		return certJobZeroRowsResult{}, nil
	}
	return nil, errors.New("unexpected exec: " + query)
}

type certJobZeroRowsResult struct{}

func (certJobZeroRowsResult) LastInsertId() (int64, error) { return 0, nil }

func (certJobZeroRowsResult) RowsAffected() (int64, error) { return 0, nil }

func TestDeleteCertJob_reread_failure_returns_500(t *testing.T) {
	// R56 N-4：CAS 命中 0 行后的归因重读本身失败（瞬时 DB 故障）是 R55 A-#3
	// 新增的第三分支——必须显式 500（读取任务状态失败），不得误报 409/404。
	// Given
	h := newBackupTestHandlers(t)
	fake := sql.OpenDB(certJobRereadFailingConnector{})
	t.Cleanup(func() { _ = fake.Close() })
	orig := db.DB
	db.DB = fake
	t.Cleanup(func() { db.DB = orig })
	router := gin.New()
	router.DELETE("/jobs/:id", h.DeleteCertJob)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/jobs/7", nil))

	// Then
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（重读失败不得误报 409/404）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "读取任务状态失败") {
		t.Fatalf("body=%s, want 读取任务状态失败", response.Body.String())
	}
}

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
