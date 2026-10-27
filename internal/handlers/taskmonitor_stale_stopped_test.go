package handlers

// 任务监控的跨端点口径与引擎停止边界：
//   - 残留 running 行（终态 UPDATE 失败）在列表与运行历史必须给出一致结论；
//   - 调度写端点（toggle/control）在引擎已停止时必须 503——StartLoop/StopLoop
//     在已停引擎上恒 no-op，200「已恢复/已启动」是假信号。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestGetSystemTaskHistory_normalizesStaleRunningRow(t *testing.T) {
	initTaskEngineForTest(t)
	if err := services.TaskEngine().Register(taskengine.Descriptor{
		ID: "history-stale", Family: "test", Name: "残留运行行", Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO task_runs (task_id, family, trigger, status, started_at)
		VALUES ('history-stale', 'test', 'auto', 'running', datetime('now','-5 minutes'))`); err != nil {
		t.Fatal(err)
	}
	router := gin.New()
	h := &Handlers{}
	router.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/system/tasks/history-stale/history", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("history status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"status":"interrupted"`) {
		t.Fatalf("残留 running 行在历史里应归一为 interrupted（与列表同口径）: %s", body)
	}
	if strings.Contains(body, `"status":"running"`) {
		t.Fatalf("同一 run 在列表显示已中断、历史不得仍称运行中: %s", body)
	}
}

func TestSchedulingWriteEndpoints_rejectStoppedEngine(t *testing.T) {
	initTaskEngineForTest(t)
	services.TaskEngine().Stop()

	router, _ := taskMonitorRouter()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-retention/toggle", strings.NewReader(`{"enabled":false}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("已停引擎 toggle status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}
	var pref int
	if err := db.DB.QueryRow(`SELECT enabled FROM task_loop_prefs WHERE task_id='audit-retention'`).Scan(&pref); err == nil {
		t.Fatalf("已停引擎的调度操作未生效，不得落偏好（enabled=%d）", pref)
	}

	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	control := gin.New()
	control.POST("/system/tasks/:id/control", h.ControlSystemTask)
	rec = httptest.NewRecorder()
	control.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-issuance/control", strings.NewReader(`{"action":"stop"}`)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("已停引擎 control status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}

	// Cancel 与 toggle/control 同口径：已停引擎上 te.Cancel 恒 false，409「任务
	// 未在运行」会把「引擎已停止」误报成任务状态问题。
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/crs/cancel", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("已停引擎 cancel status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}

	// Trigger 同口径：已停引擎 admission 恒 ErrEngineStopped，此前并入 409
	// Conflict（与族内 503 矛盾）并补记一条误导性「触发失败」审计。
	before := countTaskAuditForTest(t, "触发失败")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/log-cleanup/trigger", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("已停引擎 trigger status=%d body=%s, want 503", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "任务引擎已停止") {
		t.Fatalf("trigger body=%s, want 「任务引擎已停止」", rec.Body.String())
	}
	if after := countTaskAuditForTest(t, "触发失败"); after != before {
		t.Fatalf("已停引擎的 admission 拒绝不得记「触发失败」审计（before=%d after=%d）", before, after)
	}
}

// countTaskAuditForTest 统计审计表中指定动作的行数（引擎停止边界用例用）。
func countTaskAuditForTest(t *testing.T, action string) int {
	t.Helper()
	var n int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&n); err != nil {
		t.Fatalf("count audit(%s): %v", action, err)
	}
	return n
}
