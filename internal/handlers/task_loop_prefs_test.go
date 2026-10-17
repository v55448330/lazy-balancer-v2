package handlers

// U10-F02（第 78 轮）：任务监控 Toggle/Control 成功改变调度后写入节点本地
// 偏好；业务驱动与触发类任务不得写偏好。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

func taskLoopPrefRow(t *testing.T, id string) (int, bool) {
	t.Helper()
	var enabled int
	err := db.DB.QueryRow(`SELECT enabled FROM task_loop_prefs WHERE task_id=?`, id).Scan(&enabled)
	if err != nil {
		return 0, false
	}
	return enabled, true
}

func TestToggleSystemTask_persistsLoopPreference(t *testing.T) {
	initTaskEngineForTest(t)
	services.TaskEngine().StartLoop("audit-retention")
	router, _ := taskMonitorRouter()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-retention/toggle", strings.NewReader(`{"enabled":false}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("toggle status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, ok := taskLoopPrefRow(t, "audit-retention"); !ok || enabled != 0 {
		t.Fatalf("toggle 停止后偏好 enabled=%d found=%v, want 0/true", enabled, ok)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-retention/toggle", strings.NewReader(`{"enabled":true}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("toggle status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, ok := taskLoopPrefRow(t, "audit-retention"); !ok || enabled != 1 {
		t.Fatalf("toggle 恢复后偏好 enabled=%d found=%v, want 1/true", enabled, ok)
	}
}

func TestControlSystemTask_persistsLoopPreference(t *testing.T) {
	initTaskEngineForTest(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-issuance/control", strings.NewReader(`{"action":"stop"}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("control status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, ok := taskLoopPrefRow(t, "cert-issuance"); !ok || enabled != 0 {
		t.Fatalf("control stop 后偏好 enabled=%d found=%v, want 0/true", enabled, ok)
	}
	response = httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-issuance/control", strings.NewReader(`{"action":"restart"}`)))
	if response.Code != http.StatusOK {
		t.Fatalf("control status=%d body=%s", response.Code, response.Body.String())
	}
	if enabled, ok := taskLoopPrefRow(t, "cert-issuance"); !ok || enabled != 1 {
		t.Fatalf("control restart 后偏好 enabled=%d found=%v, want 1/true", enabled, ok)
	}
}

func TestToggleSystemTask_businessDrivenDoesNotPersistPreference(t *testing.T) {
	initTaskEngineForTest(t)
	router, _ := taskMonitorRouter()
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/toggle", strings.NewReader(`{"enabled":false}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("业务驱动任务 toggle status=%d, want 400", response.Code)
	}
	if _, ok := taskLoopPrefRow(t, "threat"); ok {
		t.Fatal("业务驱动任务不得写调度偏好")
	}
}
