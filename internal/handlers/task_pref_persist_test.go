package handlers

// 调度偏好写入失败的响应契约与 cert-job 历史端点的库句柄守卫。
//
// 启停端点必须先持久化偏好再切换内存态：写失败时调度状态原样保留并响亮
// 500（此前先切换后吞 WARN，响应仍 200 且偏好零行——重启后按默认清单复活，
// 与用户意图相反）。cert-job 历史在库句柄缺失时按 500 明确失败（此前裸用
// db.DB nil 解引用 panic，靠 gin.Recovery 兜成 500 + 栈噪声）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"

	"github.com/gin-gonic/gin"
)

// breakTaskLoopPrefs 让偏好的写入路径失败且可还原：重命名表比 DROP 安全，
// 同包后续用例仍需要该表（--count / 顺序无关）。
func breakTaskLoopPrefs(t *testing.T) {
	t.Helper()
	if _, err := db.DB.Exec(`ALTER TABLE task_loop_prefs RENAME TO task_loop_prefs_broken`); err != nil {
		t.Fatalf("rename task_loop_prefs: %v", err)
	}
	t.Cleanup(func() {
		if _, err := db.DB.Exec(`ALTER TABLE task_loop_prefs_broken RENAME TO task_loop_prefs`); err != nil {
			t.Errorf("restore task_loop_prefs: %v", err)
		}
	})
}

func assertPrefWriteFailureResponse(t *testing.T, response *httptest.ResponseRecorder) {
	t.Helper()
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500（偏好写失败必须拒绝）", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "任务调度偏好保存失败") {
		t.Fatalf("body=%s, want 含「任务调度偏好保存失败」", response.Body.String())
	}
	if strings.Contains(response.Body.String(), "已恢复") || strings.Contains(response.Body.String(), "已停止") || strings.Contains(response.Body.String(), "已重启") {
		t.Fatalf("body=%s，写失败不得携带成功文案", response.Body.String())
	}
}

// Given 偏好表不可写（写失败形态），任务调度当前为关。
// When 打开调度。
// Then 500 且内存态保持关闭（切换发生在持久化成功之后）。
func TestToggleSystemTask_prefWriteFailureRejectsAndKeepsState(t *testing.T) {
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	te.StopLoop("audit-retention")
	router, _ := taskMonitorRouter()

	breakTaskLoopPrefs(t)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/audit-retention/toggle", strings.NewReader(`{"enabled":true}`)))

	assertPrefWriteFailureResponse(t, response)
	if meta, ok := te.Lookup("audit-retention"); !ok || meta.LoopOn {
		t.Fatalf("偏好写失败后 loop_on=%v found=%v, want false（内存态不动）", meta.LoopOn, ok)
	}
}

// Given 偏好表不可写。
// When control stop / restart。
// Then 两种动作都 500 且调度状态与动作前一致（restart 不得半途停掉也不得启动）。
func TestControlSystemTask_prefWriteFailureRejectsAndKeepsState(t *testing.T) {
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.POST("/system/tasks/:id/control", h.ControlSystemTask)

	breakTaskLoopPrefs(t)
	for _, tc := range []struct {
		action    string
		beforeOn  bool
		wantAfter bool
	}{
		{action: "stop", beforeOn: true, wantAfter: true},
		{action: "restart", beforeOn: false, wantAfter: false},
	} {
		if tc.beforeOn {
			te.StartLoop("cert-issuance")
		} else {
			te.StopLoop("cert-issuance")
		}
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/system/tasks/cert-issuance/control", strings.NewReader(`{"action":"`+tc.action+`"}`)))
		assertPrefWriteFailureResponse(t, response)
		if meta, ok := te.Lookup("cert-issuance"); !ok || meta.LoopOn != tc.wantAfter {
			t.Fatalf("%s 偏好写失败后 loop_on=%v found=%v, want %v（内存态不动）", tc.action, meta.LoopOn, ok, tc.wantAfter)
		}
	}
}

// Given 库句柄缺失（装配窗口/关闭后）。
// When 读取 cert-job 动态行历史。
// Then 500「数据库未初始化」，不得 nil 解引用 panic。
func TestCertJobRunHistory_nilDatabaseReturnsNotInitialized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	router.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)

	old, oldCurrent := db.DB, db.GetDB()
	db.DB = nil
	db.SetDB(nil)
	t.Cleanup(func() { db.DB = old; db.SetDB(oldCurrent) })

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/tasks/cert-job:1/history", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Body.String(), "数据库未初始化") {
		t.Fatalf("body=%s, want 含「数据库未初始化」", response.Body.String())
	}
}
