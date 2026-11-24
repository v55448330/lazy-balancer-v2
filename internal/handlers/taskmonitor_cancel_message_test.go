package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

// 取消一个「正在运行但不可取消」的任务：拒绝的原因是任务不支持取消，不是
// 「任务未在运行」——后者与监控页同时显示的「运行中」自相矛盾，会让运维
// 反复点取消并怀疑状态失真。
func TestCancelSystemTask_runningNonCancelableNamesTheRealReason(t *testing.T) {
	newBackupTestHandlers(t)
	initTaskEngineForTest(t)
	te := services.TaskEngine()
	started := make(chan struct{})
	release := make(chan struct{})
	t.Cleanup(func() { close(release) }) // 晚于引擎夹具注册 → 先于引擎停止执行
	if err := te.Register(taskengine.Descriptor{
		ID: "t-nocancel-running", Family: "test", Name: "不可取消的常驻任务",
		Kind: taskengine.KindDaemon, RunsOn: taskengine.RoleAny,
		Run: func(taskengine.RunContext) error {
			close(started)
			<-release
			return nil
		},
	}); err != nil {
		t.Fatal(err)
	}
	te.StartLoop("t-nocancel-running")
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("常驻任务未启动")
	}

	router, _ := taskMonitorRouter()
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/t-nocancel-running/cancel", nil))
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s, want 409", rec.Code, rec.Body.String())
	}
	var resp struct {
		Message    string `json:"message"`
		MessageKey string `json:"message_key"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.MessageKey != "k_44b8c98f" {
		t.Fatalf("不可取消任务的取消拒绝必须点名「该任务不支持手动取消」: key=%q message=%q", resp.MessageKey, resp.Message)
	}
	if strings.Contains(resp.Message, "未在运行") {
		t.Fatalf("不可取消任务的取消拒绝不得报「任务未在运行」: %q", resp.Message)
	}

	// 回归形状：可取消但当前未运行的任务仍是「任务未在运行」。
	if err := te.Register(taskengine.Descriptor{
		ID: "t-cancel-idle", Family: "test", Name: "可取消的空闲任务",
		Kind: taskengine.KindOneshot, RunsOn: taskengine.RoleAny, Cancelable: true,
		Run: func(taskengine.RunContext) error { return nil },
	}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/system/tasks/t-cancel-idle/cancel", nil))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "k_9dd23c40") {
		t.Fatalf("可取消但未运行的任务应保持「任务未在运行」: status=%d body=%s", rec.Code, rec.Body.String())
	}
}
