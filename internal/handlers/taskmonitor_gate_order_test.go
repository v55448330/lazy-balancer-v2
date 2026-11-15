package handlers

// 任务监控写端点门序钉测：导入窗口 409 必须先于主节点门（与
// Trigger/Toggle/Control 同族）——从节点在导入窗口内收到 403 会把排障方向
// 指向集群角色，而真实事实是「导入进行中，稍后重试」。

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"lazy-balancer-v2/internal/db"
)

// Given 从节点 DB 实态 + 导入窗口开启。
// When 取消运行中任务。
// Then 409 import_in_progress（导入门先于主节点门，不得先 403）。
func TestCancelSystemTask_importGatePrecedesMasterGate(t *testing.T) {
	initTaskEngineForTest(t)
	newBackupTestHandlers(t)
	if _, err := db.DB.Exec(`UPDATE global_config SET is_master=0 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	r, _ := taskMonitorRouter()
	closeWindow := beginImportWindowForTest(t)
	defer closeWindow()

	resp := httptest.NewRecorder()
	r.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/system/tasks/threat/cancel", nil))
	if resp.Code != http.StatusConflict {
		t.Fatalf("从节点+导入窗口取消 status=%d body=%s, want 409（导入门必须先于主节点门）", resp.Code, resp.Body.String())
	}
}
