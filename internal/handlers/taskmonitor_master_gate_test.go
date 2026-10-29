package handlers

// requireMasterNode 的角色读契约（与 TestGetSystemInfo_roleReadIndependentOfClientCancel
// 同形）：请求 ctx 已取消（客户端在角色读之前断开）时仍必须解析出真实角色，
// 不得把「客户端断开」记成「节点角色查询失败」500——触发请求天然可能早断
// （前端超时/关页），写操作是否放行与该连接已无因果关系。

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestRequireMasterNode_roleReadIndependentOfClientCancel(t *testing.T) {
	newBackupTestHandlers(t)

	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	request := httptest.NewRequest(http.MethodPost, "/system/tasks/x/trigger", nil)
	clientCtx, cancel := context.WithCancel(request.Context())
	cancel() // 客户端在角色读之前断开
	ctx.Request = request.WithContext(clientCtx)

	if !requireMasterNode(ctx) {
		t.Fatalf("status=%d body=%s, want 主节点放行（角色读不得被客户端取消影响）", recorder.Code, recorder.Body.String())
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("gate returned non-200 write: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}
