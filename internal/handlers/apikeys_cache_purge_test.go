package handlers

// 第 49 轮 F49-P5-19①：删除/禁用 API Key 必须触发白名单 CIDR 解析缓存的
// 按 keyID 前缀清扫——middleware 的 apiKeyWhitelistCache 键含白名单内容
// （变更自动新键），但 Key 删除/禁用后历史条目永不再命中却永久驻留=无界累积。
// 钩子由 middleware 经 SetAPIKeyWhitelistCachePurge 注入（反向 import 会成环）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAPIKeyDeleteAndDisable_purgeWhitelistCacheHook(t *testing.T) {
	setupAPIKeyTestDB(t)
	gin.SetMode(gin.TestMode)
	var purged []int
	SetAPIKeyWhitelistCachePurge(func(keyID int) { purged = append(purged, keyID) })
	t.Cleanup(func() { SetAPIKeyWhitelistCachePurge(nil) })
	h := &Handlers{}

	// When 1：自助删除（alice 删自己的 key 10）
	recorder := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/api/v1/users/me/api-keys/10", nil)
	ctx.Set("user_id", 1)
	ctx.Params = gin.Params{{Key: "id", Value: "10"}}
	h.DeleteCurrentUserAPIKey(ctx)
	// Then 1：删除成功、成功响应保留且钩子拿到 keyID 10
	if recorder.Code != http.StatusOK {
		t.Fatalf("delete status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "API 密钥已删除") {
		t.Fatalf("delete body=%s, want 成功响应保留", recorder.Body.String())
	}
	if len(purged) != 1 || purged[0] != 10 {
		t.Fatalf("删除后钩子记录=%v, want [10]", purged)
	}

	// When 2：管理员禁用（bob 的 key 20 is_enabled=false）
	purged = nil
	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/20/status",
		strings.NewReader(`{"is_enabled":false}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")
	ctx.Params = gin.Params{{Key: "id", Value: "20"}}
	h.UpdateAPIKeyStatus(ctx)
	// Then 2：禁用触发清扫且成功响应保留
	if recorder.Code != http.StatusOK {
		t.Fatalf("disable status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "API 密钥已更新") {
		t.Fatalf("disable body=%s, want 成功响应保留", recorder.Body.String())
	}
	if len(purged) != 1 || purged[0] != 20 {
		t.Fatalf("禁用后钩子记录=%v, want [20]", purged)
	}

	// When 3：重新启用（is_enabled=true）——不触发清扫（Key 存活，条目仍会命中）
	purged = nil
	recorder = httptest.NewRecorder()
	ctx, _ = gin.CreateTestContext(recorder)
	ctx.Request = httptest.NewRequest(http.MethodPut, "/api/v1/api-keys/20/status",
		strings.NewReader(`{"is_enabled":true}`))
	ctx.Request.Header.Set("Content-Type", "application/json")
	ctx.Set("user_id", 1)
	ctx.Set("role", "admin")
	ctx.Params = gin.Params{{Key: "id", Value: "20"}}
	h.UpdateAPIKeyStatus(ctx)
	// Then 3：启用不清扫
	if recorder.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if len(purged) != 0 {
		t.Fatalf("启用不应清扫，钩子记录=%v", purged)
	}
}
