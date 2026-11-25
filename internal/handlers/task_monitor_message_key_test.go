package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

// 畸形 cert-job ID 的 400 是用户可见文案：必须走 apimsg 词条（zh/en 成对 +
// message_key 稳定键），与同文件其余 400/404 同口径——英文用户此前拿到
// 硬编码 "Invalid job ID"，界面语言切换对该提示无效。
func TestSystemTaskInvalidCertJobIDIsKeyedMessage(t *testing.T) {
	withIsolatedGlobal(t)
	const (
		wantKey = "system.taskIdInvalid"
		wantZh  = "无效的任务 ID"
	)
	h := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/system/tasks/:id/trigger", h.TriggerSystemTask)
	router.GET("/system/tasks/:id/history", h.GetSystemTaskHistory)

	type response struct {
		Code       int    `json:"code"`
		Message    string `json:"message"`
		MessageKey string `json:"message_key"`
	}
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/system/tasks/cert-job:abc/trigger"},
		{http.MethodGet, "/system/tasks/cert-job:abc/history"},
	} {
		recorder := httptest.NewRecorder()
		router.ServeHTTP(recorder, httptest.NewRequest(tc.method, tc.path, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s %s status=%d body=%s, want 400", tc.method, tc.path, recorder.Code, recorder.Body.String())
		}
		var out response
		if err := json.Unmarshal(recorder.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s decode: %v", tc.method, tc.path, err)
		}
		if out.MessageKey != wantKey {
			t.Fatalf("%s %s message_key=%q, want %q（硬编码英文缺键化）", tc.method, tc.path, out.MessageKey, wantKey)
		}
		if out.Message != wantZh {
			t.Fatalf("%s %s message=%q, want %q", tc.method, tc.path, out.Message, wantZh)
		}
	}
}
