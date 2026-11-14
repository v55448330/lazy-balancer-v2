package handlers

// 触发 admission 错误的 HTTP 映射单源钉测（respondTaskTriggerAdmissionError，
// 任务监控/规则库立即更新/爬虫地址库三处共用）：
//   - ErrNotMaster → 403；ErrAlreadyRunning/ErrSchedulingPaused → 409；
//   - ErrEngineStopped → 503——与 toggle/cancel/control 的「任务引擎已停止」
//     同口径（关停竞态窗：IsStopped 预检之后引擎才停止，admission 返回
//     ErrEngineStopped 不得漂移成 409）。

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/taskengine"
)

func TestRespondTaskTriggerAdmissionError_statusMapping(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cases := []struct {
		name     string
		err      error
		wantCode int
		wantBody string
	}{
		{"not master", taskengine.ErrNotMaster, http.StatusForbidden, ""},
		{"already running", taskengine.ErrAlreadyRunning, http.StatusConflict, ""},
		{"scheduling paused", taskengine.ErrSchedulingPaused, http.StatusConflict, ""},
		{"engine stopped", taskengine.ErrEngineStopped, http.StatusServiceUnavailable, "任务引擎已停止"},
		{"engine stopped wrapped", errors.Join(errors.New("admission"), taskengine.ErrEngineStopped), http.StatusServiceUnavailable, "任务引擎已停止"},
		{"unknown admission failure", errors.New("boom"), http.StatusServiceUnavailable, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodPost, "/system/tasks/x/trigger", nil)
			respondTaskTriggerAdmissionError(c, tc.err)
			if rec.Code != tc.wantCode {
				t.Fatalf("status=%d body=%s, want %d", rec.Code, rec.Body.String(), tc.wantCode)
			}
			if tc.wantBody != "" && !strings.Contains(rec.Body.String(), tc.wantBody) {
				t.Fatalf("body=%s, want 含 %q", rec.Body.String(), tc.wantBody)
			}
		})
	}
}
