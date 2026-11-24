package handlers

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/iotest"

	"lazy-balancer-v2/internal/services"
)

// 请求体读取失败（连接中断、读超时等瞬态故障）必须回 5xx：写侧只把 400/413
// 当「该批不可入库」直接丢弃，其余错误才落 spool 稍后补采。读失败回 400
// 等于把一批本可重试的事件永久丢弃。
func TestSecurityEventsIPCHandler_bodyReadFailureReturnsRetryable(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	h := &SecurityEventsIPCServer{}

	for _, path := range []string{services.SecurityEventsIPCIngestPath, services.SecurityEventsIPCIngestHumanPath} {
		req := httptest.NewRequest(http.MethodPost, path, io.NopCloser(iotest.ErrReader(errors.New("injected transient read failure"))))
		rec := httptest.NewRecorder()
		http.HandlerFunc(h.ingestRouter).ServeHTTP(rec, req)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s 读失败 status=%d body=%.120s, want 503（写侧据此保留 spool）", path, rec.Code, rec.Body.String())
		}
		if got := securityEventsIPCRowCount(t); got != 0 {
			t.Fatalf("%s 读失败不得有半批落库: rows=%d", path, got)
		}
	}
}
