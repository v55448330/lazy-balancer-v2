package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// LB42-4(第 42 轮审计):cert_job_log_size_mb 与 runtime_log_size_mb 仅有 >0
// 下限,无上限——天文值落库使轮转实效、日志无限增长(caddy_log_size_mb 已在
// SYS41-7 补 100-10240;两列 UI :max=10240 同口径)。补 1-10240 上限;
// logstats 消费侧不改。
func TestUpdateConfig_rejectsExcessiveLogSizeMB(t *testing.T) {
	// Given
	handler := newBackupTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/config", handler.UpdateConfig)

	for _, body := range []string{
		`{"source":"basic","cert_job_log_size_mb":99999}`,
		`{"source":"basic","runtime_log_size_mb":99999}`,
		`{"source":"basic","cert_job_log_size_mb":10241}`,
		`{"source":"basic","runtime_log_size_mb":10241}`,
	} {
		// When
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)

		// Then 400
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d body=%s, want 400", body, response.Code, response.Body.String())
		}
	}

	// 回归:边界 10240 与常规值仍 200;0 保持既有 400(下限不变)
	for _, body := range []string{
		`{"source":"basic","cert_job_log_size_mb":10240}`,
		`{"source":"basic","runtime_log_size_mb":10240}`,
		`{"source":"basic","cert_job_log_size_mb":10}`,
	} {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("body=%s status=%d body=%s, want 200", body, response.Code, response.Body.String())
		}
	}
	for _, body := range []string{
		`{"source":"basic","cert_job_log_size_mb":0}`,
		`{"source":"basic","runtime_log_size_mb":-1}`,
	} {
		request := httptest.NewRequest(http.MethodPut, "/config", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("body=%s status=%d, want 400(下限保持)", body, response.Code)
		}
	}
}
