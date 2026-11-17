package handlers

// LOG_FILE 空串时 GetAppLogs 必须经 logPaths 与
// GetLogStats 同口径兜底到默认运行日志路径，而不是读空串路径返回恒空内容
// （面板空白与 logstats 统计矛盾）。默认路径为包级 var（wafAuditLogFile
// 同模式的测试注入缝）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestGetAppLogs_emptyLogFileFallsBackToDefaultRuntimePath(t *testing.T) {
	withIsolatedGlobal(t)
	// Given：默认运行日志存在内容，配置显式 log_file 为空串
	logPath := filepath.Join(t.TempDir(), "lazy-balancer.log")
	if err := os.WriteFile(logPath, []byte("runtime-line-1\nruntime-line-2\n"), 0o644); err != nil {
		t.Fatalf("write runtime log: %v", err)
	}
	orig := defaultRuntimeLogPath
	defaultRuntimeLogPath = logPath
	defer func() { defaultRuntimeLogPath = orig }()

	handler := &Handlers{cfg: &config.Config{LogFile: ""}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then：读到默认运行日志内容，而非空串路径的恒空 200
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", response.Code, response.Body.String())
	}
	var envelope struct {
		Data struct {
			Content string `json:"content"`
		} `json:"data"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !strings.Contains(envelope.Data.Content, "runtime-line-2") {
		t.Fatalf("empty LOG_FILE must fall back to default runtime log, got %q", envelope.Data.Content)
	}
}
