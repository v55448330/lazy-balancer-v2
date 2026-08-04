package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/config"
)

func TestGetAppLogs_reads_configured_log_file(t *testing.T) {
	// Given：超过 500 行的自定义路径日志文件
	logPath := filepath.Join(t.TempDir(), "custom-app.log")
	var builder strings.Builder
	for index := 1; index <= 600; index++ {
		builder.WriteString(fmt.Sprintf("log-line-%d\n", index))
	}
	if err := os.WriteFile(logPath, []byte(builder.String()), 0o644); err != nil {
		t.Fatalf("write log file: %v", err)
	}
	handler := &Handlers{cfg: &config.Config{LogFile: logPath}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then：读取配置路径且仅保留尾部 500 行
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
	if !strings.Contains(envelope.Data.Content, "log-line-102") || !strings.Contains(envelope.Data.Content, "log-line-600") {
		t.Fatalf("log content missing expected tail lines: %q", envelope.Data.Content)
	}
	if strings.Contains(envelope.Data.Content, "log-line-101\n") {
		t.Fatalf("log content kept more than 500 lines: %q", envelope.Data.Content)
	}
}

func TestGetAppLogs_returns_empty_content_when_log_file_missing(t *testing.T) {
	// Given
	handler := &Handlers{cfg: &config.Config{LogFile: filepath.Join(t.TempDir(), "missing.log")}}
	router := gin.New()
	router.GET("/system/logs", handler.GetAppLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/system/logs", nil))

	// Then
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"content":""`) {
		t.Fatalf("status=%d body=%s, want 200 with empty content", response.Code, response.Body.String())
	}
}
