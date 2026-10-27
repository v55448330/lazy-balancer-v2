package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// GET /caddy/logs 注册在 business 组（任意登录用户可读），因此它的 5xx 必须是
// 固定文案：日志文件的容器内绝对路径与 errno 只进运行日志。此前该端点被当作
// admin 排障接口，把 `open /app/logs/...: permission denied` 一类文本原样回给
// 任何登录用户（信息泄露，且政策前提与路由组失配）。
func TestGetCaddyLogs_5xxHidesPathAndErrno(t *testing.T) {
	h := newBackupTestHandlers(t)
	dir := t.TempDir()
	// 目录冒充日志文件：os.Stat 成功，os.Open+Seek/Read 失败——命中 Open 分支。
	dirAsLog := filepath.Join(dir, "caddy-runtime.log")
	if err := os.MkdirAll(dirAsLog, 0o755); err != nil {
		t.Fatalf("mkdir log path: %v", err)
	}
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": dirAsLog}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)
	response := httptest.NewRecorder()

	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))

	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d body=%s, want 500", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if strings.Contains(body, dirAsLog) {
		t.Fatalf("响应体泄漏日志文件绝对路径: %s", body)
	}
	for _, leak := range []string{"is a directory", "no such file", "permission denied", "errno"} {
		if strings.Contains(strings.ToLower(body), leak) {
			t.Fatalf("响应体泄漏底层 errno(%s): %s", leak, body)
		}
	}
	if !strings.Contains(body, "日志文件不可访问") && !strings.Contains(body, "打开日志文件失败") && !strings.Contains(body, "读取日志文件失败") {
		t.Fatalf("响应体缺少固定文案: %s", body)
	}
}

// 回归形状：日志文件不存在时仍是 200 + 空内容（fail-visible 的「无该日志」语义
// 不得被固定文案改动波及），未知 type 仍是点名可选值的 400。
func TestGetCaddyLogs_missingFileAndUnknownTypeUnchanged(t *testing.T) {
	h := newBackupTestHandlers(t)
	oldPaths := caddyLogPaths
	caddyLogPaths = map[string]string{"runtime": filepath.Join(t.TempDir(), "absent.log")}
	t.Cleanup(func() { caddyLogPaths = oldPaths })

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/caddy/logs", h.GetCaddyLogs)

	missing := httptest.NewRecorder()
	router.ServeHTTP(missing, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=runtime", nil))
	if missing.Code != http.StatusOK || !strings.Contains(missing.Body.String(), `"content":""`) {
		t.Fatalf("缺失日志 status=%d body=%s, want 200 空内容", missing.Code, missing.Body.String())
	}

	unknown := httptest.NewRecorder()
	router.ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/caddy/logs?type=nope", nil))
	if unknown.Code != http.StatusBadRequest || !strings.Contains(unknown.Body.String(), "runtime") {
		t.Fatalf("未知类型 status=%d body=%s, want 400 点名可选值", unknown.Code, unknown.Body.String())
	}
}
