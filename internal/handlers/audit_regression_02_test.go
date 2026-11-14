package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

func TestDBQueryNotFoundDistinguishesMissingRowsFromDatabaseErrors(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "missing", err: fmt.Errorf("query: %w", sql.ErrNoRows), want: http.StatusNotFound},
		{name: "database failure", err: errors.New("database is closed"), want: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := httptest.NewRecorder()
			context, _ := gin.CreateTestContext(response)
			if !dbQueryNotFound(context, tt.err, "not found", "test query") {
				t.Fatal("error was not handled")
			}
			if response.Code != tt.want {
				t.Fatalf("status=%d, want %d", response.Code, tt.want)
			}
		})
	}
}

func TestIDHandlersRejectNonPositiveIDs(t *testing.T) {
	h := &Handlers{}
	tests := []struct {
		name   string
		method string
		path   string
		route  string
		handle gin.HandlerFunc
	}{
		{name: "get cert job", method: http.MethodGet, path: "/jobs/0", route: "/jobs/:id", handle: h.GetCertJob},
		{name: "get cert job logs", method: http.MethodGet, path: "/jobs/-1/logs", route: "/jobs/:id/logs", handle: h.GetCertJobLogs},
		{name: "get CA provider", method: http.MethodGet, path: "/ca/0", route: "/ca/:id", handle: h.GetCAProvider},
		{name: "update CA provider", method: http.MethodPut, path: "/ca/-1", route: "/ca/:id", handle: h.UpdateCAProvider},
		{name: "test CA provider", method: http.MethodPost, path: "/ca/0/test", route: "/ca/:id/test", handle: h.TestCAProvider},
		{name: "registration status", method: http.MethodGet, path: "/registration/0", route: "/registration/:id", handle: h.GetClusterRegistrationStatus},
		{name: "test certificate config", method: http.MethodPost, path: "/certificate-configs/0/test", route: "/certificate-configs/:id/test", handle: h.TestCertificateConfig},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := gin.New()
			router.Handle(tt.method, tt.route, tt.handle)
			request := httptest.NewRequest(tt.method, tt.path, nil)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s, want 400", response.Code, response.Body.String())
			}
		})
	}
}

// CA 提供商写端点跟随全局「请求体大小」配置项（不再硬编码 1MB）。
// Given 配置上限 1MB。When 提交超过上限的 JSON。Then 413（与导入/PutCaddyConfig/
// admin-tls 同口径）。
func TestUpdateCAProvider_oversizedBodyReturns413(t *testing.T) {
	h := newBackupTestHandlers(t)
	h.caProviderService = services.NewCAProviderService()
	if _, err := db.DB.Exec("UPDATE global_config SET request_body_max_size_mb=1 WHERE id=1"); err != nil {
		t.Fatalf("set request body limit: %v", err)
	}
	router := gin.New()
	router.PUT("/ca/:id", h.UpdateCAProvider)
	body := `{"name":"` + strings.Repeat("a", (1<<20)+64) + `"}`
	request := httptest.NewRequest(http.MethodPut, "/ca/1", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d body=%.200s, want 413", response.Code, response.Body.String())
	}
}

// 5xx 写点单源：dbQueryNotFound 的 500 分支必须委托 writeInternalError，不得
// 自行 services.Logf + c.JSON——本函数有 18 个调用点，未来统一 5xx 策略
// （trace id / 统一脱敏 / 错误码映射）漏改这里即分叉。
func TestDBQueryNotFound_500BranchUsesWriteInternalError(t *testing.T) {
	source, err := os.ReadFile("db_errors.go")
	if err != nil {
		t.Fatalf("read db_errors.go: %v", err)
	}
	text := string(source)
	start := strings.Index(text, "func dbQueryNotFound(")
	if start < 0 {
		t.Fatal("db_errors.go 缺 dbQueryNotFound 定义")
	}
	rest := text[start:]
	end := strings.Index(rest, "\n}\n")
	if end < 0 {
		t.Fatal("dbQueryNotFound 函数体切片失败")
	}
	body := rest[:end]
	if !strings.Contains(body, `writeInternalError(c, http.StatusInternalServerError, "数据库错误"`) {
		t.Fatalf("dbQueryNotFound 的 500 分支必须委托统一写点: %s", body)
	}
	if strings.Contains(body, "c.JSON(http.StatusInternalServerError") {
		t.Fatal("dbQueryNotFound 不得自行写 500 响应（统一 5xx 策略会漏改）")
	}
}

// dbQueryNotFound 的 500 分支必须经统一写点：响应只含固定文案（不泄底层错误），
// operation 归因与底层错误只进日志——否则未来统一 5xx 策略会漏改本函数调用面。
func TestDBQueryNotFound_500UsesUnifiedWriter(t *testing.T) {
	logs := captureLog(t)
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	if !dbQueryNotFound(context, errors.New("disk I/O error"), "not found", "查询规则") {
		t.Fatal("error was not handled")
	}
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d, want 500", response.Code)
	}
	body := response.Body.String()
	if !strings.Contains(body, "数据库错误") || strings.Contains(body, "disk I/O error") {
		t.Fatalf("body=%s, want 固定文案且不泄露底层错误", body)
	}
	if !strings.Contains(logs.String(), "查询规则") || !strings.Contains(logs.String(), "disk I/O error") {
		t.Fatalf("日志=%q, want operation 归因与底层错误", logs.String())
	}
}
