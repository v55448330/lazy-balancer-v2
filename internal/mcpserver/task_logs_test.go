package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/mcpserver"
	"lazy-balancer-v2/internal/services"
	"lazy-balancer-v2/internal/taskengine"
)

func TestGetSystemTaskLogs_certJobReadsRealLogThroughMCP(t *testing.T) {
	// Given：真实 DB 中的 cert-job:1 → lb_mcp_log，及其实际证书日志文件。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	oldLogDir := taskengine.LogDir()
	taskengine.SetLogDir(t.TempDir())
	t.Cleanup(func() { taskengine.SetLogDir(oldLogDir) })
	if _, err := db.DB.Exec(`INSERT INTO cert_jobs (id,rule_id,domain,status) VALUES (1,'lb_mcp_log','mcp.example.test','queued')`); err != nil {
		t.Fatal(err)
	}
	logPath := services.CertJobLogPath("lb_mcp_log")
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte("real-cert-job-log-line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/system/tasks/:id/logs", (&handlers.Handlers{}).GetSystemTaskLogs)
	rest := httptest.NewServer(router)
	defer rest.Close()

	// When：经 MCP tools/call → 真实 API handler → DB → 文件读取。
	mcpHandler := mcpserver.New(rest.URL+"/api/v1", rest.Client())
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_system_task_logs","arguments":{"id":"cert-job:1"}}}`
	request := httptest.NewRequest(http.MethodPost, "/api/v1/mcp", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json, text/event-stream")
	request.Header.Set("X-API-Key", "lb_sk_redirect-test")
	response := httptest.NewRecorder()
	mcpHandler.ServeHTTP(response, request)
	result := response.Body.String()

	// Then：返回真实证书日志，而不是 tasks/cert-job:1.log 的空内容。
	if !strings.Contains(result, "real-cert-job-log-line") {
		t.Fatalf("MCP 未读到真实证书日志: %q", result)
	}
}

func TestGetSystemTaskLogs_certJobMissingReturnsEmpty(t *testing.T) {
	// Given：不存在的 cert-job:999。
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/v1/system/tasks/:id/logs", (&handlers.Handlers{}).GetSystemTaskLogs)
	response := httptest.NewRecorder()

	// When
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/system/tasks/cert-job:999/logs", nil))

	// Then：与普通不存在任务一致，返回空内容而非 500。
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"content":""`) {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}
