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

func setupTaskLogDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		mcpserver.RestoreDBForTest(oldDB, oldMetricsDB, oldAuditDB)
	})
}

func TestGetSystemTaskLogs_certJobReadsRealLogThroughMCP(t *testing.T) {
	setupTaskLogDB(t)
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
	mcpHandler := mcpserver.NewForTest(rest.URL+"/api/v1", rest.Client())
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
	setupTaskLogDB(t)
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

// get_cert_job_logs 双载体（tools.go usage / server.go spec）必须披露 256KB
// 截断行为：REST 端点超预算时首行前置提示行并携带 truncated 标记
// （readRotatedLogTail 单源），与 get_system_task_logs 同形态——漏披露会让
// Agent 把截断尾部当完整日志消费。源码文本对账，措辞改写丢半句在此红。
func TestGetCertJobLogs_descriptionsDiscloseTruncation(t *testing.T) {
	for _, face := range []string{"tools.go", "server.go"} {
		source, err := os.ReadFile(face)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", face, err)
		}
		start := strings.Index(string(source), `"get_cert_job_logs"`)
		if start < 0 {
			t.Fatalf("%s 缺 get_cert_job_logs 载体", face)
		}
		carrier := string(source)[start:]
		if end := strings.Index(carrier, "\n"); end >= 0 {
			carrier = carrier[:end]
		}
		for _, marker := range []string{"256KB", "日志过长，仅显示最近 256KB", "truncated"} {
			if !strings.Contains(carrier, marker) {
				t.Errorf("%s get_cert_job_logs 载体缺截断披露 %q: %s", face, marker, carrier)
			}
		}
	}
}
