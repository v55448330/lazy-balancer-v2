package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// A-1(2026-09-10 审计):recordAudit 优先读中间件注入的 audit_ip(内部 MCP
// 转发请求的真实客户端 IP,经 constant-time 采信头),缺省回退 c.ClientIP()。
// 此前 handler 审计路径全部 127.0.0.1。
func TestRecordAudit_prefersContextAuditIP(t *testing.T) {
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeAuditDB(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Set("username", "admin")
	c.Set("audit_ip", "192.0.2.99")
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/config", nil)
	c.Request.RemoteAddr = "127.0.0.1:1234"

	recordAudit(c, "更新", "全局配置", "detail")

	var ip string
	if err := db.AuditDB.QueryRow(`SELECT ip_address FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&ip); err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if ip != "192.0.2.99" {
		t.Fatalf("ip_address=%q, want 192.0.2.99(采信 audit_ip)", ip)
	}
}
