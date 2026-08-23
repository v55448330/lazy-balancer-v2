package services

import (
	"database/sql"
	"testing"

	"lazy-balancer-v2/internal/db"
)

func TestGetConfigSourceSection(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{source: "basic", want: "基础设置"},
		{source: "cluster", want: "集群管理"},
		{source: "acme", want: "ACME配置"},
		{source: "caddy", want: "Caddy配置"},
		{source: "", want: "全局配置"},
		{source: "unknown", want: "全局配置"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := GetConfigSourceSection(tt.source); got != tt.want {
				t.Fatalf("GetConfigSourceSection(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestStartAuditCleanup_starts_once_and_stops(t *testing.T) {
	// Given
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
	})
	StartAuditCleanup()
	firstDone := auditCleanupDone

	// When
	StartAuditCleanup()
	secondDone := auditCleanupDone
	StopAuditCleanup()

	// Then
	if firstDone != secondDone {
		t.Fatal("repeated startup created another audit cleanup worker")
	}
	if firstDone == nil {
		t.Fatal("audit cleanup worker did not publish its completion channel")
	}
	select {
	case <-firstDone:
	default:
		t.Fatal("audit cleanup worker did not stop")
	}
}

// R66 D-N3：Explicit 路由的映射已全部删除（handler 显式记录 + HasExplicitAuditEvent
// 前置短路使中间件映射不可达）——这些端点经 FormatAuditAction 必须返回空。
func TestFormatAuditActionExplicitRoutesReturnEmpty(t *testing.T) {
	paths := []struct{ method, path string }{
		{"POST", "/api/v1/rules/lb_example/enable"},
		{"POST", "/api/v1/certificates/issue"},
		{"POST", "/api/v1/auth/login"},
		{"POST", "/api/v1/cluster/register"},
		{"PUT", "/api/v1/ca-providers/1"},
	}
	for _, tt := range paths {
		action, resource, _ := FormatAuditAction(tt.method, tt.path)
		if action != "" || resource != "" {
			t.Fatalf("FormatAuditAction(%s %s) = (%q, %q), want 空（Explicit 路由由 handler 记录，映射非空即双条风险）", tt.method, tt.path, action, resource)
		}
	}
}

func TestFormatAuditActionDirectConfigReload(t *testing.T) {
	// R65 D-N1：/config/reload 改由 handler（ReloadCaddy）单独记录，映射为空
	//（中间件跳过）——此前映射+handler 双记录，单次动作两条 audit_log。
	action, resource, _ := FormatAuditAction("POST", "/api/v1/config/reload")
	if action != "" || resource != "" {
		t.Fatalf("FormatAuditAction() = (%q, %q), want 空（handler 已显式记录）", action, resource)
	}
}

func TestRecordAuditLogWritesToIndependentDatabase(t *testing.T) {
	oldDB, oldAuditDB := db.DB, db.AuditDB
	mainDB, err := sql.Open("sqlite", t.TempDir()+"/main.db")
	if err != nil {
		t.Fatal(err)
	}
	auditDB, err := sql.Open("sqlite", t.TempDir()+"/audit.db")
	if err != nil {
		t.Fatal(err)
	}
	db.DB, db.AuditDB = mainDB, auditDB
	t.Cleanup(func() {
		db.DB, db.AuditDB = oldDB, oldAuditDB
		mainDB.Close()
		auditDB.Close()
	})
	if _, err := auditDB.Exec(`CREATE TABLE audit_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username VARCHAR(100), action VARCHAR(50) NOT NULL, resource VARCHAR(100),
		detail TEXT, ip_address VARCHAR(45), created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		t.Fatal(err)
	}

	RecordAuditLog("system", "测试", "审计", "同步写入", "127.0.0.1")

	var count int
	if err := auditDB.QueryRow("SELECT COUNT(*) FROM audit_log WHERE detail='同步写入'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("audit DB count = %d, want 1", count)
	}
}

func TestFormatAuditActionAuthAndNodeRegistration(t *testing.T) {
	// R66 D-N3：原断言 /nodes/register 映射——该路由实际注册为 /cluster/register，
	// 映射从未可达（死映射）；/auth/login 为 Explicit（handler 记录 登录成功/失败）。
	// 两者现均须为空。
	action, resource, _ := FormatAuditAction("POST", "/api/v1/auth/login")
	if action != "" || resource != "" {
		t.Fatalf("login mapping = (%q, %q), want 空", action, resource)
	}
	action, resource, _ = FormatAuditAction("POST", "/api/v1/nodes/register")
	if action != "" || resource != "" {
		t.Fatalf("node registration mapping = (%q, %q), want 空（原为指向不存在路由的死映射）", action, resource)
	}
}
