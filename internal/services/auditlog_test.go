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

// （R69 过度修复审查 REMOVE：TestFormatAuditActionDirectConfigReload 已删除——
// 其断言被 TestAuditGenericRoutesExactlyOnce 的 /config/reload 子测试完全吸收
//（B/D 双域独立确认零覆盖）；R65 决策文档化于 auditlog.go FormatAuditAction
// 注释与 genericRouteRegistry。）

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
