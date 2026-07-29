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
		{source: "acme", want: "ACME全局设置"},
		{source: "caddy", want: "Caddy全局配置"},
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

func TestFormatAuditActionRuleEnable(t *testing.T) {
	action, resource, detail := FormatAuditAction("POST", "/api/v1/rules/lb_example/enable")
	if action != "启用" || resource != "负载均衡规则" || detail != "/api/v1/rules/lb_example/enable" {
		t.Fatalf("FormatAuditAction() = (%q, %q, %q)", action, resource, detail)
	}
}

func TestFormatAuditActionDirectConfigReload(t *testing.T) {
	action, resource, detail := FormatAuditAction("POST", "/api/v1/config/reload")
	if action != "重载" || resource != "Caddy配置" || detail != "/api/v1/config/reload" {
		t.Fatalf("FormatAuditAction() = (%q, %q, %q)", action, resource, detail)
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

func TestFormatAuditActionTriggerCertificateIssue(t *testing.T) {
	action, resource, _ := FormatAuditAction("POST", "/api/v1/certificates/issue")
	if action != "触发签发" || resource != "证书" {
		t.Fatalf("FormatAuditAction() = (%q, %q)", action, resource)
	}
}

func TestFormatAuditActionAuthAndNodeRegistration(t *testing.T) {
	action, resource, _ := FormatAuditAction("POST", "/api/v1/auth/login")
	if action != "登录" || resource != "用户认证" {
		t.Fatalf("login mapping = (%q, %q)", action, resource)
	}
	action, resource, _ = FormatAuditAction("POST", "/api/v1/nodes/register")
	if action != "注册" || resource != "集群节点" {
		t.Fatalf("node registration mapping = (%q, %q)", action, resource)
	}
}
