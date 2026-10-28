package services

// Caddy admin 端点原文只能留在服务端日志，
// 全员可见面（操作审计 detail / 后台重载失败横幅）必须剥离后再落盘。

import (
	"errors"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
)

const adminTransportErrorText = `Post "http://10.20.30.40:2019/load": dial tcp 10.20.30.40:2019: connect: connection refused`

func TestRedactCaddyAdminEndpoint_shapes(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  []string
		deny  []string
	}{
		{
			name:  "URL 与拨号地址",
			input: adminTransportErrorText,
			want:  []string{"<Caddy admin 端点>", "connection refused"},
			deny:  []string{"10.20.30.40", "2019"},
		},
		{
			name:  "IPv6 拨号地址",
			input: `Get "http://[::1]:2019/config/": dial tcp [::1]:2019: connect: connection refused`,
			want:  []string{"<Caddy admin 端点>"},
			deny:  []string{"[::1]"},
		},
		{
			name:  "域名解析失败",
			input: `Post "http://caddy.internal.example:2019/load": dial tcp: lookup caddy.internal.example: no such host`,
			want:  []string{"<Caddy admin 端点>"},
			deny:  []string{"caddy.internal.example"},
		},
		{
			name:  "无地址文本原样返回",
			input: "Caddy 配置应用失败（旧配置已保留）：配置被拒绝",
			want:  []string{"Caddy 配置应用失败（旧配置已保留）：配置被拒绝"},
			deny:  []string{"<Caddy admin 端点>"},
		},
	}
	for _, testCase := range cases {
		got := RedactCaddyAdminEndpoint(testCase.input)
		for _, want := range testCase.want {
			if !strings.Contains(got, want) {
				t.Errorf("%s: %q 缺 %q", testCase.name, got, want)
			}
		}
		for _, deny := range testCase.deny {
			if strings.Contains(got, deny) {
				t.Errorf("%s: %q 仍含 %q", testCase.name, got, deny)
			}
		}
	}
}

// 数据类更新（IP 库/CRS）触发的后台重载失败审计同样是全员可见面。
func TestRecordSystemReloadAudit_redactsAdminEndpoint(t *testing.T) {
	initializeRedactTestDB(t)

	recordSystemReloadAudit("crs_update", errors.New(adminTransportErrorText))

	var detail string
	if err := db.AuditDB.QueryRow(`SELECT detail FROM audit_log WHERE action='重载失败' ORDER BY id DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取重载失败审计: %v", err)
	}
	if strings.Contains(detail, "10.20.30.40") || strings.Contains(detail, "2019") {
		t.Fatalf("审计 detail=%q, want 不含 admin 端点地址/端口", detail)
	}
	if !strings.Contains(detail, "<Caddy admin 端点>") || !strings.Contains(detail, "connection refused") {
		t.Fatalf("审计 detail=%q, want 占位短语 + 保留底层原因", detail)
	}
}

// 后台数据类重载失败横幅（/caddy/status 的 background_apply_error）同样全员可见。
func TestBackgroundApplyFailureBanner_redactsAdminEndpoint(t *testing.T) {
	initializeRedactTestDB(t)
	ClearBackgroundApplyFailure(BackgroundApplyCertDeploy)
	t.Cleanup(func() { ClearBackgroundApplyFailure(BackgroundApplyCertDeploy) })

	RecordBackgroundApplyFailure(BackgroundApplyCertDeploy, errors.New(adminTransportErrorText))

	banner := BackgroundApplyFailureBanner()
	if banner == "" {
		t.Fatal("横幅为空，want 失败可见")
	}
	if strings.Contains(banner, "10.20.30.40") || strings.Contains(banner, "2019") {
		t.Fatalf("横幅=%q, want 不含 admin 端点地址/端口", banner)
	}
	if !strings.Contains(banner, "<Caddy admin 端点>") {
		t.Fatalf("横幅=%q, want 占位短语", banner)
	}
}

func initializeRedactTestDB(t *testing.T) {
	t.Helper()
	oldDB, oldMetricsDB, oldAuditDB := db.DB, db.MetricsDB, db.AuditDB
	if err := db.Initialize(t.TempDir()); err != nil {
		t.Fatalf("initialize test database: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		db.DB, db.MetricsDB, db.AuditDB = oldDB, oldMetricsDB, oldAuditDB
		db.SetDB(oldDB)
	})
}
