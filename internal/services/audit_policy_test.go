package services

import "testing"

// LBS-B-R4（第 69 轮）：原 TestExplicitAuditRoutesAreHandledByHandlers（手抄
// 43 条 Explicit 路由子集断言 HasExplicitAuditEvent）已删除——F63-B5e2-4 后
// HasExplicitAuditEvent 从 auditRoutePolicies 派生，子集断言退化为恒真同义
// 反复（对新增路由静默失效）。覆盖由更强钉吸收：audit_action_mapping_test.go
// 的 TestAuditExplicitHandlersRecord（全量遍历+AST handler 审计调用扫描）、
// TestAuditExplicitRoutesMappingEmpty（全量 Explicit 映射空钉）、
// TestAuditPolicyListsEqual（派生活性钉）。

type auditRouteCase struct {
	method string
	path   string
	policy AuditPolicy
}

func TestClassifyAuditRouteMatrix(t *testing.T) {
	cases := []auditRouteCase{
		{"POST", "/api/v1/auth/login", AuditPolicyExplicit},
		{"POST", "/api/v1/auth/logout", AuditPolicyExplicit},
		{"POST", "/api/v1/users", AuditPolicyExplicit},
		{"PUT", "/api/v1/users/:id", AuditPolicyExplicit},
		{"PUT", "/api/v1/users/:id/status", AuditPolicyExplicit},
		{"POST", "/api/v1/users/:id/reset-password", AuditPolicyExplicit},
		{"DELETE", "/api/v1/users/:id", AuditPolicyExplicit},
		{"PUT", "/api/v1/ca-providers/:id", AuditPolicyExplicit},
		{"POST", "/api/v1/ca-providers/:id/test", AuditPolicyExplicit},
		{"POST", "/api/v1/cluster/register", AuditPolicyExplicit},
		{"POST", "/api/v1/cluster/nodes/:id/approve", AuditPolicyExplicit},
		{"DELETE", "/api/v1/cluster/nodes/:id", AuditPolicyExplicit},
		{"POST", "/api/v1/config/preview", AuditPolicySkip},
		{"PUT", "/api/v1/config", AuditPolicyExplicit},
		{"POST", "/api/v1/config/reload", AuditPolicyGeneric},
		{"POST", "/api/v1/config/validate", AuditPolicyExplicit},
		{"POST", "/api/v1/config/import/validate", AuditPolicySkip},
		{"POST", "/api/v1/admin-tls/inspect", AuditPolicySkip},
		{"POST", "/api/v1/cluster/sync/pull", AuditPolicyExplicit},
		{"PATCH", "/api/v1/users/me", AuditPolicyExplicit},
		{"POST", "/api/v1/rules/cert-info", AuditPolicySkip},
		{"POST", "/api/v1/rules", AuditPolicyExplicit},
		{"PUT", "/api/v1/rules/:caddy_id", AuditPolicyExplicit},
		{"DELETE", "/api/v1/rules/:caddy_id", AuditPolicyExplicit},
		{"POST", "/api/v1/rules/:caddy_id/enable", AuditPolicyExplicit},
		{"POST", "/api/v1/rules/:caddy_id/disable", AuditPolicyExplicit},
		{"POST", "/api/v1/rules/:caddy_id/duplicate", AuditPolicyExplicit},
		{"POST", "/api/v1/certificate-configs", AuditPolicyExplicit},
		{"PUT", "/api/v1/certificate-configs/:id", AuditPolicyExplicit},
		{"DELETE", "/api/v1/certificate-configs/:id", AuditPolicyExplicit},
		{"POST", "/api/v1/certificate-configs/test", AuditPolicyExplicit},
		{"POST", "/api/v1/certificate-configs/:id/test", AuditPolicyExplicit},
		{"PUT", "/api/v1/caddy/config", AuditPolicyExplicit},
		{"POST", "/api/v1/caddy/start", AuditPolicyGeneric},
		{"POST", "/api/v1/caddy/stop", AuditPolicyGeneric},
		{"POST", "/api/v1/caddy/restart", AuditPolicyGeneric},
		{"POST", "/api/v1/certificates/issue", AuditPolicyExplicit},
		{"POST", "/api/v1/certificates/parse", AuditPolicySkip},
		{"POST", "/api/v1/certificates/jobs/:id/retry", AuditPolicyExplicit},
		{"DELETE", "/api/v1/certificates/jobs/:id", AuditPolicyExplicit},
		{"POST", "/api/v1/security/policies/:id/bind", AuditPolicyExplicit},
		{"DELETE", "/api/v1/security/policies/:id/bind/:caddy_id", AuditPolicyExplicit},
		{"PUT", "/api/v1/security/crs/auto-update", AuditPolicyExplicit},
		// 任务触发（U1-P3-1，第 67 轮）：升 Explicit——handler 按
		// TaskTriggerSelfRecordsAudit 分流补记（非自记族）/跳过（自记族）。
		{"POST", "/api/v1/system/tasks/:id/trigger", AuditPolicyExplicit},
		// 三库手动更新：审计由任务体 defer 单记（2026-09-29 裁定+R62 U1-P3-2）。
		{"POST", "/api/v1/security/crs/update", AuditPolicySkip},
		{"POST", "/api/v1/security/custom-rules", AuditPolicyExplicit},
		{"PUT", "/api/v1/security/custom-rules/:id", AuditPolicyExplicit},
		{"DELETE", "/api/v1/security/custom-rules/:id", AuditPolicyExplicit},
		{"POST", "/api/v1/security/block-pages", AuditPolicyExplicit},
		{"PUT", "/api/v1/security/block-pages/:id", AuditPolicyExplicit},
		{"DELETE", "/api/v1/security/block-pages/:id", AuditPolicyExplicit},
	}
	seen := map[string]bool{}
	for _, tt := range cases {
		key := tt.method + " " + tt.path
		if seen[key] {
			t.Fatalf("duplicate route case: %s", key)
		}
		seen[key] = true
		if got := ClassifyAuditRoute(tt.method, tt.path); got != tt.policy {
			t.Fatalf("ClassifyAuditRoute(%s) = %v, want %v", key, got, tt.policy)
		}
	}
}

// R39-7(C3):POST /settings/oidc/test 是读探测语义(发现+JWKS 可达性,不落库
// 配置)——与 certificate-configs 两条 test、ca-providers/:id/test 同口径
// (2026-09-10 裁定先例),只读 API Key 应可调用,须经 readOnlyWriteRoutes 放行。
func TestIsReadOnlyWriteRoute_allowsOIDCDiscoveryProbe(t *testing.T) {
	if !IsReadOnlyWriteRoute("POST", "/api/v1/settings/oidc/test") {
		t.Fatal("IsReadOnlyWriteRoute(POST /api/v1/settings/oidc/test)=false, want true (读探测语义)")
	}
}

func TestAuditResultText_translates_partial_result(t *testing.T) {
	if got := AuditResultText("partial"); got != "部分成功" {
		t.Fatalf("AuditResultText(partial)=%q, want 部分成功", got)
	}
}

// U1-P3-1（第 67 轮）：12 个可手动触发族的自记分流必须与现实一致——5 族
// 任务体自记审计（handler 跳过复记），7 族任务体零审计（handler 补记）。
// 集合漂移（新增可触发族未评估/自记机制撤销）会在这里当场失败。
func TestTaskTriggerSelfRecordsAudit_familySplit(t *testing.T) {
	// Given 5 个自记族（任务体 defer/执行器/载入审计，operator 经 RunContext 归人）
	for _, id := range []string{"threat", "crs", "ip2region", "auto-backup", "startup:config-load"} {
		if !TaskTriggerSelfRecordsAudit(id) {
			t.Fatalf("自记族 %s 应报告 true（handler 复记会双审计，违反 U1-P3-2 单记裁定）", id)
		}
	}
	// When/Then 7 个非自记族报告 false（handler 显式补记「触发/任务监控」）
	for _, id := range []string{"log-cleanup", "audit-retention", "security-events-retention", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca"} {
		if TaskTriggerSelfRecordsAudit(id) {
			t.Fatalf("非自记族 %s 应报告 false（任务体零审计，handler 不补记则手动触发无痕）", id)
		}
	}
	// 未知族按非自记处理（handler 补记——宁多记不遗漏）
	if TaskTriggerSelfRecordsAudit("no-such-task") {
		t.Fatal("未知族应报告 false")
	}
}
