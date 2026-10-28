package services

import "testing"

// 原 TestExplicitAuditRoutesAreHandledByHandlers（手抄
// 43 条 Explicit 路由子集断言 HasExplicitAuditEvent）已删除——后
// HasExplicitAuditEvent 从 auditRoutePolicies 派生，子集断言退化为恒真同义
// 反复（对新增路由静默失效）。覆盖由更强钉吸收：audit_action_mapping_test.go
// 的 TestAuditExplicitHandlersRecord（全量遍历+AST handler 审计调用扫描）、
// TestAuditExplicitRoutesMappingEmpty（全量 Explicit 映射空钉）、
// TestAuditPolicyListsEqual（派生活性钉）。

// TestClassifyAuditRouteMatrix 仅是既有映射的变更探测器（非独立行为断言）；
// 新增路由与真实行为覆盖见 middleware/audit_routes_test.go 和上述映射门。

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
		// 任务触发：升 Explicit——handler 按
		// TaskTriggerSelfRecordsAudit 分流补记（非自记族）/跳过（自记族）。
		{"POST", "/api/v1/system/tasks/:id/trigger", AuditPolicyExplicit},
		// 三库手动更新：审计由任务体 defer 单记（2026-09-29 裁定+）。
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

// POST /settings/oidc/test 是读探测语义(发现+JWKS 可达性,不落库
// 配置)——只读 API Key 应可调用,须经 readOnlyWriteRoutes 放行。
func TestIsReadOnlyWriteRoute_allowsOIDCDiscoveryProbe(t *testing.T) {
	if !IsReadOnlyWriteRoute("POST", "/api/v1/settings/oidc/test") {
		t.Fatal("IsReadOnlyWriteRoute(POST /api/v1/settings/oidc/test)=false, want true (读探测语义)")
	}
}

// 证书配置两条 test 路由移出只读白名单
// ——dnsproviders.Validate 会真实 Present+CleanUp DNS TXT（非只读探测）。
// CA 提供商 test 同步移出——provider == ZeroSSL 且
// 缺 EAB 时 TestCAProviderWithContext → AutoProvisionZeroSSLEAB 会申请 EAB 并
// UPDATE ca_providers.credentials（caproviders.go:342-344），不是纯探测；
// 只读 API Key/从节点/MFA step-up 三守卫必须恢复完整写权限校验。
func TestIsReadOnlyWriteRoute_writeSideEffectTestsAreNotProbes(t *testing.T) {
	for _, path := range []string{"/api/v1/certificate-configs/:id/test", "/api/v1/certificate-configs/test"} {
		if IsReadOnlyWriteRoute("POST", path) {
			t.Fatalf("IsReadOnlyWriteRoute(POST %s)=true, want false（真实 DNS 写副作用，三守卫须恢复）", path)
		}
	}
	if IsReadOnlyWriteRoute("POST", "/api/v1/ca-providers/:id/test") {
		t.Fatal("IsReadOnlyWriteRoute(POST /api/v1/ca-providers/:id/test)=true, want false（ZeroSSL 缺 EAB 时真实写 ca_providers.credentials，三守卫须恢复）")
	}
}

func TestAuditResultText_translates_partial_result(t *testing.T) {
	if got := AuditResultText("partial"); got != "部分成功" {
		t.Fatalf("AuditResultText(partial)=%q, want 部分成功", got)
	}
}

// 16 个可手动触发族的自记分流必须与现实一致——6 族
// 任务体自记审计（handler 跳过复记），10 族任务体零审计（handler 补记）。
// 集合漂移（新增可触发族未评估/自记机制撤销）会在这里当场失败。
func TestTaskTriggerSelfRecordsAudit_familySplit(t *testing.T) {
	// Given 6 个自记族（任务体 defer/执行器/载入审计，operator 经 RunContext 归人）
	selfRecorded := []string{"threat", "crs", "ip2region", "crawlerbot-update", "auto-backup", "startup:config-load"}
	for _, id := range selfRecorded {
		if !TaskTriggerSelfRecordsAudit(id) {
			t.Fatalf("自记族 %s 应报告 true（handler 复记会双审计，违反单记口径）", id)
		}
	}
	// When/Then 10 个非自记族报告 false（handler 显式补记「触发/任务监控」）
	handlerRecorded := []string{"config-watchdog", "log-cleanup", "audit-retention", "security-events-retention", "metrics-orphan-cleanup", "cert-renewal-scan", "cert-reconcile", "cert-manual-poll", "cert-waiting-ca", "autoban"}
	for _, id := range handlerRecorded {
		if TaskTriggerSelfRecordsAudit(id) {
			t.Fatalf("非自记族 %s 应报告 false（任务体零审计，handler 不补记则手动触发无痕）", id)
		}
	}
	// 未知族按非自记处理（handler 补记——宁多记不遗漏）
	if TaskTriggerSelfRecordsAudit("no-such-task") {
		t.Fatal("未知族应报告 false")
	}

	// 反向对表：任务引擎注册的**全部可手动触发族**必须落在上面两张清单之一，
	// 且生产分流结果与所在清单一一致。只在测试里手抄两张清单时，新增可触发族
	// 不评估（既不进自记集也不进补记集）不会红；从注册表反查才能真正钉住。
	in := func(list []string, id string) bool {
		for _, v := range list {
			if v == id {
				return true
			}
		}
		return false
	}
	te := newWireTestEngine(t)
	checked := 0
	for _, meta := range te.DescribeAll() {
		if !meta.CanTrigger {
			continue
		}
		checked++
		self := in(selfRecorded, meta.ID)
		switch {
		case self && in(handlerRecorded, meta.ID):
			t.Errorf("任务族 %s 同时出现在自记/补记清单——分流二义", meta.ID)
		case !self && !in(handlerRecorded, meta.ID):
			t.Errorf("可手动触发族 %s 未登记分流清单（任务体是否自记审计？新族必须评估并加入其一）", meta.ID)
		case TaskTriggerSelfRecordsAudit(meta.ID) != self:
			t.Errorf("任务族 %s 的生产分流=%v 与清单=%v 不一致", meta.ID, TaskTriggerSelfRecordsAudit(meta.ID), self)
		}
	}
	if checked < 10 {
		t.Fatalf("反向对表仅覆盖 %d 个可触发族（注册表未装载完整？），期望 ≥10", checked)
	}
}
