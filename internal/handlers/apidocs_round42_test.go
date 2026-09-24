package handlers

import (
	"strings"
	"testing"
)

// APIMCP42-1(第 42 轮审计):9 条幂等写端点的重试契约此前落入通用兜底
// 「不可安全重试」族——PUT 全量/部分更新与幂等追加(added=false)重复调用
// 保持相同目标状态,与 OIDC C7 同格「可安全重试」文案。
func TestAPIDocs_idempotentWriteRetryContracts(t *testing.T) {
	for _, key := range []string{
		"PUT /settings/auto-backup",
		"PUT /security/policies/:id",
		"PUT /security/rules/:caddy_id/policies",
		"PUT /security/custom-rules/:id",
		"PUT /security/block-pages/:id",
		"PUT /security/ip-lists/:id",
		"PUT /security/crs/auto-update",
		"PUT /security/ip2region/auto-update",
		"PUT /security/threat-lib/auto-update",
		"PUT /security/threat-lib/:id/flags",
		"PUT /security/crs/schedule",
		"PUT /security/ip2region/schedule",
		"PUT /security/threat-lib/schedule",
		"POST /security/ip-lists/:id/ips",
	} {
		route := routesEntry(t, key)
		description := operationDescription(route)
		if strings.Contains(description, "不可安全重试") || strings.Contains(description, "不可盲目安全重试") {
			t.Errorf("%s description=%q, want retryable contract(幂等写)", key, description)
		}
		if !strings.Contains(description, "重试") {
			t.Errorf("%s description=%q lacks retry contract", key, description)
		}
	}
}

// APIMCP50-P5-16(第 50 轮审计):三条 PATCH 路由此前被 operationDescription
// 方法门(仅 POST/PUT/DELETE)挡在重试契约之外,文档完全无重试语义——PATCH
// 语义化更新与 PUT 同格「可安全重试:相同请求重复调用保持相同目标状态」。
func TestAPIDocs_patchWriteRetryContracts(t *testing.T) {
	for _, key := range []string{
		"PATCH /users/me",
		"PATCH /users/me/api-keys/:id",
		"PATCH /api-keys/:id/status",
	} {
		route := routesEntry(t, key)
		description := operationDescription(route)
		if strings.Contains(description, "不可安全重试") || strings.Contains(description, "不可盲目安全重试") {
			t.Errorf("%s description=%q, want retryable contract(PATCH 幂等写)", key, description)
		}
		if !strings.Contains(description, "重试") {
			t.Errorf("%s description=%q lacks retry contract", key, description)
		}
	}
}

// APIMCP42-2(第 42 轮审计):创建特权 API Key(非只读或开启 MCP)经 MFA
// step-up 门,开启 mfa_write_guard 时 JWT 身份可能收到 428——两个创建端点的
// Errors 缺「428 mfa_step_up_required」,Description 未注明触发条件。
func TestAPIDocs_apiKeyCreationDocumentsMFAStepUp(t *testing.T) {
	for _, key := range []string{"POST /users/me/api-keys", "POST /api-keys"} {
		route := routesEntry(t, key)
		if !containsRouteError(route.Errors, "428") {
			t.Errorf("%s errors=%v, want 428 mfa_step_up_required", key, route.Errors)
		}
		if !strings.Contains(route.Description, "428") || !strings.Contains(route.Description, "特权") {
			t.Errorf("%s description=%q, want 特权 Key(非只读或 MCP)428 触发条件注明", key, route.Description)
		}
	}
}
