package middleware

import (
	"net/http"
	"testing"

	"lazy-balancer-v2/internal/services"
)

func TestSetupRouter_writeRoutesHaveExplicitAuditClassification(t *testing.T) {
	// Given
	router := newMiddlewareTestRouter(t)
	intentionalSkip := map[string]struct{}{
		"POST /api/v1/admin-tls/inspect":            {},
		"POST /api/v1/certificates/parse":           {},
		"POST /api/v1/certificates/jobs/current":    {},
		"POST /api/v1/cluster/nodes/report":         {},
		"POST /api/v1/cluster/registration/confirm": {},
		// 服务控制机器接口：handler 全路径（含失败）显式记录「服务控制」审计。
		"POST /api/v1/cluster/service-control": {},
		"POST /api/v1/config/import/validate":  {},
		"POST /api/v1/config/preview":          {},
		// R69 C-N3-c：/config/validate 已升为 Explicit（handler 记录校验三态）。
		"POST /api/v1/mcp":             {},
		"POST /api/v1/rules/cert-info": {},
		// v2.1.8 MFA：setup/verify-step 为读形态或内部动作（不产生审计；handler
		// 对失败已按认证拒绝/错误路径细分记录）。recovery-codes 已升为 Explicit
		//（S-8：handler 显式记录「生成/恢复码」），不再属有意跳过。
		"POST /api/v1/auth/mfa/setup":       {},
		"POST /api/v1/auth/mfa/verify-step": {},
		// 三库手动更新：审计由任务体 defer 单记（2026-09-29 用户裁定 + Round 62
		// U1-P3-2 收敛——handler 补记已撤、operator 经 RunContext 归人）。
		"POST /api/v1/security/crs/update":         {},
		"POST /api/v1/security/ip2region/update":   {},
		"POST /api/v1/security/threat-lib/update":  {},
		"POST /api/v1/security/crawler-lib/update": {},
		// 任务触发（U1-P3-1，第 67 轮）：已升 Explicit——12 个可触发族中 7 族
		// 任务体零审计，handler 对非自记族显式补记「触发/任务监控」（自记族
		// 跳过，保 U1-P3-2 单记裁定），不再属有意跳过。
	}
	writeMethods := map[string]struct{}{
		http.MethodPost: {}, http.MethodPut: {}, http.MethodPatch: {}, http.MethodDelete: {},
	}

	// When
	for _, route := range router.Routes() {
		if _, write := writeMethods[route.Method]; !write {
			continue
		}
		key := route.Method + " " + route.Path
		policy := services.ClassifyAuditRoute(route.Method, route.Path)

		// Then
		if _, skipped := intentionalSkip[key]; skipped {
			if policy != services.AuditPolicySkip || !services.IsAuditedWriteRoute(route.Method, route.Path) {
				t.Errorf("intentional audit skip is not explicitly classified: %s", key)
			}
			continue
		}
		if policy == services.AuditPolicySkip {
			t.Errorf("write route has default audit classification: %s", key)
		}
	}
}
