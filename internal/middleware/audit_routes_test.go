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
		// v2.1.8 MFA：setup/verify-step/recovery-codes 为读形态或内部动作
		//（不产生审计；handler 对失败已按认证拒绝/错误路径细分记录）。
		"POST /api/v1/auth/mfa/setup":          {},
		"POST /api/v1/auth/mfa/verify-step":    {},
		"POST /api/v1/auth/mfa/recovery-codes": {},
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
