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
		"POST /api/v1/cluster/nodes/report":         {},
		"POST /api/v1/cluster/registration/confirm": {},
		"POST /api/v1/config/import/validate":       {},
		"POST /api/v1/config/preview":               {},
		"POST /api/v1/config/validate":              {},
		"POST /api/v1/mcp":                          {},
		"POST /api/v1/rules/cert-info":              {},
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
