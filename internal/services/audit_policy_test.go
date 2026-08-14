package services

import "testing"

type auditRouteCase struct {
	method string
	path   string
	policy AuditPolicy
}

func TestExplicitAuditRoutesAreHandledByHandlers(t *testing.T) {
	explicitRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/api/v1/auth/login"},
		{"POST", "/api/v1/auth/logout"},
		{"POST", "/api/v1/users"},
		{"PUT", "/api/v1/users/:id"},
		{"PUT", "/api/v1/users/:id/status"},
		{"POST", "/api/v1/users/:id/reset-password"},
		{"DELETE", "/api/v1/users/:id"},
		{"POST", "/api/v1/cluster/register"},
		{"POST", "/api/v1/cluster/register-tokens"},
		{"POST", "/api/v1/cluster/nodes/:id/approve"},
		{"POST", "/api/v1/cluster/nodes/:id/reject"},
		{"DELETE", "/api/v1/cluster/nodes/:id"},
		{"POST", "/api/v1/cluster/mode"},
		{"POST", "/api/v1/cluster/promote"},
		{"POST", "/api/v1/rules"},
		{"PUT", "/api/v1/rules/:caddy_id"},
		{"DELETE", "/api/v1/rules/:caddy_id"},
		{"POST", "/api/v1/rules/:caddy_id/enable"},
		{"POST", "/api/v1/rules/:caddy_id/disable"},
		{"POST", "/api/v1/rules/:caddy_id/duplicate"},
		{"POST", "/api/v1/certificate-configs"},
		{"PUT", "/api/v1/certificate-configs/:id"},
		{"DELETE", "/api/v1/certificate-configs/:id"},
		{"POST", "/api/v1/certificates/issue"},
		{"POST", "/api/v1/certificates/jobs/:id/retry"},
		{"DELETE", "/api/v1/certificates/jobs/:id"},
		{"POST", "/api/v1/cluster/sync/pull"},
		{"PUT", "/api/v1/config"},
		{"POST", "/api/v1/security/policies/:id/bind"},
		{"DELETE", "/api/v1/security/policies/:id/bind/:caddy_id"},
		{"PUT", "/api/v1/security/crs/auto-update"},
		{"POST", "/api/v1/security/crs/update"},
		{"POST", "/api/v1/security/custom-rules"},
		{"PUT", "/api/v1/security/custom-rules/:id"},
		{"DELETE", "/api/v1/security/custom-rules/:id"},
		{"POST", "/api/v1/security/block-pages"},
		{"PUT", "/api/v1/security/block-pages/:id"},
		{"DELETE", "/api/v1/security/block-pages/:id"},
	}
	for _, tt := range explicitRoutes {
		if !HasExplicitAuditEvent(tt.method, tt.path) {
			t.Fatalf("explicit route not marked handler-owned: %s %s", tt.method, tt.path)
		}
	}
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
		{"POST", "/api/v1/config/validate", AuditPolicySkip},
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
		{"POST", "/api/v1/security/crs/update", AuditPolicyExplicit},
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

func TestAuditResultText_translates_partial_result(t *testing.T) {
	if got := AuditResultText("partial"); got != "部分成功" {
		t.Fatalf("AuditResultText(partial)=%q, want 部分成功", got)
	}
}
