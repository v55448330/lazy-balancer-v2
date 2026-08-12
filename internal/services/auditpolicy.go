package services

type AuditPolicy int

const (
	AuditPolicySkip AuditPolicy = iota
	AuditPolicyGeneric
	AuditPolicyExplicit
)

var auditRoutePolicies = map[string]AuditPolicy{
	"POST /api/v1/auth/login":                             AuditPolicyExplicit,
	"POST /api/v1/auth/ticket-login":                      AuditPolicyExplicit,
	"POST /api/v1/auth/logout":                            AuditPolicyExplicit,
	"POST /api/v1/auth/setup":                             AuditPolicyExplicit,
	"POST /api/v1/mcp":                                    AuditPolicySkip,
	"POST /api/v1/users":                                  AuditPolicyExplicit,
	"PUT /api/v1/users/:id":                               AuditPolicyExplicit,
	"PUT /api/v1/users/:id/status":                        AuditPolicyExplicit,
	"POST /api/v1/users/:id/reset-password":               AuditPolicyExplicit,
	"DELETE /api/v1/users/:id":                            AuditPolicyExplicit,
	"PATCH /api/v1/users/me":                              AuditPolicyExplicit,
	"POST /api/v1/users/me/api-keys":                      AuditPolicyExplicit,
	"PATCH /api/v1/users/me/api-keys/:id":                 AuditPolicyExplicit,
	"DELETE /api/v1/users/me/api-keys/:id":                AuditPolicyExplicit,
	"POST /api/v1/api-keys":                               AuditPolicyExplicit,
	"PATCH /api/v1/api-keys/:id/status":                   AuditPolicyExplicit,
	"DELETE /api/v1/api-keys/:id":                         AuditPolicyExplicit,
	"PUT /api/v1/ca-providers/:id":                        AuditPolicyExplicit,
	"POST /api/v1/ca-providers/:id/test":                  AuditPolicyExplicit,
	"POST /api/v1/cluster/register":                       AuditPolicyExplicit,
	"POST /api/v1/cluster/registration/confirm":           AuditPolicySkip,
	"POST /api/v1/cluster/register-tokens":                AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/approve":              AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/reject":               AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/:id/login-ticket":         AuditPolicyExplicit,
	"PUT /api/v1/cluster/nodes/:id/access-url":            AuditPolicyExplicit,
	"DELETE /api/v1/cluster/nodes/:id":                    AuditPolicyExplicit,
	"POST /api/v1/cluster/nodes/report":                   AuditPolicySkip,
	"POST /api/v1/cluster/mode":                           AuditPolicyExplicit,
	"POST /api/v1/cluster/promote":                        AuditPolicyExplicit,
	"POST /api/v1/cluster/sync/pull":                      AuditPolicyExplicit,
	"PUT /api/v1/cluster/settings":                        AuditPolicyExplicit,
	"POST /api/v1/config/preview":                         AuditPolicySkip,
	"POST /api/v1/config/import/validate":                 AuditPolicySkip,
	"PUT /api/v1/config":                                  AuditPolicyExplicit,
	"PUT /api/v1/admin-tls":                               AuditPolicyExplicit,
	"POST /api/v1/admin-tls/inspect":                      AuditPolicySkip,
	"POST /api/v1/system/restart":                         AuditPolicyGeneric,
	"POST /api/v1/config/reload":                          AuditPolicyGeneric,
	"POST /api/v1/config/validate":                        AuditPolicySkip,
	"POST /api/v1/rules/cert-info":                        AuditPolicySkip,
	"POST /api/v1/rules":                                  AuditPolicyExplicit,
	"PUT /api/v1/rules/:caddy_id":                         AuditPolicyExplicit,
	"DELETE /api/v1/rules/:caddy_id":                      AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/enable":                 AuditPolicyExplicit,
	"PUT /api/v1/rules/:caddy_id/disable":                 AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/duplicate":              AuditPolicyExplicit,
	"POST /api/v1/certificate-configs":                    AuditPolicyExplicit,
	"PUT /api/v1/certificate-configs/:id":                 AuditPolicyExplicit,
	"DELETE /api/v1/certificate-configs/:id":              AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/test":               AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/:id/test":           AuditPolicyExplicit,
	"PUT /api/v1/caddy/config":                            AuditPolicyExplicit,
	"POST /api/v1/config/import":                          AuditPolicyExplicit,
	"POST /api/v1/config/import/v1":                       AuditPolicyExplicit,
	"POST /api/v1/caddy/start":                            AuditPolicyGeneric,
	"POST /api/v1/caddy/stop":                             AuditPolicyGeneric,
	"POST /api/v1/caddy/restart":                          AuditPolicyGeneric,
	"POST /api/v1/certificates/issue":                     AuditPolicyExplicit,
	"POST /api/v1/certificates/parse":                     AuditPolicySkip,
	"POST /api/v1/certificates/jobs/current":              AuditPolicySkip,
	"POST /api/v1/certificates/jobs/:id/retry":            AuditPolicyExplicit,
	"DELETE /api/v1/certificates/jobs/:id":                AuditPolicyExplicit,
	"POST /api/v1/security/policies":                      AuditPolicyExplicit,
	"PUT /api/v1/security/policies/:id":                   AuditPolicyExplicit,
	"DELETE /api/v1/security/policies/:id":                AuditPolicyExplicit,
	"POST /api/v1/security/policies/:id/bind":             AuditPolicyExplicit,
	"DELETE /api/v1/security/policies/:id/bind/:caddy_id": AuditPolicyExplicit,
	"PUT /api/v1/security/crs/auto-update":                AuditPolicyExplicit,
	"POST /api/v1/security/crs/update":                    AuditPolicyExplicit,
	"PUT /api/v1/security/ip2region/auto-update":          AuditPolicyExplicit,
	"POST /api/v1/security/ip2region/update":              AuditPolicyExplicit,
	"POST /api/v1/security/custom-rules":                  AuditPolicyExplicit,
	"PUT /api/v1/security/custom-rules/:id":               AuditPolicyExplicit,
	"DELETE /api/v1/security/custom-rules/:id":            AuditPolicyExplicit,
	"POST /api/v1/security/block-pages":                   AuditPolicyExplicit,
	"PUT /api/v1/security/block-pages/:id":                AuditPolicyExplicit,
	"DELETE /api/v1/security/block-pages/:id":             AuditPolicyExplicit,
}

var readOnlyWriteRoutes = map[string]struct{}{
	"POST /api/v1/admin-tls/inspect":            {},
	"POST /api/v1/ca-providers/:id/test":        {},
	"POST /api/v1/certificate-configs/:id/test": {},
	"POST /api/v1/certificates/jobs/current":    {},
	"POST /api/v1/certificate-configs/test":     {},
	"POST /api/v1/certificates/parse":           {},
	"POST /api/v1/config/import/validate":       {},
	"POST /api/v1/config/preview":               {},
	"POST /api/v1/config/validate":              {},
	"POST /api/v1/mcp":                          {},
	"POST /api/v1/rules/cert-info":              {},
}

func ClassifyAuditRoute(method, path string) AuditPolicy {
	if policy, ok := auditRoutePolicies[method+" "+path]; ok {
		return policy
	}
	return AuditPolicySkip
}

func IsAuditedWriteRoute(method, path string) bool {
	_, exists := auditRoutePolicies[method+" "+path]
	return exists
}

func IsReadOnlyWriteRoute(method, path string) bool {
	_, exists := readOnlyWriteRoutes[method+" "+path]
	return exists
}

func HasExplicitAuditEvent(method, path string) bool {
	switch method + " " + path {
	case "POST /api/v1/auth/login",
		"POST /api/v1/auth/ticket-login",
		"POST /api/v1/auth/logout",
		"POST /api/v1/auth/setup",
		"POST /api/v1/users",
		"PUT /api/v1/users/:id",
		"PUT /api/v1/users/:id/status",
		"POST /api/v1/users/:id/reset-password",
		"DELETE /api/v1/users/:id",
		"PATCH /api/v1/users/me",
		"POST /api/v1/users/me/api-keys",
		"PATCH /api/v1/api-keys/:id/status",
		"PATCH /api/v1/users/me/api-keys/:id",
		"DELETE /api/v1/users/me/api-keys/:id",
		"POST /api/v1/api-keys",
		"DELETE /api/v1/api-keys/:id",
		"POST /api/v1/cluster/register",
		"POST /api/v1/cluster/register-tokens",
		"POST /api/v1/cluster/nodes/:id/approve",
		"POST /api/v1/cluster/nodes/:id/reject",
		"POST /api/v1/cluster/nodes/:id/login-ticket",
		"PUT /api/v1/cluster/nodes/:id/access-url",
		"DELETE /api/v1/cluster/nodes/:id",
		"POST /api/v1/cluster/mode",
		"POST /api/v1/cluster/promote",
		"POST /api/v1/cluster/sync/pull",
		"PUT /api/v1/cluster/settings",
		"POST /api/v1/rules",
		"PUT /api/v1/rules/:caddy_id",
		"DELETE /api/v1/rules/:caddy_id",
		"POST /api/v1/rules/:caddy_id/enable",
		"PUT /api/v1/rules/:caddy_id/disable",
		"POST /api/v1/rules/:caddy_id/duplicate",
		"POST /api/v1/certificate-configs",
		"PUT /api/v1/certificate-configs/:id",
		"DELETE /api/v1/certificate-configs/:id",
		"PUT /api/v1/ca-providers/:id",
		"POST /api/v1/ca-providers/:id/test",
		"POST /api/v1/certificate-configs/test",
		"POST /api/v1/certificate-configs/:id/test",
		"POST /api/v1/certificates/issue",
		"POST /api/v1/certificates/jobs/:id/retry",
		"DELETE /api/v1/certificates/jobs/:id",
		"PUT /api/v1/caddy/config",
		"POST /api/v1/config/import",
		"POST /api/v1/config/import/v1",
		"PUT /api/v1/config",
		"POST /api/v1/security/policies/:id/bind",
		"DELETE /api/v1/security/policies/:id/bind/:caddy_id",
		"PUT /api/v1/security/crs/auto-update",
		"POST /api/v1/security/crs/update",
		"PUT /api/v1/security/ip2region/auto-update",
		"POST /api/v1/security/ip2region/update",
		"POST /api/v1/security/custom-rules",
		"PUT /api/v1/security/custom-rules/:id",
		"DELETE /api/v1/security/custom-rules/:id",
		"POST /api/v1/security/block-pages",
		"PUT /api/v1/security/block-pages/:id",
		"DELETE /api/v1/security/block-pages/:id":
		return true
	default:
		return false
	}
}
