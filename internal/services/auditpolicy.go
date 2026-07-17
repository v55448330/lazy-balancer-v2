package services

type AuditPolicy int

const (
	AuditPolicySkip AuditPolicy = iota
	AuditPolicyGeneric
	AuditPolicyExplicit
)

var auditRoutePolicies = map[string]AuditPolicy{
	"POST /api/v1/auth/login":                   AuditPolicyExplicit,
	"POST /api/v1/auth/logout":                  AuditPolicyExplicit,
	"POST /api/v1/users":                        AuditPolicyExplicit,
	"PUT /api/v1/users/:id":                     AuditPolicyExplicit,
	"PUT /api/v1/users/:id/status":              AuditPolicyExplicit,
	"POST /api/v1/users/:id/reset-password":     AuditPolicyExplicit,
	"DELETE /api/v1/users/:id":                  AuditPolicyExplicit,
	"PATCH /api/v1/api-keys/:id/status":         AuditPolicyExplicit,
	"PATCH /api/v1/users/me/api-keys/:id":       AuditPolicyExplicit,
	"PUT /api/v1/ca-providers/:id":              AuditPolicyExplicit,
	"POST /api/v1/ca-providers/:id/test":        AuditPolicyExplicit,
	"PUT /api/v1/nodes/:id/approve":             AuditPolicyExplicit,
	"PUT /api/v1/nodes/:id/reject":              AuditPolicyExplicit,
	"DELETE /api/v1/nodes/:id":                  AuditPolicyExplicit,
	"POST /api/v1/config/preview":               AuditPolicySkip,
	"PUT /api/v1/config":                        AuditPolicyExplicit,
	"POST /api/v1/config/reload":                AuditPolicyGeneric,
	"POST /api/v1/config/validate":              AuditPolicySkip,
	"POST /api/v1/sync/pull":                    AuditPolicyExplicit,
	"PUT /api/v1/users/me":                      AuditPolicyExplicit,
	"POST /api/v1/rules/cert-info":              AuditPolicySkip,
	"POST /api/v1/rules":                        AuditPolicyExplicit,
	"PUT /api/v1/rules/:caddy_id":               AuditPolicyExplicit,
	"DELETE /api/v1/rules/:caddy_id":            AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/enable":       AuditPolicyExplicit,
	"PUT /api/v1/rules/:caddy_id/disable":       AuditPolicyExplicit,
	"POST /api/v1/rules/:caddy_id/duplicate":    AuditPolicyExplicit,
	"POST /api/v1/certificate-configs":          AuditPolicyExplicit,
	"PUT /api/v1/certificate-configs/:id":       AuditPolicyExplicit,
	"DELETE /api/v1/certificate-configs/:id":    AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/test":     AuditPolicyExplicit,
	"POST /api/v1/certificate-configs/:id/test": AuditPolicyExplicit,
	"PUT /api/v1/caddy/config":                  AuditPolicyGeneric,
	"POST /api/v1/caddy/start":                  AuditPolicyGeneric,
	"POST /api/v1/caddy/stop":                   AuditPolicyGeneric,
	"POST /api/v1/caddy/restart":                AuditPolicyGeneric,
	"POST /api/v1/nodes/register":               AuditPolicyExplicit,
	"POST /api/v1/nodes/:id/heartbeat":          AuditPolicySkip,
	"PUT /api/v1/nodes/:id":                     AuditPolicyExplicit,
	"POST /api/v1/certificates/issue":           AuditPolicyExplicit,
	"POST /api/v1/certificates/parse":           AuditPolicySkip,
	"POST /api/v1/certificates/jobs/:id/retry":  AuditPolicyExplicit,
	"DELETE /api/v1/certificates/jobs/:id":      AuditPolicyExplicit,
}

func ClassifyAuditRoute(method, path string) AuditPolicy {
	if policy, ok := auditRoutePolicies[method+" "+path]; ok {
		return policy
	}
	return AuditPolicySkip
}

func HasExplicitAuditEvent(method, path string) bool {
	switch method + " " + path {
	case "POST /api/v1/auth/login",
		"POST /api/v1/auth/logout",
		"POST /api/v1/users",
		"PUT /api/v1/users/:id",
		"PUT /api/v1/users/:id/status",
		"POST /api/v1/users/:id/reset-password",
		"DELETE /api/v1/users/:id",
		"PUT /api/v1/users/me",
		"PATCH /api/v1/api-keys/:id/status",
		"PATCH /api/v1/users/me/api-keys/:id",
		"POST /api/v1/nodes/register",
		"PUT /api/v1/nodes/:id/approve",
		"PUT /api/v1/nodes/:id/reject",
		"DELETE /api/v1/nodes/:id",
		"PUT /api/v1/nodes/:id",
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
		"POST /api/v1/sync/pull",
		"PUT /api/v1/config":
		return true
	default:
		return false
	}
}
