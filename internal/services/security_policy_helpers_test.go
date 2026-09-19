package services

// SEC41-1（第 41 轮审计）：GetSecurityPolicyForRule 的 ORDER BY policy_id DESC
// 口径是 v2.2.0 前的单策略语义（与多策略「首绑定=最小 id」相反），生产面零
// 调用（生成路径走 loadSecurityPolicyContext / GetSecurityPoliciesForRule），
// 从 services/security.go 退役为本测试专用 helper——SQL 原样保留，既有调用方
// 测试零行为变化。

import (
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// GetSecurityPolicyForRule 返回 v2.2.0 单策略语义下的规则生效策略：最高
// policy_id 绑定生效，最高绑定指向禁用策略时返回 nil（不回退次高）。
// 仅限测试使用；生产读路径一律用 GetSecurityPoliciesForRule（policy_id ASC
// 全量列表）。
func GetSecurityPolicyForRule(ruleCaddyID string) *models.SecurityPolicy {
	if db.DB == nil {
		return nil
	}
	var policyID int
	err := db.DB.QueryRow("SELECT policy_id FROM security_policy_bindings WHERE rule_caddy_id=? ORDER BY policy_id DESC LIMIT 1", ruleCaddyID).Scan(&policyID)
	if err != nil {
		return nil
	}
	policy := scanSecurityPolicyByID(policyID)
	if policy == nil {
		return nil
	}
	// 引用的 IP 列表在此解析（单策略一次批量查询），发射端经 Merged* 消费。
	resolvePolicyIPListRefs([]*models.SecurityPolicy{policy}, nil)
	return policy
}
