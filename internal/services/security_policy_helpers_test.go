package services

// GetSecurityPolicyForRule 的 ORDER BY policy_id DESC
// 口径是 v2.2.0 前的单策略语义（与多策略「首绑定=最小 id」相反），生产面零
// 调用（生成路径走 loadSecurityPolicyContext / GetSecurityPoliciesForRule），
// 从 services/security.go 退役为本测试专用 helper——SQL 原样保留，既有调用方
// 测试零行为变化。

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// GetSecurityPolicyForRule 返回 v2.2.0 单策略语义下的规则生效策略：最高
// policy_id 绑定生效，最高绑定指向禁用策略时返回 nil（不回退次高）。
// 仅限测试使用；生产读路径一律用 GetSecurityPoliciesForRule（绑定 rank ASC，
// policy_id 兜序全量列表）。
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

// Given 安全策略整行列清单（securityPolicyRowColumns）。
// When 核对人机/CC 列的 COALESCE 回退值来源。
// Then 六个治理默认值必须绑成 db 包选择器表达式——私抄字面量（slider/30/
// 40/10/70/5）会在 DDL DEFAULT/启动回填调整后与读侧静默分叉（策略行扫描
// 是本面板唯一读形态，分叉后 UI 与引擎看到两套默认值）。
func TestSecurityPolicyRowColumns_bindsGovernedDefaults(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "security.go", nil, 0)
	if err != nil {
		t.Fatalf("parse security.go: %v", err)
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		declared := false
		for _, name := range spec.Names {
			if name.Name == "securityPolicyRowColumns" {
				declared = true
			}
		}
		if !declared {
			return true
		}
		ast.Inspect(spec, func(inner ast.Node) bool {
			if sel, ok := inner.(*ast.SelectorExpr); ok {
				if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "db" {
					seen[sel.Sel.Name] = true
				}
			}
			return true
		})
		return false
	})
	for _, want := range []string{
		"DefaultHumanVerifyType", "DefaultHumanVerifyTTL",
		"DefaultCCRPSLimit", "DefaultCCRPSWindow",
		"DefaultCC4xxRatio", "DefaultCCSessionUAThreshold",
	} {
		if !seen[want] {
			t.Fatalf("securityPolicyRowColumns 未绑定 db.%s（COALESCE 回退值私抄为字面量）", want)
		}
	}
	// 运行期形态仍须与常量同值（拼接/引号位置正确）。
	for _, want := range []string{
		"'" + db.DefaultHumanVerifyType + "'",
		strconv.Itoa(db.DefaultHumanVerifyTTL),
		strconv.Itoa(db.DefaultCCRPSLimit),
		strconv.Itoa(db.DefaultCCRPSWindow),
		strconv.Itoa(db.DefaultCC4xxRatio),
		strconv.Itoa(db.DefaultCCSessionUAThreshold),
	} {
		if !strings.Contains(securityPolicyRowColumns, want) {
			t.Fatalf("securityPolicyRowColumns 缺默认值形态 %q: %s", want, securityPolicyRowColumns)
		}
	}
}
