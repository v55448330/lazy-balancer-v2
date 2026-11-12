package services

import (
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 结果语义（2026-11-12 用户裁定）：信任记录与人机挑战都不是攻击证据——
// 它们必须从拦截/检测/大屏攻击口径中剔除；只有 rejected/blocked 才计攻击。
func TestSecurityEventCountsAsAttack_excludesTrustAndChallenged(t *testing.T) {
	cases := []struct {
		action, rule string
		want         bool
	}{
		{"blocked", "942100", true},
		{"logged", "942100", true}, // WAF 检测：计入攻击面（检测）
		{"logged", "12", false},    // 保留检测（信任）不是攻击
		{"trust", "12", false},     // 新信任动作整类排除
		{"challenged", "human_challenge", false},
		{"challenged", "human_pass", false},
		{"challenged", "human_failed", false},
		{"blocked", "human_failed", true}, // 历史行（升级前写入的 blocked）仍按攻击计
		{"logged", "810017", false},       // 爬虫放行族（段内：810000+policyID*16+engine）
	}
	for _, tc := range cases {
		if got := SecurityEventCountsAsAttack(tc.action, tc.rule); got != tc.want {
			t.Fatalf("CountsAsAttack(%q,%q)=%v，want %v", tc.action, tc.rule, got, tc.want)
		}
	}
	sql := AttackEventSQLPredicate("rule_triggered", "action")
	if !containsAllSubs(sql, "'trust'", "'challenged'") {
		t.Fatalf("SQL 攻击谓词必须整类排除 trust/challenged：%s", sql)
	}
}

func containsAllSubs(s string, subs ...string) bool {
	for _, sub := range subs {
		ok := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// 四阶段推断（2026-11-12）：人机/限流 → CC(stage2)；WAF → stage3；
// 跨阶段组合 → mixed；零能力 → 内容防护关闭态(stage3)。
func TestInferPolicyType_fourStage(t *testing.T) {
	cases := []struct {
		name string
		p    models.SecurityPolicy
		want string
	}{
		{"human only", models.SecurityPolicy{HumanVerifyMode: "auto"}, models.PolicyTypeStage2},
		{"rate only", models.SecurityPolicy{RateLimitEnabled: true, RateLimitRPS: 100}, models.PolicyTypeStage2},
		{"human + rate", models.SecurityPolicy{HumanVerifyMode: "force", RateLimitEnabled: true, RateLimitRPS: 100}, models.PolicyTypeStage2},
		{"waf only", models.SecurityPolicy{Mode: "blocking"}, models.PolicyTypeStage3},
		{"empty", models.SecurityPolicy{Mode: "off"}, models.PolicyTypeStage3},
		{"trust only", models.SecurityPolicy{IPWhitelistEnabled: true, IPWhitelist: []byte(`["10.0.0.1"]`)}, models.PolicyTypeStage0},
		{"human + acl", models.SecurityPolicy{HumanVerifyMode: "auto", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.0/8"]`}, models.PolicyTypeMixed},
		{"human + waf", models.SecurityPolicy{HumanVerifyMode: "auto", Mode: "blocking"}, models.PolicyTypeMixed},
	}
	for _, tc := range cases {
		if got := models.InferPolicyType(&tc.p); got != tc.want {
			t.Fatalf("%s: InferPolicyType=%q，want %q", tc.name, got, tc.want)
		}
	}
	if models.NormalizePolicyType(models.PolicyTypeStage4) != models.PolicyTypeStage3 {
		t.Fatal("旧编号 stage4 必须归一为 stage3")
	}
}

// CC 防护开关：cc_enabled 必须随配置下发（关闭时 auto 模式不再按阈值挑战）。
func TestBuildHumanHandlerConfig_carriesCCEnabled(t *testing.T) {
	setupGeoipConfigTestDB(t)
	humanSecretMu.Lock()
	humanSecretCache = ""
	humanSecretMu.Unlock()
	p := &models.SecurityPolicy{ID: 1, Name: "CC", Mode: "off", HumanVerifyMode: "auto",
		CCDetectEnabled: true, CCRPSLimit: 33, CCRPSWindow: 5, CC4xxRatio: 60, CCSessionUAThreshold: 4}
	cfg := buildHumanHandler("lb-cc", []*models.SecurityPolicy{p})
	if cfg["cc_enabled"] != true || cfg["cc_rps_limit"] != 33 {
		t.Fatalf("handler 配置必须携带 cc_enabled 与阈值：%v", cfg)
	}
	p.CCDetectEnabled = false
	cfg = buildHumanHandler("lb-cc", []*models.SecurityPolicy{p})
	if cfg["cc_enabled"] != false {
		t.Fatalf("未启用 CC 检测时 cc_enabled 必须为 false：%v", cfg)
	}
}
