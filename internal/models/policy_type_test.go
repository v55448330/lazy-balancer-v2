package models

import (
	"encoding/json"
	"testing"
)

// 策略实体单职化（2026-09-20 用户裁定）：security_policies.policy_type ∈
// stage0（信任名单独立策略类型）/ stage1（IP 访问控制+地域拦截）/ stage2（限流）/
// stage3（WAF）/ mixed（存量混合兼容）。InferPolicyType 按内容特征推断，是
// backfill、写侧缺省提交、旧快照/旧备份导入的共同单一事实源。特征分组：
// g0=信任名单（启用且非空），g1=IP ACL/黑白名单/GeoIP，g2=限流，
// g3=WAF（mode≠off 或自定义规则引用非空）；恰好一组→对应类型，多组→mixed，
// 零组→stage3（WAF 是安全策略的默认心智，空策略归此）。
func TestInferPolicyType(t *testing.T) {
	cases := []struct {
		name   string
		policy SecurityPolicy
		want   string
	}{
		{"blocking only", SecurityPolicy{Mode: "blocking"}, PolicyTypeStage3},
		{"detection with custom rules", SecurityPolicy{Mode: "detection", CustomRules: json.RawMessage(`[{"id":1,"enabled":true}]`)}, PolicyTypeStage3},
		{"custom_only with rule refs", SecurityPolicy{Mode: "custom_only", CustomRules: json.RawMessage(`[3]`)}, PolicyTypeStage3},
		{"acl deny", SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`}, PolicyTypeStage1},
		{"acl refs only", SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "allow", IPACLListRefs: `[2]`}, PolicyTypeStage1},
		{"trust list", SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}, PolicyTypeStage0},
		{"trust refs only", SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelistRefs: `[4]`}, PolicyTypeStage0},
		{"legacy blacklist", SecurityPolicy{Mode: "off", IPBlacklist: json.RawMessage(`["1.2.3.4"]`)}, PolicyTypeStage1},
		{"geoip", SecurityPolicy{Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`)}, PolicyTypeStage1},
		{"rate limit", SecurityPolicy{Mode: "off", RateLimitEnabled: true, RateLimitRPS: 100}, PolicyTypeStage2},
		{"rate limit enabled but zero rps", SecurityPolicy{Mode: "off", RateLimitEnabled: true, RateLimitRPS: 0}, PolicyTypeStage3},
		{"blocking + rate limit", SecurityPolicy{Mode: "blocking", RateLimitEnabled: true, RateLimitRPS: 100}, PolicyTypeMixed},
		{"acl + geoip same stage", SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.0/8"]`, GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`)}, PolicyTypeStage1},
		{"detection + geoip", SecurityPolicy{Mode: "detection", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`)}, PolicyTypeMixed},
		{"empty policy", SecurityPolicy{Mode: "off"}, PolicyTypeStage3},
		{"acl disabled with retained list", SecurityPolicy{Mode: "off", IPACLEnabled: false, IPACLList: `["10.0.0.0/8"]`}, PolicyTypeStage3},
		{"geoip off with retained countries", SecurityPolicy{Mode: "off", GeoIPMode: "off", GeoIPCountries: json.RawMessage(`["海外"]`)}, PolicyTypeStage3},
		{"trust only is stage0", SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}, PolicyTypeStage0},
		{"trust refs only is stage0", SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelistRefs: `[2]`}, PolicyTypeStage0},
		{"trust + acl is mixed", SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`), IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`}, PolicyTypeMixed},
		{"trust + waf is mixed", SecurityPolicy{Mode: "blocking", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}, PolicyTypeMixed},
		{"trust disabled with retained list is not stage0", SecurityPolicy{Mode: "off", IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}, PolicyTypeStage3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := InferPolicyType(&tc.policy); got != tc.want {
				t.Fatalf("InferPolicyType=%q, want %q", got, tc.want)
			}
		})
	}
}
