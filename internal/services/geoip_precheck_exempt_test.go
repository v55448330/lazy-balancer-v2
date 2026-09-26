package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 第 58 轮（用户裁定）：ACL 白名单（allow 交集）命中的 IP 需豁免 GeoIP 地域
// 拦截——豁免 pass 规则（id:13, pass+nolog+skipAfter）必须位于 allow 拒绝规则
// （id:7）之后、GeoIP 逐策略链（800000+policyID）之前；纯 deny/黑名单规则不
// 受影响（显式 deny 仍先于豁免评估，命中照常拦截）。
func TestBuildIPPrecheckDirectives_allowExemptSkipsGeoChains(t *testing.T) {
	allowPolicy := &models.SecurityPolicy{
		ID:           21,
		PolicyType:   models.PolicyTypeStage1,
		Mode:         "off",
		IPACLEnabled: true,
		IPACLMode:    "allow",
		IPACLList:    `["203.0.113.10"]`,
	}
	geoPolicy := &models.SecurityPolicy{
		ID:             22,
		PolicyType:     models.PolicyTypeStage1,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{allowPolicy, geoPolicy}, 0))

	if !strings.Contains(directives, `@ipListFast `) || !strings.Contains(directives, `u-allow-exempt`) || !strings.Contains(directives, `"id:13,phase:1,pass,nolog,skipAfter:SECURITY_RULES_END"`) {
		t.Fatalf("directives must contain allow-membership geo exemption rule:\n%s", directives)
	}
	idxAllow := strings.Index(directives, `id:7,phase:1,deny`)
	idxExempt := strings.Index(directives, `id:13,phase:1,pass`)
	idxGeo := strings.Index(directives, `id:800022,phase:1,deny`)
	if idxAllow < 0 || idxExempt < 0 || idxGeo < 0 {
		t.Fatalf("missing anchor rules (allow=%d exempt=%d geo=%d):\n%s", idxAllow, idxExempt, idxGeo, directives)
	}
	if !(idxAllow < idxExempt && idxExempt < idxGeo) {
		t.Fatalf("exemption must sit between allow deny rule and geo chains (allow=%d exempt=%d geo=%d):\n%s", idxAllow, idxExempt, idxGeo, directives)
	}
}

// 回归形状：无 allow 名单（纯 deny/GeoIP）时不得发射豁免规则（避免恒真跳过
// 使 GeoIP 失效）。
func TestBuildIPPrecheckDirectives_noAllowListNoExempt(t *testing.T) {
	geoPolicy := &models.SecurityPolicy{
		ID:             22,
		PolicyType:     models.PolicyTypeStage1,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{geoPolicy}, 0))
	if strings.Contains(directives, "id:13,phase:1,pass") {
		t.Fatalf("exemption rule must not be emitted without allow lists:\n%s", directives)
	}
	if !strings.Contains(directives, `id:800022,phase:1,deny`) {
		t.Fatalf("geo chain must still be emitted:\n%s", directives)
	}
}

// 回归形状：deny 名单与 allow 名单并存（不同策略）时，deny 规则先于豁免评估——
// 显式 deny 命中照常拦截（deny+skipAfter 在豁免之前短路），豁免只对未被显式
// deny 的 allow 成员豁免 GeoIP。
func TestBuildIPPrecheckDirectives_denyPrecedesExempt(t *testing.T) {
	denyPolicy := &models.SecurityPolicy{
		ID:           23,
		PolicyType:   models.PolicyTypeStage1,
		Mode:         "off",
		IPACLEnabled: true,
		IPACLMode:    "deny",
		IPACLList:    `["198.51.100.9"]`,
	}
	allowPolicy := &models.SecurityPolicy{
		ID:           21,
		PolicyType:   models.PolicyTypeStage1,
		Mode:         "off",
		IPACLEnabled: true,
		IPACLMode:    "allow",
		IPACLList:    `["203.0.113.10"]`,
	}
	geoPolicy := &models.SecurityPolicy{
		ID:             22,
		PolicyType:     models.PolicyTypeStage1,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{denyPolicy, allowPolicy, geoPolicy}, 0))
	idxDeny := strings.Index(directives, `id:2,phase:1,deny`)
	idxExempt := strings.Index(directives, `id:13,phase:1,pass`)
	if idxDeny < 0 || idxExempt < 0 || idxDeny > idxExempt {
		t.Fatalf("deny rule must precede exemption (deny=%d exempt=%d):\n%s", idxDeny, idxExempt, directives)
	}
}

// R-10 引擎编译门禁：allow 豁免 + GeoIP 链共存的真实渲染产物必须被 coraza
// 编译接受（pass+skipAfter 与 deny+chain 混排形状）。
func TestEngineGate_allowExemptWithGeoChain(t *testing.T) {
	allowPolicy := &models.SecurityPolicy{
		ID:           21,
		PolicyType:   models.PolicyTypeStage1,
		Mode:         "off",
		IPACLEnabled: true,
		IPACLMode:    "allow",
		IPACLList:    `["203.0.113.10"]`,
	}
	geoPolicy := &models.SecurityPolicy{
		ID:             22,
		PolicyType:     models.PolicyTypeStage1,
		Mode:           "off",
		GeoIPMode:      "deny",
		GeoIPCountries: json.RawMessage(`["海外"]`),
	}
	compileForEngineGate(t, mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{allowPolicy, geoPolicy}, 0)))
}
