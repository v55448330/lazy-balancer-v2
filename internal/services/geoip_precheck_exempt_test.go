package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 历史（用户裁定）：ACL 白名单（allow 交集）命中的 IP 需豁免 GeoIP 地域
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
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{allowPolicy, geoPolicy}, "lb_test"))

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
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{geoPolicy}, "lb_test"))
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
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{denyPolicy, allowPolicy, geoPolicy}, "lb_test"))
	idxDeny := strings.Index(directives, `id:1500`)
	idxExempt := strings.Index(directives, `id:13,phase:1,pass`)
	if idxDeny < 0 || idxExempt < 0 || idxDeny > idxExempt {
		t.Fatalf("deny rule must precede exemption (deny=%d exempt=%d):\n%s", idxDeny, idxExempt, directives)
	}
}

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
	compileForEngineGate(t, mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{allowPolicy, geoPolicy}, "lb_test")))
}

// deny 并集（id:2/4）须先于 allow 交集外拒绝（id:7）
// 发射——同在 deny 名单与 allow 交集外的 IP，事件归因应为「IP 黑名单拒绝」
// （deny 侧精确策略语义）而非「IP 白名单拒绝」。拦截结果不变（同 deny+status），
// 仅消息与归因策略修正。
func TestBuildIPPrecheckDirectives_denyPrecedesAllowDeny(t *testing.T) {
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
		// 遗留黑名单字段（非热路径）与 ACL 并存——夹具必须真实产出 id:4，
		// 否则下方「黑名单并集先于 allow 交集外拒绝」的顺序契约无法验证
		//（黑名单为空时 id:4 受内容门控不发射）。
		IPBlacklist: json.RawMessage(`["198.51.100.66"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{denyPolicy, allowPolicy}, "lb_test"))
	idxDeny := strings.Index(directives, `id:1500`)
	// 拆链后黑名单逐策略 id=1510000+policyID（allowPolicy ID 21 → 1510021）。
	idxBlacklist := strings.Index(directives, `id:1510021,phase:1,deny`)
	idxAllow := strings.Index(directives, `id:7,phase:1,deny`)
	if idxDeny < 0 || idxBlacklist < 0 || idxAllow < 0 {
		t.Fatalf("missing anchor rules (deny=%d blacklist=%d allow=%d):\n%s", idxDeny, idxBlacklist, idxAllow, directives)
	}
	if idxDeny > idxBlacklist || idxBlacklist > idxAllow {
		t.Fatalf("顺序须为 ACL deny 链(1500000+pid) → 黑名单链(1510000+pid) → allow 交集外拒绝(id:7)，got %d/%d/%d:\n%s",
			idxDeny, idxBlacklist, idxAllow, directives)
	}
}

// 阶段 1 抬码形态（denyStatus=481——id:2/4 带 status:481）
// 过引擎编译门禁——曾全部门禁调用恒传 0，仅编译期可见的形状错误单测拦不住。
func TestEngineGate_precheckDirectivesWithLiftedSyntheticStatus(t *testing.T) {
	// 拦截页逐策略归因（2026-11 用户裁定）：规则级 481/482 已删除，预检 deny
	// 链抬码唯一来源是属主策略合成码（483+i）。策略 7 获码 484 → 链首显式抬码。
	deny := &models.SecurityPolicy{ID: 7, Enabled: true, IPACLMode: "deny", IPACLEnabled: true, IPACLList: `["192.0.2.0/24"]`}
	policies := []*models.SecurityPolicy{deny}
	directives, err := buildIPPrecheckDirectives(policies, "lb_test", attribCtx(map[int]string{10: "<p>"}, map[int]int{7: 484}))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !strings.Contains(directives, "id:1500007,phase:1,deny,status:484") {
		t.Fatalf("逐策略 ACL 链应抬合成码 484\n%s", directives)
	}
	if strings.Contains(directives, "status:481") || strings.Contains(directives, "status:482") {
		t.Fatalf("阶段码 481/482 已删除，不得出现\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// 语义声明钉（白名单=全豁免）：allow 豁免规则（id:13 skipAfter）位于爬虫伪装
// deny（850000+policyID）之前——白名单成员被人工信任后不再评估爬虫伪装族
// （含他策略的伪装规则）。该顺序即「白名单全豁免」语义，注释与之同源；若
// 未来改为「只豁免 GeoIP」，必须把伪装块移到 id:13 之前并同步更新注释。
func TestBuildIPPrecheckDirectives_allowExemptPrecedesCrawlerSpoof(t *testing.T) {
	allowPolicy := &models.SecurityPolicy{
		ID:           21,
		PolicyType:   models.PolicyTypeStage1,
		Mode:         "off",
		IPACLEnabled: true,
		IPACLMode:    "allow",
		IPACLList:    `["203.0.113.10"]`,
	}
	crawlerPolicy := &models.SecurityPolicy{
		ID:                  24,
		PolicyType:          models.PolicyTypeStage1,
		Mode:                "blocking",
		Enabled:             true,
		GeoIPMode:           "deny",
		GeoIPCountries:      json.RawMessage(`["海外"]`),
		GeoIPCrawlerExempt:  true,
		GeoIPCrawlerEngines: json.RawMessage(`["googlebot"]`),
		IPWhitelistEnabled:  true,
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{allowPolicy, crawlerPolicy}, "lb_exempt_spoof"))

	idxExempt := strings.Index(directives, `id:13,phase:1,pass`)
	idxSpoof := strings.Index(directives, `id:850024,phase:1,deny`)
	if idxExempt < 0 || idxSpoof < 0 {
		t.Fatalf("missing anchors (exempt=%d spoof=%d):\n%s", idxExempt, idxSpoof, directives)
	}
	if idxExempt > idxSpoof {
		t.Fatalf("allow 豁免必须前置于爬虫伪装 deny（全豁免语义；exempt=%d spoof=%d）:\n%s", idxExempt, idxSpoof, directives)
	}
	compileForEngineGate(t, directives)
}
