package services

import (
	"reflect"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// 共享映射（IPC 批摄取与 live 尾读命中同一份只读快照）发布前必须完成全部
// 策略级懒解析：两个通道的锁互不相交，若把解析留到发布后由各通道「首次
// 命中」再做，读者可能看见「已标记解析 / 值未填」的中间态——事件被算到
// 另一条策略或没有策略。本用例把「发布点之前预热当前已知懒解析字段」钉在
// loader 上：删掉预热循环即红。新增懒字段的漏预热由下方反射守卫结构性拦截
// （注释承诺不再依赖维护者自觉）。
func TestSecurityEventsLoadMappings_prewarmsPolicyAnalysisBeforePublish(t *testing.T) {
	_, database := newClusterTestService(t)
	resetSecurityEventsMappingsCacheForTest()
	t.Cleanup(resetSecurityEventsMappingsCacheForTest)

	// 策略覆盖全部懒解析面：CRS 组号、自定义规则 id 数组、遗留黑名单、内联 ACL。
	if _, err := database.Exec(`INSERT INTO security_policies
		(id,name,enabled,custom_rules,crs_rule_groups,ip_blacklist,ip_acl_enabled,ip_acl_mode,ip_acl_list)
		VALUES (1,'policy-warm',1,'[5]','["942100","913100"]','["10.0.0.0/8"]',1,'deny','["1.2.3.0/24"]')`); err != nil {
		t.Fatalf("insert policy: %v", err)
	}

	_, _, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	p := policyByID[1]
	if p == nil {
		t.Fatal("policy 1 missing from published mapping")
	}
	if !p.CRSRuleGroupsParsed || p.CRSRuleGroupsSet == nil {
		t.Fatalf("CRSRuleGroupsParsed=%v set=%v, want true/非空 —— CRS 组解析必须早于映射发布",
			p.CRSRuleGroupsParsed, p.CRSRuleGroupsSet)
	}
	if !p.CustomRulesCached {
		t.Fatal("CustomRulesCached=false —— 自定义规则解析必须早于映射发布")
	}
	if !p.CustomRuleIDsParsed {
		t.Fatal("CustomRuleIDsParsed=false —— 自定义规则发射 id 集必须早于映射发布")
	}
	if !p.ACLIPIndex.Built || !p.ACLIPIndex.OK || !p.ACLIPIndex.NonEmpty {
		t.Fatalf("ACLIPIndex built/ok/nonEmpty=%v/%v/%v, want true/true/true —— ACL 名单快照必须早于映射发布",
			p.ACLIPIndex.Built, p.ACLIPIndex.OK, p.ACLIPIndex.NonEmpty)
	}
	if !p.IPBlacklistIPIndex.Built || !p.IPBlacklistIPIndex.OK || p.IPBlacklistIPIndex.Entries == 0 {
		t.Fatalf("IPBlacklistIPIndex built/ok/entries=%v/%v/%d, want true/true/>0 —— 黑名单快照必须早于映射发布",
			p.IPBlacklistIPIndex.Built, p.IPBlacklistIPIndex.OK, p.IPBlacklistIPIndex.Entries)
	}
}

// 反射守卫：models.SecurityPolicy 的懒解析标记字段全集必须与本清单逐字
// 相等——新增懒字段（*Parsed/*Cached 布尔或 *IPIndex 快照）而不同步预热
// 与本清单即红。与上方行为钉互补：行为钉证明「已知字段已预热」，本守卫
// 证明「没有未知的漏网字段」。
func TestSecurityEventsLoadMappings_lazyFieldInventoryMatchesPrewarmSurface(t *testing.T) {
	want := map[string]bool{
		"CRSRuleGroupsParsed": true,
		"CustomRulesCached":   true,
		"CustomRuleIDsParsed": true,
		"ACLIPIndex":          true,
		"IPBlacklistIPIndex":  true,
	}
	got := map[string]bool{}
	typ := reflect.TypeOf(models.SecurityPolicy{})
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if strings.HasSuffix(name, "Parsed") || strings.HasSuffix(name, "Cached") || strings.HasSuffix(name, "IPIndex") {
			got[name] = true
		}
	}
	if len(got) != len(want) {
		t.Fatalf("懒解析字段清单漂移: got=%v want=%v —— 新增懒字段必须同步 loader 预热循环与本清单", got, want)
	}
	for name := range want {
		if !got[name] {
			t.Fatalf("懒解析字段 %s 消失/改名: got=%v —— 预热面与守卫清单必须同步", name, got)
		}
	}
}
