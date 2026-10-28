package services

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	_ "unsafe"

	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
)

// 测试直接读取引擎条目解析计数，验证安全事件策略缓存没有重复解析。
//
//go:linkname wafiplistParseEntryCallsForTest lazy-balancer-v2/wafiplist.parseEntryCallsForTest
var wafiplistParseEntryCallsForTest atomic.Int64

// legacyIPInList 是改造前的逐条解析实现（TrimSpace → ParseIPEntry → Contains），
// 仅作等价性基准：生产路径改为「每 tick 解析一次 + 二分」，两者对全部名单
// 形态（重复/嵌套/空白/畸形/4in6/zone）必须逐点一致。
func legacyIPInList(ip string, list []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, perr := wafiplist.ParseIPEntry(entry); perr == nil && prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// legacyContainsRule 是改造前 id:2 / id:4 成员归因分支的等价基准（同源选择
// 合并集 → 回退 inline、原始条目数判「名单非空」、空 clientIP 直接认领）。
func legacyContainsRule(policy *models.SecurityPolicy, ruleTriggered, clientIP string) bool {
	switch ruleTriggered {
	case "4":
		var blacklist []string
		if err := json.Unmarshal(policy.IPBlacklist, &blacklist); err != nil {
			return false
		}
		if len(blacklist) == 0 {
			return false
		}
		return clientIP == "" || legacyIPInList(clientIP, blacklist)
	case "2":
		if !policy.IPACLEnabled {
			return false
		}
		aclList := policy.MergedACLList
		if len(aclList) == 0 {
			var inline []string
			if err := json.Unmarshal([]byte(policy.IPACLList), &inline); err != nil {
				return false
			}
			aclList = inline
		}
		nonEmpty := len(aclList) > 0 || ipListRefsNonEmpty(policy.IPACLListRefs)
		if policy.IPACLMode == "allow" {
			return !nonEmpty
		}
		if policy.IPACLMode != "deny" || !nonEmpty {
			return false
		}
		return clientIP == "" || legacyIPInList(clientIP, aclList)
	}
	panic("legacyContainsRule: unsupported rule " + ruleTriggered)
}

func TestSecurityEventsIPInPrefixSet_matchesLegacyScan(t *testing.T) {
	lists := map[string][]string{
		"empty":            {},
		"single ip":        {"203.0.113.7"},
		"cidr":             {"203.0.113.0/24"},
		"duplicates":       {"203.0.113.0/24", "203.0.113.0/24", "198.51.100.7", "198.51.100.7"},
		"nested":           {"10.0.0.0/8", "10.1.0.0/16", "10.1.2.3"},
		"siblings":         {"192.0.2.0/25", "192.0.2.128/25"},
		"host bits":        {"192.168.1.5/24"},
		"whitespace":       {"  198.51.100.0/24  ", "", "   ", "\t203.0.113.9\n"},
		"garbage":          {"not-an-ip", "198.51.100.0/33", "198.51.100.7/24"},
		"zone rejected":    {"fe80::1%eth0", "2001:db8::/32"},
		"4in6 entry":       {"::ffff:203.0.113.0/120", "::ffff:198.51.100.7"},
		"4in6 + v4 mix":    {"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		"v6":               {"2001:db8::/32", "2001:db8:1::/48"},
		"overlap families": {"0.0.0.0/0", "2001:db8::/32", "203.0.113.7"},
	}
	queries := []string{
		"203.0.113.7", "203.0.113.8", "198.51.100.7", "198.51.100.8",
		"10.1.2.3", "10.2.3.4", "192.0.2.1", "192.0.2.200",
		"192.168.1.5", "192.168.1.6", "1.2.3.4",
		"::ffff:203.0.113.7", "2001:db8::1", "2001:db8:1::1", "2001:db8:2::1",
		"", "not-an-ip", "fe80::1%eth0",
	}
	for name, list := range lists {
		t.Run(name, func(t *testing.T) {
			set := securityEventsIPPrefixSet(list)
			// 聚合不变量：升序、去重、不相交（二分检索前提）。
			for i := 1; i < len(set); i++ {
				prev := set[i-1]
				if prev.Addr().Compare(set[i].Addr()) >= 0 {
					t.Fatalf("prefix set not strictly ascending at %d: %v -> %v", i, prev, set[i])
				}
				if prev.Contains(set[i].Addr()) {
					t.Fatalf("prefix set not disjoint at %d: %v contains %v", i, prev, set[i])
				}
			}
			for _, ip := range queries {
				want := legacyIPInList(ip, list)
				if got := securityEventsIPInPrefixSet(ip, set); got != want {
					t.Fatalf("contains(%q) with list %v = %v, legacy = %v", ip, list, got, want)
				}
			}
		})
	}
}

func TestSecurityEventsPolicyIPIndex_cachedBuildSkipsParsing(t *testing.T) {
	p := models.SecurityPolicy{
		MergedACLList: []string{"203.0.113.0/24", "198.51.100.7"},
		IPACLList:     `[]`,
	}
	before := wafiplistParseEntryCallsForTest.Load()
	first := securityEventsPolicyACLIndex(&p)
	if got := wafiplistParseEntryCallsForTest.Load() - before; got != 2 {
		t.Fatalf("首次构建条目解析次数=%d, want 2", got)
	}
	if !first.Built || !first.OK || len(first.Prefixes) != 2 {
		t.Fatalf("首次构建索引无效: %+v", first)
	}

	before = wafiplistParseEntryCallsForTest.Load()
	second := securityEventsPolicyACLIndex(&p)
	if got := wafiplistParseEntryCallsForTest.Load() - before; got != 0 {
		t.Fatalf("第二次命中缓存仍解析条目 %d 次, want 0", got)
	}
	if second.Entries != first.Entries || len(second.Prefixes) != len(first.Prefixes) {
		t.Fatalf("缓存索引发生变化: first=%+v second=%+v", first, second)
	}
}

func TestSecurityEventsPolicyIPIndex_containsRuleEquivalent(t *testing.T) {
	type fixture struct {
		name    string
		policy  models.SecurityPolicy
		queries []string
	}
	base := func(mode string) models.SecurityPolicy {
		return models.SecurityPolicy{ID: 1, IPACLEnabled: true, IPACLMode: mode}
	}
	withMerged := func(mode string, merged []string, inline string) models.SecurityPolicy {
		p := base(mode)
		p.MergedACLList = merged
		p.IPACLList = inline
		return p
	}

	fixtures := []fixture{
		{
			name:    "deny merged cidr",
			policy:  withMerged("deny", []string{"203.0.113.0/24"}, `[]`),
			queries: []string{"203.0.113.7", "203.0.113.0", "203.0.114.7", ""},
		},
		{
			name:    "deny inline raw with dupes and garbage",
			policy:  withMerged("deny", nil, `["198.51.100.0/24","198.51.100.0/24","10.0.0.0/8","10.1.0.0/16","junk"]`),
			queries: []string{"198.51.100.9", "10.1.2.3", "10.2.3.4", "junk", ""},
		},
		{
			name:    "deny inline only garbage entries",
			policy:  withMerged("deny", nil, `["junk","10.0.0.0/33"]`),
			queries: []string{"10.0.0.1", ""},
		},
		{
			name:    "deny inline whitespace only",
			policy:  withMerged("deny", nil, `["","  "]`),
			queries: []string{"10.0.0.1", ""},
		},
		{
			name:    "deny inline malformed json",
			policy:  withMerged("deny", nil, `{"bad"`),
			queries: []string{"10.0.0.1", ""},
		},
		{
			name:    "deny empty",
			policy:  withMerged("deny", []string{}, `[]`),
			queries: []string{"10.0.0.1", ""},
		},
		{
			name:    "allow empty claims fail-closed surface",
			policy:  withMerged("allow", []string{}, `[]`),
			queries: []string{"10.0.0.1", ""},
		},
		{
			name:    "allow non-empty keeps legacy non-claim",
			policy:  withMerged("allow", []string{"203.0.113.0/24"}, `[]`),
			queries: []string{"203.0.113.7", ""},
		},
		{
			name: "refs only merged set",
			policy: func() models.SecurityPolicy {
				p := base("deny")
				p.MergedACLList = []string{"2001:db8::/32"}
				p.IPACLListRefs = `[7]`
				return p
			}(),
			queries: []string{"2001:db8::1", "2001:db9::1", ""},
		},
		{
			name:    "4in6 and zone entries",
			policy:  withMerged("deny", nil, `["::ffff:203.0.113.0/120","fe80::1%eth0","203.0.113.9"]`),
			queries: []string{"203.0.113.7", "::ffff:203.0.113.7", "fe80::1", ""},
		},
		{
			name: "acl disabled",
			policy: func() models.SecurityPolicy {
				p := withMerged("deny", []string{"203.0.113.0/24"}, `[]`)
				p.IPACLEnabled = false
				return p
			}(),
			queries: []string{"203.0.113.7", ""},
		},
	}
	for _, f := range fixtures {
		t.Run(f.name, func(t *testing.T) {
			for _, ip := range f.queries {
				want := legacyContainsRule(&f.policy, "2", ip)
				fresh := f.policy
				fresh.ACLIPIndex = models.SecurityPolicyIPListIndex{}
				if got := securityEventsPolicyContainsRuleWithExclusions(&fresh, "2", ip, securityEventsPolicyCRSExclusions{}); got != want {
					t.Fatalf("contains(id:2, %q)=%v, legacy=%v", ip, got, want)
				}
			}
			// 同一策略对象的缓存字段只构建一次，重复判定结果不变（复用安全）。
			first := securityEventsPolicyACLIndex(&f.policy)
			again := securityEventsPolicyACLIndex(&f.policy)
			if first.Entries != again.Entries || first.NonEmpty != again.NonEmpty || first.OK != again.OK || len(first.Prefixes) != len(again.Prefixes) {
				t.Fatalf("cached index mutated between lookups: %+v vs %+v", first, again)
			}
		})
	}

	blacklistFixtures := []struct {
		name     string
		raw      string
		queries  []string
		disabled bool
	}{
		{name: "raw cidr", raw: `["198.51.100.0/24"]`, queries: []string{"198.51.100.7", "198.51.101.7", ""}},
		{name: "raw mixed shapes", raw: `["10.0.0.0/8","10.0.0.0/8","10.1.0.0/16","junk","  192.0.2.5  "]`, queries: []string{"10.1.2.3", "192.0.2.5", "192.0.2.6", "junk", ""}},
		{name: "empty", raw: `[]`, queries: []string{"10.0.0.1", ""}},
		{name: "whitespace only", raw: `[""]`, queries: []string{"10.0.0.1", ""}},
		{name: "malformed json", raw: `["10.0.0.0/8"`, queries: []string{"10.0.0.1", ""}},
		{name: "4in6", raw: `["::ffff:198.51.100.0/120"]`, queries: []string{"198.51.100.7", "::ffff:198.51.100.7", ""}},
	}
	for _, f := range blacklistFixtures {
		t.Run("blacklist/"+f.name, func(t *testing.T) {
			p := models.SecurityPolicy{ID: 2, IPBlacklist: []byte(f.raw)}
			for _, ip := range f.queries {
				want := legacyContainsRule(&p, "4", ip)
				fresh := p
				fresh.IPBlacklistIPIndex = models.SecurityPolicyIPListIndex{}
				if got := securityEventsPolicyContainsRuleWithExclusions(&fresh, "4", ip, securityEventsPolicyCRSExclusions{}); got != want {
					t.Fatalf("contains(id:4, %q)=%v, legacy=%v (raw %s)", ip, got, want, f.raw)
				}
			}
		})
	}
}

// TestSecurityEventsIPFamilyEventSurface_usesIndexedCapability 钉住能力首选层
// 与逐事件实现的口径：名单非空判据取「聚合后发射面非空」（白名单/空白条目
// 不算），黑名单判据取原始条目数（含不可解析条目）。
func TestSecurityEventsIPFamilyEventSurface_usesIndexedCapability(t *testing.T) {
	cases := []struct {
		name   string
		policy models.SecurityPolicy
		rule   string
		action string
		want   bool
	}{
		{
			name: "deny acl cidr capable",
			policy: models.SecurityPolicy{
				ID: 1, IPACLEnabled: true, IPACLMode: "deny",
				IPACLList: `["203.0.113.0/24"]`,
			},
			rule: "2", action: "blocked", want: true,
		},
		{
			name: "deny acl whitespace entries not capable",
			policy: models.SecurityPolicy{
				ID: 1, IPACLEnabled: true, IPACLMode: "deny",
				IPACLList: `["","  "]`,
			},
			rule: "2", action: "blocked", want: false,
		},
		{
			name: "deny acl unparseable passthrough still capable",
			policy: models.SecurityPolicy{
				ID: 1, IPACLEnabled: true, IPACLMode: "deny",
				IPACLList: `["junk"]`,
			},
			rule: "2", action: "blocked", want: true,
		},
		{
			name: "legacy blacklist entries capable",
			policy: models.SecurityPolicy{
				ID: 1, IPBlacklist: []byte(`["junk"]`),
			},
			rule: "4", action: "blocked", want: true,
		},
		{
			name: "legacy blacklist malformed not capable",
			policy: models.SecurityPolicy{
				ID: 1, IPBlacklist: []byte(`["10.0.0.0/8"`),
			},
			rule: "4", action: "blocked", want: false,
		},
		{
			name: "rule 7 allow empty claims fail-closed surface",
			policy: models.SecurityPolicy{
				ID: 1, IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`,
			},
			rule: "7", action: "blocked", want: true,
		},
		{
			name: "logged non-empty trust whitelist capable",
			policy: models.SecurityPolicy{
				ID: 1, IPWhitelistEnabled: true,
				MergedWhitelist: []string{"203.0.113.0/24"},
			},
			rule: "4", action: "logged", want: true,
		},
		{
			name: "logged empty trust whitelist not capable despite refs",
			policy: models.SecurityPolicy{
				ID: 1, IPWhitelistEnabled: true,
				MergedWhitelist: []string{}, IPWhitelistRefs: `[7]`,
			},
			rule: "4", action: "logged", want: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityEventsIPFamilyEventSurface(&tc.policy, tc.action, tc.rule); got != tc.want {
				t.Fatalf("surface=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestSecurityEventsCRSExclusionIPIndex_groupTargetMatchesExplicitly(t *testing.T) {
	entries := ParseCRSExcludedRules(`[{"target":"42"}]`)
	if len(entries) != 1 {
		t.Fatalf("fixture entries=%d, want 1", len(entries))
	}
	indexed := securityEventsPolicyCRSExclusions{
		entries:   entries,
		entrySets: securityEventsBuildCRSExclusionIPIndex(entries, nil),
	}
	for _, tc := range []struct {
		rule string
		ip   string
		want bool
	}{
		{rule: "942100", ip: "203.0.113.7", want: true},
		{rule: "942550", ip: "", want: true},
		{rule: "943100", ip: "203.0.113.7", want: false},
		{rule: "42", ip: "203.0.113.7", want: false},
	} {
		if got := securityEventsCRSExclusionRemovesRule(indexed, tc.rule, tc.ip); got != tc.want {
			t.Fatalf("group target 42: rule=%s ip=%q got=%v, want %v", tc.rule, tc.ip, got, tc.want)
		}
	}
}

// benchmarkPolicyList 构建 size 条不可归并的 /32 名单（200k 条即审计推演的
// 单策略形态）：末位地址按步长 2 递增，任意两条都不构成兄弟块，聚合后条目数
// 与输入一致（用连续 /24 会被聚合成少数大网段，失去规模意义）。
func benchmarkPolicyList(size int) []string {
	entries := make([]string, 0, size)
	for i := range size {
		a := uint32(i) * 2
		entries = append(entries, fmt.Sprintf("10.%d.%d.%d", (a>>16)&0xff, (a>>8)&0xff, a&0xff))
	}
	return entries
}

func BenchmarkSecurityEventsIPPrefixSetBuild200k(b *testing.B) {
	entries := benchmarkPolicyList(200000)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if set := securityEventsIPPrefixSet(entries); len(set) != len(entries) {
			b.Fatalf("unexpected set size %d", len(set))
		}
	}
}

func BenchmarkSecurityEventsIPInPrefixSet200k(b *testing.B) {
	set := securityEventsIPPrefixSet(benchmarkPolicyList(200000))
	targets := []string{"10.0.0.0", "10.3.13.64", "10.6.26.128", "198.51.100.7"}
	b.ReportAllocs()
	b.ResetTimer()
	var i int
	for b.Loop() {
		securityEventsIPInPrefixSet(targets[i%len(targets)], set)
		i++
	}
}

// BenchmarkSecurityEventsAttributionIPMembership_10Policies200k 复现审计推演的
// 归因热路径：10 个候选 deny 策略各带 20 万条合并名单，逐事件成员判定。
// 索引在计时外构建（每 tick 一次），计时内只测事件侧判定成本。
func BenchmarkSecurityEventsAttributionIPMembership_10Policies200k(b *testing.B) {
	entries := benchmarkPolicyList(200000)
	policies := make([]*models.SecurityPolicy, 10)
	for i := range policies {
		policies[i] = &models.SecurityPolicy{
			ID: i + 1, IPACLEnabled: true, IPACLMode: "deny",
			MergedACLList: entries,
		}
		securityEventsPolicyACLIndex(policies[i]) // 预热：模拟同 tick 首次判定
	}
	targets := []string{"10.0.0.0", "10.3.13.64", "10.6.26.128", "198.51.100.7"}
	b.ReportAllocs()
	b.ResetTimer()
	var i int
	for b.Loop() {
		p := policies[i%len(policies)]
		securityEventsPolicyContainsRuleWithExclusions(p, "2", targets[i%len(targets)], securityEventsPolicyCRSExclusions{})
		i++
	}
}

// TestSecurityEventsCRSExclusionIPIndex_matchesLegacyScan 钉住排除判定的两种
// 快照形态等价：装载期预构建的 entrySets 与手工快照的按需构建必须给出同一
// 结论，且与改造前的逐条字符串扫描逐点一致（含嵌套/重复/垃圾/4in6 条目）。
func TestSecurityEventsCRSExclusionIPIndex_matchesLegacyScan(t *testing.T) {
	lists := map[int64][]string{
		7: {"203.0.113.0/24", "203.0.113.0/24", "junk"},
		8: {"::ffff:198.51.100.0/120", "10.0.0.0/8", "10.1.0.0/16"},
	}
	entries := ParseCRSExcludedRules(`[
		{"target":"942100","scope":"ip","ips":"198.51.100.9, 2001:db8::1"},
		{"target":"942200","scope":"list","listRefs":[7,8]},
		{"target":"942300","scope":"ip","ips":""},
		{"target":"942400","scope":"all"}
	]`)
	if len(entries) != 4 {
		t.Fatalf("fixture entries=%d, want 4", len(entries))
	}
	withIndex := securityEventsPolicyCRSExclusions{
		entries:   entries,
		lists:     lists,
		entrySets: securityEventsBuildCRSExclusionIPIndex(entries, lists),
	}
	lazy := securityEventsPolicyCRSExclusions{entries: entries, lists: lists}
	queries := []string{
		"198.51.100.9", "198.51.100.10", "203.0.113.7", "203.0.113.0",
		"::ffff:198.51.100.7", "2001:db8::1", "2001:db9::1", "10.1.2.3", "10.2.3.4", "",
	}
	for _, rule := range []string{"942100", "942200", "942300", "942400", "942900"} {
		for _, ip := range queries {
			want := securityEventsCRSExclusionRemovesRule(lazy, rule, ip)
			if got := securityEventsCRSExclusionRemovesRule(withIndex, rule, ip); got != want {
				t.Fatalf("prebuilt index diverges: rule=%s ip=%q index=%v lazy=%v", rule, ip, got, want)
			}
			// 逐条扫描基准：与生产判定同口径（排除基础设施目标）。
			var legacy bool
			for _, entry := range entries {
				if CRSExclusionTargetRemovesInfra(entry.Target) {
					continue
				}
				if entry.Scope == "ip" || entry.Scope == "list" {
					if ip == "" || !(IsCRSGroupCode(entry.Target) || IsCRSRuleIDTarget(entry.Target)) {
						continue
					}
					match := strings.Split(entry.IPs, ",")
					for _, ref := range entry.ListRefs {
						match = append(match, lists[ref]...)
					}
					if !legacyIPInList(ip, match) {
						continue
					}
				} else if entry.Scope != "" && entry.Scope != "all" {
					continue
				}
				if securityEventsCRSExclusionTargetMatches(entry.Target, rule) {
					legacy = true
					break
				}
			}
			if want != legacy {
				t.Fatalf("snapshot path diverges from legacy scan: rule=%s ip=%q got=%v legacy=%v", rule, ip, want, legacy)
			}
		}
	}
}
