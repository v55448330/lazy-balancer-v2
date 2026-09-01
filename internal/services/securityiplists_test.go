package services

import (
	"encoding/json"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func seedIPList(t *testing.T, name, entriesJSON string) int64 {
	t.Helper()
	res, err := db.DB.Exec(`INSERT INTO security_ip_lists (name, entries) VALUES (?, ?)`, name, entriesJSON)
	if err != nil {
		t.Fatalf("seed ip list %s: %v", name, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestExpandPolicyIPRefs_mergeDedupInlineFirst(t *testing.T) {
	p := &models.SecurityPolicy{
		IPACLList:       `["1.2.3.4","10.0.0.0/8"]`,
		IPACLListRefs:   `[1]`,
		IPWhitelist:     json.RawMessage(`["198.51.100.1"]`),
		IPWhitelistRefs: `[2]`,
	}
	lists := map[int64][]string{
		1: {"10.0.0.0/8", "192.0.2.1"},
		2: {"198.51.100.1", "203.0.113.0/24"},
	}
	exp := expandPolicyIPRefs(p, lists)

	wantACL := []string{"1.2.3.4", "10.0.0.0/8", "192.0.2.1"}
	if len(exp.ACLList) != len(wantACL) {
		t.Fatalf("ACLList=%v, want %v", exp.ACLList, wantACL)
	}
	for i := range wantACL {
		if exp.ACLList[i] != wantACL[i] {
			t.Fatalf("ACLList=%v, want %v (inline-first dedup order)", exp.ACLList, wantACL)
		}
	}
	wantWL := []string{"198.51.100.1", "203.0.113.0/24"}
	if len(exp.Whitelist) != len(wantWL) || exp.Whitelist[0] != wantWL[0] || exp.Whitelist[1] != wantWL[1] {
		t.Fatalf("Whitelist=%v, want %v", exp.Whitelist, wantWL)
	}
}

func TestExpandPolicyIPRefs_missingAndMalformedRefsSkipped(t *testing.T) {
	base := &models.SecurityPolicy{IPACLList: `["1.2.3.4"]`}
	cases := []struct {
		name string
		refs string
	}{
		{"missing id in map", "[99]"},
		{"malformed json", "not-json"},
		{"wrong element type", `["1"]`},
		{"empty refs", "[]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := *base
			p.IPACLListRefs = tc.refs
			exp := expandPolicyIPRefs(&p, map[int64][]string{})
			if len(exp.ACLList) != 1 || exp.ACLList[0] != "1.2.3.4" {
				t.Fatalf("ACLList=%v, want inline-only [1.2.3.4]", exp.ACLList)
			}
		})
	}
}

func TestExpandPolicyIPRefs_nilMapFallsBackToInline(t *testing.T) {
	p := &models.SecurityPolicy{
		IPACLList:       `["1.2.3.4"]`,
		IPACLListRefs:   "[1]",
		IPWhitelist:     json.RawMessage(`[]`),
		IPWhitelistRefs: "[1]",
	}
	exp := expandPolicyIPRefs(p, nil)
	if len(exp.ACLList) != 1 || exp.ACLList[0] != "1.2.3.4" {
		t.Fatalf("ACLList=%v, want inline-only", exp.ACLList)
	}
	if len(exp.Whitelist) != 0 {
		t.Fatalf("Whitelist=%v, want empty", exp.Whitelist)
	}
}

func TestLoadIPListEntriesByID_valuesOnlyAndMissingSkipped(t *testing.T) {
	newClusterTestService(t)
	idA := seedIPList(t, "list-a", `[{"value":"10.0.0.0/8","remark":"内网"},{"value":"192.0.2.1","remark":""}]`)
	idB := seedIPList(t, "list-b", `not-json`)
	seedIPList(t, "list-c", `[]`)

	got, err := LoadIPListEntriesByID([]int64{idA, idB, 9999})
	if err != nil {
		t.Fatalf("LoadIPListEntriesByID: %v", err)
	}
	entries, ok := got[idA]
	if !ok || len(entries) != 2 || entries[0] != "10.0.0.0/8" || entries[1] != "192.0.2.1" {
		t.Fatalf("list-a entries=%v, want [10.0.0.0/8 192.0.2.1]", entries)
	}
	if _, ok := got[idB]; ok {
		t.Fatal("malformed entries row should be skipped")
	}
	if _, ok := got[int64(9999)]; ok {
		t.Fatal("missing id should be absent")
	}
	empty, err := LoadIPListEntriesByID(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty ids: got %v err=%v, want empty map", empty, err)
	}
}

func TestBuildCorazaDirectives_mergedEmission_inlinePlusListEntries(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "merged-src", `[{"value":"10.0.0.0/8","remark":""},{"value":"192.0.2.0/24","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES ('merged', 'off', 'deny', '["1.2.3.4"]', 1, ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_merged', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_merged")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "@ipMatch 1.2.3.4,10.0.0.0/8,192.0.2.0/24") {
		t.Fatalf("directives must emit inline + list entries in one deny rule:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_refsOnlyPolicyStillEmits(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "refs-only", `[{"value":"203.0.113.0/24","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES ('refsonly', 'off', 'deny', '[]', 1, ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_refsonly', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_refsonly")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "@ipMatch 203.0.113.0/24") {
		t.Fatalf("refs-only policy must emit list entries:\n%s", directives)
	}
	if !strings.Contains(directives, "SecRuleEngine On") {
		t.Fatalf("refs-only policy must still turn the engine on:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_unresolvedPolicyFallsBackToInline(t *testing.T) {
	policy := &models.SecurityPolicy{
		Mode:          "off",
		IPACLMode:     "deny",
		IPACLList:     `["1.2.3.4"]`,
		IPACLEnabled:  true,
		IPACLListRefs: "[42]",
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "@ipMatch 1.2.3.4") {
		t.Fatalf("inline entries must survive:\n%s", directives)
	}
	if strings.Contains(directives, "@ipMatch 1.2.3.4,") {
		t.Fatalf("unresolved refs must not append anything after inline entries:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_whitelistRefsMergedIntoTrustRule(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "trust-src", `[{"value":"198.51.100.7","remark":""}]`)
	res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_whitelist, ip_whitelist_refs, enabled) VALUES ('trustrefs', 'off', '["198.51.100.9"]', ?, 1)`, fmtListIDs(listID))
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := res.LastInsertId()
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_trustrefs', ?)`, policyID); err != nil {
		t.Fatal(err)
	}

	policy := GetSecurityPolicyForRule("lb_ip_trustrefs")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := BuildCorazaDirectives(policy, nil)
	if !strings.Contains(directives, "id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off") {
		t.Fatalf("trust rule must be emitted:\n%s", directives)
	}
	if !strings.Contains(directives, "@ipMatch 198.51.100.9,198.51.100.7") {
		t.Fatalf("trust rule must contain inline + list entries (inline first):\n%s", directives)
	}
}

func TestSecurityPolicyHasIPControl_refsOnlyTruthTable(t *testing.T) {
	cases := []struct {
		name string
		p    *models.SecurityPolicy
		want bool
	}{
		{"ACL refs only, enabled", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: "[]", IPACLListRefs: "[3]"}, true},
		{"ACL refs only, toggle off", &models.SecurityPolicy{IPACLMode: "deny", IPACLList: "[]", IPACLListRefs: "[3]"}, false},
		{"whitelist refs only, enabled", &models.SecurityPolicy{IPWhitelistEnabled: true, IPWhitelistRefs: "[3]"}, true},
		{"whitelist refs only, toggle off", &models.SecurityPolicy{IPWhitelistRefs: "[3]"}, false},
		{"malformed ACL refs", &models.SecurityPolicy{IPACLEnabled: true, IPACLList: "[]", IPACLListRefs: "bad"}, false},
		{"no refs no inline", &models.SecurityPolicy{IPACLEnabled: true, IPACLList: "[]"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SecurityPolicyHasIPControl(tc.p); got != tc.want {
				t.Fatalf("SecurityPolicyHasIPControl = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBuildIPPrecheckDirectives_mergedDenyUnion(t *testing.T) {
	newClusterTestService(t)
	listA := seedIPList(t, "deny-a", `[{"value":"10.0.0.0/8","remark":""}]`)
	listB := seedIPList(t, "deny-b", `[{"value":"192.0.2.0/24","remark":""}]`)
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["1.2.3.4"]`, IPACLListRefs: fmtListIDs(listA)}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPACLListRefs: fmtListIDs(listB)}
	resolvePolicyIPListRefs([]*models.SecurityPolicy{p1, p2}, nil)

	directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})
	if !strings.Contains(directives, "id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END") {
		t.Fatalf("deny union rule missing:\n%s", directives)
	}
	for _, want := range []string{"1.2.3.4", "10.0.0.0/8", "192.0.2.0/24"} {
		if !strings.Contains(directives, want) {
			t.Fatalf("deny union must contain %s:\n%s", want, directives)
		}
	}
}

func TestBuildIPPrecheckDirectives_mergedAllowIntersection(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "allow-a", `[{"value":"203.0.113.5","remark":""}]`)
	p1 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["198.51.100.1","203.0.113.5"]`}
	p2 := &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`, IPACLListRefs: fmtListIDs(listID)}
	resolvePolicyIPListRefs([]*models.SecurityPolicy{p1, p2}, nil)

	directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})
	if !strings.Contains(directives, "id:7,phase:1,deny,status:403,log,msg:'IP 白名单拒绝',skipAfter:SECURITY_RULES_END") {
		t.Fatalf("allow intersection rule missing:\n%s", directives)
	}
	// P1 合并集 [198.51.100.1 203.0.113.5] ∩ P2 合并集 [203.0.113.5] = [203.0.113.5]
	if !strings.Contains(directives, "!@ipMatch 203.0.113.5") {
		t.Fatalf("intersection must be merged(P1) ∩ merged(P2) = [203.0.113.5]:\n%s", directives)
	}
	if strings.Contains(directives, "198.51.100.1") {
		t.Fatalf("198.51.100.1 only in P1 must not survive the allow intersection:\n%s", directives)
	}
}

func TestGetSecurityPoliciesForRule_resolvesRefsAcrossBatch(t *testing.T) {
	newClusterTestService(t)
	listID := seedIPList(t, "batch-src", `[{"value":"10.0.0.0/8","remark":""}]`)
	refsJSON := fmtListIDs(listID)
	for _, name := range []string{"batch-1", "batch-2"} {
		res, err := db.DB.Exec(`INSERT INTO security_policies (name, mode, ip_acl_mode, ip_acl_list, ip_acl_enabled, ip_acl_list_refs, enabled) VALUES (?, 'off', 'deny', '[]', 1, ?, 1)`, name, refsJSON)
		if err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
		policyID, _ := res.LastInsertId()
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES ('lb_ip_batch', ?)`, policyID); err != nil {
			t.Fatal(err)
		}
	}

	policies := GetSecurityPoliciesForRule("lb_ip_batch")
	if len(policies) != 2 {
		t.Fatalf("policies=%d, want 2", len(policies))
	}
	for _, p := range policies {
		if len(p.MergedACLList) != 1 || p.MergedACLList[0] != "10.0.0.0/8" {
			t.Fatalf("policy %s MergedACLList=%v, want [10.0.0.0/8]", p.Name, p.MergedACLList)
		}
	}
}

func fmtListIDs(ids ...int64) string {
	raw, _ := json.Marshal(ids)
	return string(raw)
}
