package services

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func useCRSDirectivesDir(t *testing.T, dir string) {
	t.Helper()
	old := crsDirectivesDir
	crsDirectivesDir = dir
	t.Cleanup(func() { crsDirectivesDir = old })
}

func TestBuildCorazaDirectives_WAFAuditLogPartsIncludeK(t *testing.T) {
	// Given a blocking policy
	// When
	directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"})

	// Then the audit log keeps part K so matched rule ids/messages populate the
	// audit messages array (without K, event rule attribution is lost)
	if !strings.Contains(directives, "SecAuditLogParts ABIJDEFHKZ\n") {
		t.Fatalf("directives must log audit part K (rule messages):\n%s", directives)
	}
	if strings.Contains(directives, "ABIJDEFHZ") {
		t.Fatalf("audit parts missing K:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_BypassAndTrustListUseDistinctIDs(t *testing.T) {
	// Given a blocking policy in bypass ACL mode whose trust list is also populated
	policy := &models.SecurityPolicy{
		Mode:         "blocking",
		IPACLMode:    "bypass",
		IPACLList:    `["203.0.113.0/24","192.0.2.7"]`,
		IPACLEnabled: true,
		IPWhitelist:  json.RawMessage(`["198.51.100.9"]`),
	}

	// When
	directives := BuildCorazaDirectives(policy)

	// Then the bypass rule keeps id:3 with the ACL list and the trust list moves to
	// id:5, so both ctl:ruleEngine=Off rules coexist without a duplicate SecRule id
	bypassRule := `SecRule REMOTE_ADDR "@ipMatch 203.0.113.0/24,192.0.2.7" "id:3,phase:1,pass,nolog,ctl:ruleEngine=Off"`
	trustRule := `SecRule REMOTE_ADDR "@ipMatch 198.51.100.9" "id:5,phase:1,pass,nolog,ctl:ruleEngine=Off"`
	if !strings.Contains(directives, bypassRule) {
		t.Fatalf("directives missing bypass rule %q:\n%s", bypassRule, directives)
	}
	if !strings.Contains(directives, trustRule) {
		t.Fatalf("directives missing trust-list rule %q:\n%s", trustRule, directives)
	}
	if count := strings.Count(directives, "id:3,"); count != 1 {
		t.Fatalf("id:3 occurrences = %d, want exactly 1 (duplicate SecRule id):\n%s", count, directives)
	}
	if count := strings.Count(directives, "id:5,"); count != 1 {
		t.Fatalf("id:5 occurrences = %d, want exactly 1 (duplicate SecRule id):\n%s", count, directives)
	}
	if strings.Index(directives, bypassRule) > strings.Index(directives, trustRule) {
		t.Fatalf("bypass rule must precede the trust-list rule:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_TrustListPrecedesACLRules(t *testing.T) {
	// Given an allow-mode ACL policy that also trusts a monitoring IP
	policy := &models.SecurityPolicy{
		Mode:         "blocking",
		IPACLMode:    "allow",
		IPACLList:    `["203.0.113.0/24"]`,
		IPACLEnabled: true,
		IPWhitelist:  json.RawMessage(`["198.51.100.9"]`),
	}

	// When
	directives := BuildCorazaDirectives(policy)

	// Then the trust-list rule takes id:3 (no bypass rule present) and the
	// ctl:ruleEngine=Off short-circuit is emitted before the ACL deny rule
	trustRule := `SecRule REMOTE_ADDR "@ipMatch 198.51.100.9" "id:3,phase:1,pass,nolog,ctl:ruleEngine=Off"`
	aclRule := `SecRule REMOTE_ADDR "!@ipMatch 203.0.113.0/24" "id:2,phase:1,deny,status:403`
	if !strings.Contains(directives, trustRule) {
		t.Fatalf("directives missing trust-list rule %q:\n%s", trustRule, directives)
	}
	trustIdx := strings.Index(directives, "ctl:ruleEngine=Off")
	aclIdx := strings.Index(directives, aclRule)
	if trustIdx < 0 || aclIdx < 0 {
		t.Fatalf("directives must contain both the ctl short-circuit and the ACL rule:\n%s", directives)
	}
	if trustIdx > aclIdx {
		t.Fatalf("trust/bypass ctl rule (offset %d) must precede ACL rules (offset %d):\n%s", trustIdx, aclIdx, directives)
	}
}

func TestBuildCorazaDirectives_allowAndDenyModesUnchangedByBypass(t *testing.T) {
	// Given allow and deny policies
	allow := &models.SecurityPolicy{Mode: "blocking", IPACLMode: "allow", IPACLList: `["198.51.100.7"]`, IPACLEnabled: true}
	deny := &models.SecurityPolicy{Mode: "blocking", IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`, IPACLEnabled: true}

	// When
	allowDirectives := BuildCorazaDirectives(allow)
	denyDirectives := BuildCorazaDirectives(deny)

	// Then allow still denies non-listed IPs and deny still blocks listed IPs, neither emits a bypass id:3
	if !strings.Contains(allowDirectives, `SecRule REMOTE_ADDR "!@ipMatch 198.51.100.7" "id:2,phase:1,deny,status:403`) {
		t.Fatalf("allow mode directives changed:\n%s", allowDirectives)
	}
	if !strings.Contains(denyDirectives, `SecRule REMOTE_ADDR "@ipMatch 203.0.113.0/24" "id:2,phase:1,deny,status:403`) {
		t.Fatalf("deny mode directives changed:\n%s", denyDirectives)
	}
	if strings.Contains(allowDirectives, "id:3") || strings.Contains(denyDirectives, "id:3") {
		t.Fatalf("allow/deny modes must not emit the bypass id:3 rule")
	}
}

func TestSecurityPolicyHasIPControl_truthTable(t *testing.T) {
	// Given/When/Then: has_ip_control follows ACL entries, trust list, and legacy bypass
	cases := []struct {
		name   string
		policy *models.SecurityPolicy
		want   bool
	}{
		{"neither: ACL disabled, lists empty", &models.SecurityPolicy{IPACLMode: "allow", IPACLList: "[]", IPWhitelist: json.RawMessage("[]")}, false},
		{"ACL enabled but list empty", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: "[]"}, false},
		{"ACL only: enabled allow-mode with entries", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["203.0.113.0/24"]`}, true},
		{"trust only: whitelist populated, ACL disabled", &models.SecurityPolicy{IPACLList: "[]", IPWhitelist: json.RawMessage(`["198.51.100.9"]`)}, true},
		{"both: enabled ACL entries and trust list", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`, IPWhitelist: json.RawMessage(`["198.51.100.9"]`)}, true},
		{"legacy bypass: bypass mode with entries", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "bypass", IPACLList: `["192.0.2.7"]`}, true},
		{"legacy bypass: entries present but toggle off", &models.SecurityPolicy{IPACLMode: "bypass", IPACLList: `["192.0.2.7"]`}, false},
		{"bypass mode with empty list and no trust list", &models.SecurityPolicy{IPACLMode: "bypass", IPACLList: "[]"}, false},
		{"nil policy", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SecurityPolicyHasIPControl(tc.policy); got != tc.want {
				t.Fatalf("SecurityPolicyHasIPControl(%+v) = %v, want %v", tc.policy, got, tc.want)
			}
		})
	}
}

func TestGetSecurityPolicyForRule_roundTripsIPWhitelistAndBlacklist(t *testing.T) {
	// Given a bound policy persisted with trust list, blacklist, and ACL fields
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO security_policies (name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,
		rate_limit_enabled,rate_limit_rps,rate_limit_burst,block_status_code,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,enabled)
		VALUES ('roundtrip','desc','blocking',5,'allow','["203.0.113.0/24"]',1,'["192.0.2.0/24","2001:db8::1"]','["203.0.113.5"]',1,100,50,'429','[]','[]','[]',0,1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_roundtrip',?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}

	// When
	policy := GetSecurityPolicyForRule("lb_roundtrip")

	// Then the trust list and blacklist survive the read path as valid JSON
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	var whitelist, blacklist []string
	if err := json.Unmarshal(policy.IPWhitelist, &whitelist); err != nil {
		t.Fatalf("ip_whitelist is not valid JSON: %v (%s)", err, policy.IPWhitelist)
	}
	if err := json.Unmarshal(policy.IPBlacklist, &blacklist); err != nil {
		t.Fatalf("ip_blacklist is not valid JSON: %v (%s)", err, policy.IPBlacklist)
	}
	if len(whitelist) != 2 || whitelist[0] != "192.0.2.0/24" || whitelist[1] != "2001:db8::1" {
		t.Fatalf("ip_whitelist round-trip = %v, want [192.0.2.0/24 2001:db8::1]", whitelist)
	}
	if len(blacklist) != 1 || blacklist[0] != "203.0.113.5" {
		t.Fatalf("ip_blacklist round-trip = %v, want [203.0.113.5]", blacklist)
	}
}

// TestBuildCorazaDirectives_trimsLegacyCRSGroupWhitespace 验证 R47 B-#1 发射侧：
// 历史遗留行（旧校验放行过首尾空白条目）即使库中组号为 " 42 "，发射端也必须
// trim 后拼接，产出合法 glob REQUEST-942-*.conf 而非零匹配的 REQUEST-9 42-*.conf
// ——coraza 对零匹配 Include 静默接受，blocking 模式该组规则将静默缺失。
// RESPONSE-9 同行走同一变量，一并断言。
func TestBuildCorazaDirectives_trimsLegacyCRSGroupWhitespace(t *testing.T) {
	// Given 一条历史遗留策略行：组号含首尾空白（模拟绕过校验直接落库的旧数据）
	useCRSDirectivesDir(t, t.TempDir())
	_, database := newClusterTestService(t)
	result, err := database.Exec(`INSERT INTO security_policies (name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,
		rate_limit_enabled,rate_limit_rps,rate_limit_burst,block_status_code,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,enabled,waf_check_response)
		VALUES ('legacy','desc','blocking',5,'deny','[]',0,'[]','[]',0,0,0,'403','[" 42 "]','[]','[]',0,1,1)`)
	if err != nil {
		t.Fatalf("seed legacy policy: %v", err)
	}
	policyID, _ := result.LastInsertId()
	if _, err := database.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_legacy_group',?)`, policyID); err != nil {
		t.Fatalf("bind policy: %v", err)
	}

	// When
	policy := GetSecurityPolicyForRule("lb_legacy_group")
	if policy == nil {
		t.Fatal("expected bound policy to load")
	}
	directives := BuildCorazaDirectives(policy)

	// Then REQUEST/RESPONSE 两行均为 trim 后的合法 glob，且不存在畸形 glob
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-942-*.conf\n") {
		t.Fatalf("directives must emit trimmed REQUEST glob:\n%s", directives)
	}
	if !strings.Contains(directives, "Include /app/waf/crs/rules/RESPONSE-942-*.conf\n") {
		t.Fatalf("directives must emit trimmed RESPONSE glob:\n%s", directives)
	}
	if strings.Contains(directives, "REQUEST-9 42") || strings.Contains(directives, "RESPONSE-9 42") {
		t.Fatalf("directives must not contain malformed glob with whitespace:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_includesUserOverridesWhenFileExists(t *testing.T) {
	// Given a live CRS dir containing the user overrides file
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "zz-user-overrides.conf"), []byte("# user overrides"), 0o644); err != nil {
		t.Fatal(err)
	}
	useCRSDirectivesDir(t, dir)

	// When
	directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"})

	// Then the overrides include follows the crs-setup include
	setupIdx := strings.Index(directives, "Include /app/waf/crs/crs-setup.conf")
	overridesIdx := strings.Index(directives, "Include /app/waf/crs/zz-user-overrides.conf")
	if setupIdx < 0 {
		t.Fatalf("directives missing crs-setup include:\n%s", directives)
	}
	if overridesIdx < 0 {
		t.Fatalf("directives missing user overrides include:\n%s", directives)
	}
	if overridesIdx <= setupIdx {
		t.Fatalf("overrides include must follow the crs-setup include:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_omitsUserOverridesWhenFileMissing(t *testing.T) {
	// Given a live CRS dir without the user overrides file
	useCRSDirectivesDir(t, t.TempDir())

	// When
	directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"})

	// Then
	if strings.Contains(directives, "zz-user-overrides") {
		t.Fatalf("directives must not include a missing overrides file:\n%s", directives)
	}
}
