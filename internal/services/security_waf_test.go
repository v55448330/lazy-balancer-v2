package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

func useCRSDirectivesDir(t *testing.T, dir string) {
	t.Helper()
	oldLive, old := crsLiveDir, crsDirectivesDir
	crsLiveDir, crsDirectivesDir = dir, dir
	t.Cleanup(func() { crsLiveDir, crsDirectivesDir = oldLive, old })
}

func TestBuildCorazaDirectives_WAFAuditLogPartsIncludeK(t *testing.T) {
	// Given a blocking policy
	// When
	directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 0, "lb_test"))

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
	// Given a blocking policy in 绕过 ACL mode whose trust list is also populated
	policy := &models.SecurityPolicy{
		AnomalyThreshold:   5,
		Mode:               "blocking",
		IPACLMode:          "绕过",
		IPACLList:          `["203.0.113.0/24","192.0.2.7"]`,
		IPACLEnabled:       true,
		IPWhitelist:        json.RawMessage(`["198.51.100.9"]`),
		IPWhitelistEnabled: true,
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

	// Then the 绕过 rule keeps id:3 (Off+auditOff,超授权外保持);
	// 信任名单 id:5 改 DetectionOnly(2026-09-15 用户裁定:信任流量全评估+
	// 事件记录动作=检测,不再静默)——两语义共存无重复 SecRule id。
	// v2.3.x：名单经 @ipListFast 文件投影——形状钉 id/动作，内容钉文件。
	绕过Rule := `"id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off"`
	trustRule := `"id:5,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	if !strings.Contains(directives, 绕过Rule) {
		t.Fatalf("directives missing 绕过 rule %q:\n%s", 绕过Rule, directives)
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
	// 发射序钉（绕过终态保证）：coraza ctl 同相位后写覆盖前写——信任
	// DetectionOnly 先发、绕过 Off 后发，同一 IP 同列两名册时绕过才是
	// 事务终态；反之绕过被降级为「全评估仅记录」。真实事务级断言见
	// security_render_guard_test.go 的引擎门禁用例。
	if strings.Index(directives, trustRule) > strings.Index(directives, 绕过Rule) {
		t.Fatalf("trust-list rule must precede the 绕过 rule（后写覆盖前写，绕过必须是终态）:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "-acl"); got != "192.0.2.7/32\n203.0.113.0/24\n" {
		t.Fatalf("绕过 名单文件=%q, want 聚合排序两条", got)
	}
	if got := readRenderedIPList(t, directives, "-trust"); got != "198.51.100.9/32\n" {
		t.Fatalf("信任名单文件=%q, want 仅 198.51.100.9/32", got)
	}
}

func TestBuildCorazaDirectives_TrustListPrecedesACLRules(t *testing.T) {
	// Given an allow-mode ACL policy that also trusts a monitoring IP
	policy := &models.SecurityPolicy{
		AnomalyThreshold:   5,
		Mode:               "blocking",
		IPACLMode:          "allow",
		IPACLList:          `["203.0.113.0/24"]`,
		IPACLEnabled:       true,
		IPWhitelist:        json.RawMessage(`["198.51.100.9"]`),
		IPWhitelistEnabled: true,
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

	// Then the trust-list rule takes id:3 (no 绕过 rule present)——
	// DetectionOnly short-circuit(2026-09-15 用户裁定:信任可见放行)emitted
	// before the ACL deny rule
	trustRule := `"id:3,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`
	aclRule := `SecRule REMOTE_ADDR "!@ipListFast `
	if !strings.Contains(directives, trustRule) {
		t.Fatalf("directives missing trust-list rule %q:\n%s", trustRule, directives)
	}
	trustIdx := strings.Index(directives, "ctl:ruleEngine=DetectionOnly")
	aclIdx := strings.Index(directives, aclRule)
	if trustIdx < 0 || aclIdx < 0 {
		t.Fatalf("directives must contain both the ctl short-circuit and the ACL rule:\n%s", directives)
	}
	if trustIdx > aclIdx {
		t.Fatalf("trust/绕过 ctl rule (offset %d) must precede ACL rules (offset %d):\n%s", trustIdx, aclIdx, directives)
	}
}

func TestBuildCorazaDirectives_allowAndDenyModesUnchangedByBypass(t *testing.T) {
	// Given allow and deny policies（显式相异 id——稳定命名 <scope>.txt 按
	// 策略 id 定文件，零值 id 会让两个夹具共写 p0-acl.txt）
	allow := &models.SecurityPolicy{ID: 41, AnomalyThreshold: 5, Mode: "blocking", IPACLMode: "allow", IPACLList: `["198.51.100.7"]`, IPACLEnabled: true}
	deny := &models.SecurityPolicy{ID: 42, AnomalyThreshold: 5, Mode: "blocking", IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`, IPACLEnabled: true}

	// When
	allowDirectives := mustDirectives(BuildCorazaDirectives(allow, nil, "", false, 0, "lb_test"))
	denyDirectives := mustDirectives(BuildCorazaDirectives(deny, nil, "", false, 0, "lb_test"))

	// Then allow still denies non-listed IPs and deny still blocks listed IPs, neither emits a 绕过 id:3
	if !strings.Contains(allowDirectives, `SecRule REMOTE_ADDR "!@ipListFast `) || !strings.Contains(allowDirectives, `"id:2,phase:1,deny,status:403`) {
		t.Fatalf("allow mode directives changed:\n%s", allowDirectives)
	}
	if !strings.Contains(denyDirectives, `SecRule REMOTE_ADDR "@ipListFast `) || !strings.Contains(denyDirectives, `"id:2,phase:1,deny,status:403`) {
		t.Fatalf("deny mode directives changed:\n%s", denyDirectives)
	}
	if got := readRenderedIPList(t, allowDirectives, "-acl"); got != "198.51.100.7/32\n" {
		t.Fatalf("allow 名单文件=%q, want 仅 198.51.100.7/32", got)
	}
	if got := readRenderedIPList(t, denyDirectives, "-acl"); got != "203.0.113.0/24\n" {
		t.Fatalf("deny 名单文件=%q, want 仅 203.0.113.0/24", got)
	}
	if strings.Contains(allowDirectives, "id:3") || strings.Contains(denyDirectives, "id:3") {
		t.Fatalf("allow/deny modes must not emit the 绕过 id:3 rule")
	}
}

// IP ACL deny 规则引用的 skipAfter 终点与无条件发射的 SecMarker
// 必须成对存在——marker 缺失时 coraza 拒绝编译整个 directives（配置自锁）。
func TestBuildCorazaDirectives_ipACLDenyCarriesSkipAfterAndMarker(t *testing.T) {
	// Given：deny 模式 ACL + 遗留黑名单各一条
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		IPACLMode:        "deny",
		IPACLList:        `["203.0.113.0/24"]`,
		IPACLEnabled:     true,
		IPBlacklist:      json.RawMessage(`["192.0.2.99"]`),
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

	// Then：deny 规则携带 skipAfter 引用，且终点 SecMarker 存在
	if !strings.Contains(directives, `deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END`) {
		t.Fatalf("ACL deny rule must skipAfter the end marker:\n%s", directives)
	}
	if !strings.Contains(directives, `deny,status:403,log,msg:'IP 黑名单',skipAfter:SECURITY_RULES_END`) {
		t.Fatalf("legacy blacklist rule must skipAfter the end marker:\n%s", directives)
	}
	if !strings.Contains(directives, "SecMarker SECURITY_RULES_END\n") {
		t.Fatalf("directives must emit the SecMarker terminal:\n%s", directives)
	}
	// And：marker 位于 deny 规则之后（skipAfter 向前跳转到终点）
	denyIdx := strings.Index(directives, "skipAfter:SECURITY_RULES_END")
	markerIdx := strings.Index(directives, "SecMarker SECURITY_RULES_END")
	if denyIdx < 0 || markerIdx < denyIdx {
		t.Fatalf("SecMarker (offset %d) must follow the skipAfter references (offset %d):\n%s", markerIdx, denyIdx, directives)
	}
}

func TestSecurityPolicyHasIPControl_truthTable(t *testing.T) {
	// Given/When/Then: has_ip_control follows ACL entries, trust list, and legacy 绕过
	cases := []struct {
		name   string
		policy *models.SecurityPolicy
		want   bool
	}{
		{"neither: ACL disabled, lists empty", &models.SecurityPolicy{IPACLMode: "allow", IPACLList: "[]", IPWhitelist: json.RawMessage("[]")}, false},
		// 始终发射收敛（2026-10-15）：deny ACL 开启即恒发射空文件算子，与内容解耦
		{"ACL enabled but list empty", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: "[]"}, true},
		{"ACL only: enabled allow-mode with entries", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["203.0.113.0/24"]`}, true},
		{"trust only: whitelist populated, ACL disabled", &models.SecurityPolicy{IPACLList: "[]", IPWhitelist: json.RawMessage(`["198.51.100.9"]`), IPWhitelistEnabled: true}, true},
		{"both: enabled ACL entries and trust list", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["203.0.113.0/24"]`, IPWhitelist: json.RawMessage(`["198.51.100.9"]`)}, true},
		{"legacy 绕过: 绕过 mode with entries", &models.SecurityPolicy{IPACLEnabled: true, IPACLMode: "绕过", IPACLList: `["192.0.2.7"]`}, true},
		{"legacy 绕过: entries present but toggle off", &models.SecurityPolicy{IPACLMode: "绕过", IPACLList: `["192.0.2.7"]`}, false},
		{"绕过 mode with empty list and no trust list", &models.SecurityPolicy{IPACLMode: "绕过", IPACLList: "[]"}, false},
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

// TestBuildCorazaDirectives_trimsLegacyCRSGroupWhitespace 验证发射侧
// 历史遗留行（旧校验放行过首尾空白条目）即使库中组号为 " 42 "，发射端也必须
// trim 后拼接，产出合法 glob REQUEST-942-*.conf 而非零匹配的 REQUEST-9 42-*.conf
// ——coraza 对零匹配 Include 静默接受，blocking 模式该组规则将静默缺失。
// 同行走同一变量，一并断言。
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
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

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
	// crs-setup.conf 有存在性门（缺失不发射，防致命 Include）——本用例验证
	// 「setup 先于 overrides」，文件必须在场。
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte("# setup"), 0o644); err != nil {
		t.Fatal(err)
	}
	useCRSDirectivesDir(t, dir)

	// When
	directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 0, "lb_test"))

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
	directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 0, "lb_test"))

	// Then
	if strings.Contains(directives, "zz-user-overrides") {
		t.Fatalf("directives must not include a missing overrides file:\n%s", directives)
	}
}

// 2026-09-09 排查 942550 误报（JSON 订单单被当 SQL 注入拦截）确认的集成缺口：
// coraza 不按自动启用 JSON/XML body processor（源码注释明确
// XML and JSON must be forced with ctl），CRS 901340 对无 processor 的 body 强制
// forceRequestBodyVariable 后 coraza 兜底按 URLENCODED 解析——JSON 整串成为
// 单个参数名：扫 ARGS_NAMES 的规则（942550/941100）在原始文本上误报，扫
// ARGS 值的规则对 body 失明。修复：CRS Include 之前显式激活 processor（对齐
// ModSecurity 连接器的引擎层行为；id 9/10 沿用本项目自有单数码段）。
// 值大小写不受控（coraza 仅小写化 header 名），
// 激活正则必须 (?i)，否则 Application/JSON 变体按请求退回兜底误报路径。
func TestBuildCorazaDirectives_activatesJSONXMLBodyProcessors(t *testing.T) {
	// crs-setup.conf 存在性门：夹具目录须含该文件（本用例按 setup Include 定位
	// 顺序，缺失时无法断言）。
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "crs-setup.conf"), []byte("# setup"), 0o644); err != nil {
		t.Fatal(err)
	}
	useCRSDirectivesDir(t, dir)
	jsonRule := `SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^application/(?:[\w.+-]+?\+)?json(?:\s*;|$)" "id:9,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"`
	xmlRule := `SecRule REQUEST_HEADERS:Content-Type "@rx (?i)^(?:application|text)/(?:[\w.+-]+?\+)?xml(?:\s*;|$)" "id:10,phase:1,pass,nolog,ctl:requestBodyProcessor=XML"`

	for _, mode := range []string{"blocking", "detection"} {
		// Given / When：CRS 加载的两种模式
		directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: mode}, nil, "", false, 0, "lb_test"))

		// Then：两条激活规则存在，且位于 crs-setup Include 之前（phase:1 按
		// 发射序执行，晚于 901340 的激活无法阻止 URLENCODED 兜底）
		setupIdx := strings.Index(directives, "Include /app/waf/crs/crs-setup.conf")
		if setupIdx < 0 {
			t.Fatalf("mode %s: crs-setup include missing:\n%s", mode, directives)
		}
		for _, rule := range []string{jsonRule, xmlRule} {
			idx := strings.Index(directives, rule)
			if idx < 0 {
				t.Fatalf("mode %s: body processor activation rule missing:\n%s", mode, directives)
			}
			if idx > setupIdx {
				t.Fatalf("mode %s: activation rule must precede the crs-setup include:\n%s", mode, directives)
			}
		}
	}
}

// 畸形 JSON/XML（或嵌套超深）使 coraza 解析失败——所有 body
// 集合为空且 901340 不再 force，CRS 4.29 无任何规则消费 REQBODY_PROCESSOR_ERROR
// （grep 实证零命中），恶意 body 可借「声明 JSON + 发非法 JSON」对全部 body
// 规则隐身。守卫规则 id:11 计满临界异常分（默认阈值 5 → 拦截模式即拦），
// 与 coraza ctl.go 文档建议的使用者自检口径一致。
func TestBuildCorazaDirectives_flagsBodyProcessorErrors(t *testing.T) {
	guard := `SecRule REQBODY_PROCESSOR_ERROR "@eq 1" "id:11,phase:2,pass,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'请求体解析失败'"`
	for _, mode := range []string{"blocking", "detection"} {
		// Given / When
		directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: mode}, nil, "", false, 0, "lb_test"))

		// Then
		if !strings.Contains(directives, guard) {
			t.Fatalf("mode %s: body processor error guard missing:\n%s", mode, directives)
		}
	}
}

// 2026-09-09 裁定:WAF 模式四态化——off 收敛为「CRS 与自定义规则均不生效」,
// 新增 custom_only(CRS 不生效、仅自定义规则,计分动作无 949 评估链退化为检测
// 计分)。发射契约:off 不再因自定义规则而开引擎;custom_only 开引擎、发射
// 自定义规则与 body processor 激活规则(自定义 body 规则需要解析),零 CRS Include。
func TestBuildCorazaDirectives_offModeOmitsCustomRules(t *testing.T) {
	// Given:mode=off 且挂启用中的自定义拦截规则
	policy := &models.SecurityPolicy{
		Mode: "off",
		CustomRules: json.RawMessage(`[{"id":1,"name":"off拦截","enabled":true,"action":"block","score":5,` +
			`"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`),
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

	// Then:新语义 off=全关——自定义规则不再触发引擎,整份发射为空
	if directives != "" {
		t.Fatalf("mode=off must not emit custom rules anymore (2026-09-09 裁定):\n%s", directives)
	}
}

func TestBuildCorazaDirectives_customOnlyModeEmitsCustomRulesWithoutCRS(t *testing.T) {
	// Given:mode=custom_only 且挂自定义拦截规则(含 body 条件)
	policy := &models.SecurityPolicy{
		Mode: "custom_only",
		// 启用规则会发射 body processor 守卫（id:11 计分=anomaly_threshold），
		// 按真实库形态给合法值 5（写侧枚举+启动回填保证恒正）。
		AnomalyThreshold: 5,
		CustomRules: json.RawMessage(`[{"id":2,"name":"仅自定义body","enabled":true,"action":"block","score":5,` +
			`"conditions":[{"target":"body","operator":"contains","pattern":"evil"}]}]`),
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))

	// Then:引擎开、自定义规则发射、body processor 激活规则在位
	for _, want := range []string{
		"SecRuleEngine On",
		"id:10002,phase:2",
		`id:9,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON`,
		`id:10,phase:1,pass,nolog,ctl:requestBodyProcessor=XML`,
		`id:11,phase:2,pass,log`,
		"SecMarker SECURITY_RULES_END",
	} {
		if !strings.Contains(directives, want) {
			t.Fatalf("custom_only directives missing %q:\n%s", want, directives)
		}
	}
	// And:零 CRS Include、无 DetectionOnly 切换(CRS 不加载,自定义 deny 直接拦)
	if strings.Contains(directives, "Include /app/waf/crs/") ||
		strings.Contains(directives, "DetectionOnly") {
		t.Fatalf("custom_only must not include CRS nor DetectionOnly:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_customOnlyWithoutAnythingIsEmpty(t *testing.T) {
	// Given:custom_only 但无自定义规则/IP 控制/GeoIP
	// When
	directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{Mode: "custom_only"}, nil, "", false, 0, "lb_test"))
	// Then:无可发射内容,整份为空(不产空转 coraza handler)
	if directives != "" {
		t.Fatalf("custom_only without any active component must emit nothing:\n%s", directives)
	}
}

func TestBuildCorazaDirectives_skipsIllegalSecRuleRemoveTargets(t *testing.T) {
	// B-新1：SecRuleRemoveById 形态门——非法形态（coraza Atoi 失败→
	// 全部配置编译失败/LB 停摆）与越界 range（1-999999 静默删光全部规则）
	// 必须跳过；合法单 ID 与合法区间照常发射。
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		CRSRuleGroups:    json.RawMessage(`["942"]`),
		CRSExcludedRules: json.RawMessage(`["942100","ABCDEF","942100-abc","REQUEST-942.conf","1-999999","932100-932200"]`),
	}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if !strings.Contains(directives, "SecRuleRemoveById 942100") {
		t.Fatal("legal single ID must be emitted")
	}
	if !strings.Contains(directives, "SecRuleRemoveById 932100-932200") {
		t.Fatal("legal in-range pair must be emitted")
	}
	for _, illegal := range []string{"ABCDEF", "942100-abc", "REQUEST-942.conf", "1-999999"} {
		if strings.Contains(directives, illegal) {
			t.Fatalf("illegal entry %q must be skipped", illegal)
		}
	}
}

func TestMergeOverridesLines_preservesExistingAndDedups(t *testing.T) {
	// B-新2：两次手改 setup 跨两次成功更新，前次迁移行必须保留；
	// 重复行去重；空 diff 且既有为空 → nil（不写空文件）。
	dir := t.TempDir()
	path := filepath.Join(dir, "zz-user-overrides.conf")
	os.WriteFile(path, []byte("# header\nSecAction pass,nolog,setvar:tx.old=1\n"), 0644)
	merged := mergeOverridesLines(path, "# new header\n", []string{"setvar tx.new=1", "SecAction pass,nolog,setvar:tx.old=1"})
	out := string(merged)
	for _, want := range []string{"setvar:tx.old=1", "setvar tx.new=1", "# new header"} {
		if !strings.Contains(out, want) {
			t.Fatalf("merged overrides missing %q:\n%s", want, out)
		}
	}
	if strings.Count(out, "setvar:tx.old=1") != 1 {
		t.Fatalf("duplicate line must be deduped:\n%s", out)
	}
	if mergeOverridesLines(filepath.Join(dir, "none.conf"), "# h\n", nil) != nil {
		t.Fatal("no existing + empty diff must return nil")
	}
}

func TestBuildCorazaDirectives_emitsCustomRuleWithNullColumns(t *testing.T) {
	// Given：两条自定义规则——一条 conditions=NULL，一条 action=NULL
	// （带外编辑或 restoreTable 透传 JSON null 可产生 NULL 行）
	_, database := newClusterTestService(t)
	r1, err := database.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled)
		VALUES ('null-conditions', NULL, 'block', 5, 1)`)
	if err != nil {
		t.Fatalf("seed null-conditions rule: %v", err)
	}
	r1ID, _ := r1.LastInsertId()
	r2, err := database.Exec(`INSERT INTO security_custom_rules (name, conditions, action, score, enabled)
		VALUES ('null-action', '[{"target":"uri","operator":"contains","pattern":"/admin"}]', NULL, 3, 1)`)
	if err != nil {
		t.Fatalf("seed null-action rule: %v", err)
	}
	r2ID, _ := r2.LastInsertId()
	policy := &models.SecurityPolicy{
		AnomalyThreshold: 5,
		Mode:             "blocking",
		CustomRules:      json.RawMessage(fmt.Sprintf("[%d,%d]", r1ID, r2ID)),
	}

	// When
	directives := mustDirectives(BuildCorazaDirectives(policy, database, "", false, 0, "lb_test"))

	// Then：r2（action=NULL → COALESCE 'block'）必须发射为 deny 规则
	wantID2 := fmt.Sprintf("id:%d", r2ID+10000)
	var r2Line string
	for _, line := range strings.Split(directives, "\n") {
		if strings.Contains(line, wantID2) {
			r2Line = line
		}
	}
	if r2Line == "" {
		t.Fatalf("null-action rule must be emitted with id %s:\n%s", wantID2, directives)
	}
	if !strings.Contains(r2Line, "null-action") {
		t.Fatalf("null-action rule name must appear in its own directive line:\n%s", r2Line)
	}
	// deny 必须锚定 r2 自身指令行——其它 deny 行（949 抬码/ACL 拒绝等）会让
	// 宽断言恒真。
	if !strings.Contains(r2Line, "deny") {
		t.Fatalf("null-action rule must default to deny (COALESCE 'block'):\n%s", r2Line)
	}
	// r1（conditions=NULL → '[]'）从 DB 加载成功但被发射侧正确跳过（空条件）——
	// 负向断言：不得出现其发射行，也不得再被误报为「不存在」（修复前 scan
	// 失败 → continue → 静默丢弃）。
	if wantID1 := fmt.Sprintf("id:%d", r1ID+10000); strings.Contains(directives, wantID1) {
		t.Fatalf("空条件规则不得发射（want 无 %s）:\n%s", wantID1, directives)
	}
}

func TestBuildRateLimitHandler_sweepIntervalAtHandlerLevel(t *testing.T) {
	// sweep_interval 必须在 handler 层而非 zone 级——Caddy v2.11.4
	// 对模块载荷 DisallowUnknownFields，zone 级未知字段使整个配置加载 400
	// （开启限流即配置停摆，README 核心功能不可用）。
	policy := &models.SecurityPolicy{RateLimitEnabled: true, RateLimitRPS: 5, RateLimitBurst: 10}
	handler, err := buildRateLimitHandler("lb_test", policy)
	if err != nil {
		t.Fatalf("buildRateLimitHandler: %v", err)
	}
	if handler["sweep_interval"] != "10m" {
		t.Fatalf("sweep_interval must live at handler level, got %v", handler["sweep_interval"])
	}
	zones := handler["rate_limits"].(map[string]interface{})
	for name, zone := range zones {
		zm, ok := zone.(map[string]interface{})
		if !ok {
			t.Fatalf("zone %s not a map", name)
		}
		for _, key := range []string{"sweep_interval"} {
			if _, exists := zm[key]; exists {
				t.Fatalf("zone %s must not carry %q (Caddy strict unmarshal rejects unknown zone fields)", name, key)
			}
		}
		if _, exists := zm["key"]; !exists {
			t.Fatalf("zone %s missing key", name)
		}
	}
	// burst 形态 sec+min 双 zone；非 burst 形态单 zone。
	if len(zones) != 2 {
		t.Fatalf("burst form should emit sec+min zones, got %d", len(zones))
	}
}

func TestBuildCorazaDirectives_crsPoolFingerprint(t *testing.T) {
	// Given：CRS 目录指向临时目录（无 zz-user-overrides.conf）
	dir := t.TempDir()
	useCRSDirectivesDir(t, dir)
	_, database := newClusterTestService(t)
	policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}

	// When：第一次渲染
	d1 := mustDirectives(BuildCorazaDirectives(policy, database, "", false, 0, "lb_test"))

	// Then：输出必须包含 crs-pool 指纹行
	if !strings.Contains(d1, "# crs-pool=") {
		t.Fatalf("directives must contain crs-pool fingerprint line:\n%s", d1)
	}

	// Given：写入 overrides 文件（改变 mtime+size）
	overridesPath := filepath.Join(dir, "zz-user-overrides.conf")
	if err := os.WriteFile(overridesPath, []byte("# v1\nSecAction pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：第二次渲染
	d2 := mustDirectives(BuildCorazaDirectives(policy, database, "", false, 0, "lb_test"))

	// Then：指纹必须不同（overrides 文件出现 → mtime/size 非零）
	fp1 := extractCRSPoolFingerprint(t, d1)
	fp2 := extractCRSPoolFingerprint(t, d2)
	if fp1 == fp2 {
		t.Fatalf("fingerprint must change after overrides file appears: %q == %q", fp1, fp2)
	}

	// Given：修改 overrides 内容（改变 size）
	if err := os.WriteFile(overridesPath, []byte("# v2 longer content here to change size\nSecAction pass\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When：第三次渲染
	d3 := mustDirectives(BuildCorazaDirectives(policy, database, "", false, 0, "lb_test"))

	// Then：指纹再次不同（size 变化）
	fp3 := extractCRSPoolFingerprint(t, d3)
	if fp2 == fp3 {
		t.Fatalf("fingerprint must change after overrides content changes: %q == %q", fp2, fp3)
	}
}

func extractCRSPoolFingerprint(t *testing.T, directives string) string {
	t.Helper()
	for _, line := range strings.Split(directives, "\n") {
		if strings.HasPrefix(line, "# crs-pool=") {
			return strings.TrimPrefix(line, "# crs-pool=")
		}
	}
	t.Fatalf("no crs-pool fingerprint line in directives:\n%s", directives)
	return ""
}

// (2026-09-10 审计):响应体缓冲(WAFCheckResponse)在 off/custom_only 下零消费
// (响应规则仅 blocking/detection Include,自定义无响应目标)——发射侧按 CRS
// 生效模式门控,避免无谓内存/CPU 缓冲。
func TestBuildCorazaDirectives_responseBodyAccessGatedByCRSMode(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want bool
	}{
		{"blocking", true},
		{"detection", true},
		{"custom_only", false},
	} {
		p := &models.SecurityPolicy{Mode: tc.mode, WAFCheckResponse: true,
			CustomRules: json.RawMessage(`[{"id":1,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`)}
		// custom_only 在有启用规则时同样发射 body processor 守卫（id:11 计分=阈值），
		// 三种模式都按真实库形态给合法值 5。
		p.AnomalyThreshold = 5
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		got := strings.Contains(directives, "SecResponseBodyAccess On")
		if got != tc.want {
			t.Fatalf("mode=%s SecResponseBodyAccess On=%v, want %v:\n%s", tc.mode, got, tc.want, directives)
		}
	}
	// off + IP 控制(引擎开):同样不缓冲
	d := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{Mode: "off", WAFCheckResponse: true,
		IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["1.2.3.4"]`}, nil, "", false, 0, "lb_test"))
	if strings.Contains(d, "SecResponseBodyAccess On") {
		t.Fatalf("off+IP控制 SecResponseBodyAccess On 应不发射:\n%s", d)
	}
}

func TestBuildCorazaDirectives_malformedCRSRuleGroupsLogsWarnAndUsesAll(t *testing.T) {
	var logBuf bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldLog) })
	policy := &models.SecurityPolicy{ID: 7, Name: "broken-groups", Mode: "blocking", AnomalyThreshold: 5, CRSRuleGroups: json.RawMessage(`{"not":"an array"`)}

	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_broken_groups"))
	if !strings.Contains(logBuf.String(), "crs_rule_groups 畸形") {
		t.Fatalf("malformed crs_rule_groups must leave a WARN trail, log:\n%s", logBuf.String())
	}
	if !strings.Contains(directives, "Include /app/waf/crs/rules/REQUEST-*.conf") {
		t.Fatalf("malformed groups must retain empty-means-all behavior:\n%s", directives)
	}

	logBuf.Reset()
	policy.CRSRuleGroups = json.RawMessage(`[]`)
	_ = mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_valid_groups"))
	if strings.Contains(logBuf.String(), "crs_rule_groups 畸形") {
		t.Fatalf("valid empty groups must not warn:\n%s", logBuf.String())
	}
}

// 畸形列 WARN 与同族三处（内联/引用名单解析失败）同口径 60s 限流：同一脏
// 策略在单次全量生成中被「规则×绑定策略」粒度重复渲染时，同窗口只放行
// 首条 WARN（脏行存续期逐条刷会淹没同窗口真实告警）。
func TestBuildCorazaDirectives_malformedJSONWarnRateLimited(t *testing.T) {
	var logBuf bytes.Buffer
	oldLog := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(oldLog) })

	groupsPolicy := &models.SecurityPolicy{ID: 900008, Name: "broken-groups-rl", Mode: "blocking", AnomalyThreshold: 5, CRSRuleGroups: json.RawMessage(`{"not":"an array"`)}
	for range 3 {
		_ = mustDirectives(BuildCorazaDirectives(groupsPolicy, nil, "", false, 0, "lb_broken_groups_rl"))
	}
	if got := strings.Count(logBuf.String(), "crs_rule_groups 畸形"); got != 1 {
		t.Fatalf("3 次渲染同脏策略 crs_rule_groups WARN=%d 条, want 1（60s 限流）:\n%s", got, logBuf.String())
	}

	logBuf.Reset()
	geoPolicy := &models.SecurityPolicy{ID: 900009, Name: "broken-geo-rl", Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`{"not":"an array"`)}
	for range 3 {
		// GeoIP 在预检渲染链求值（策略引擎对纯 GeoIP 策略产空串，不经策略渲染）
		_ = mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{geoPolicy}, 0, "lb_broken_geo_rl"))
	}
	if got := strings.Count(logBuf.String(), "geoip_countries 畸形"); got != 1 {
		t.Fatalf("3 次渲染同脏策略 geoip_countries WARN=%d 条, want 1（60s 限流）:\n%s", got, logBuf.String())
	}
}
