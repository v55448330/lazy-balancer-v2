package services

// / TDD 强化 §11 + 引擎编译门禁
// 配置生成类修复的验证终点是「引擎接受」——字符串形状断言不构成行为验证
// (coraza「disruptive 动作仅允许链首段」约束在文本层不可见,坏形状曾随
// v2.2.11 出厂)。本文件的测试把 BuildCorazaDirectives/buildIPPrecheckDirectives
// 的真实渲染产物直接送入 coraza v3.8.1(与 Dockerfile coraza-caddy v2.6.2
// 同版)编译——编译拒绝即测试失败,字符串测试无法覆盖的引擎约束在此拦截。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

// compileForEngineGate 把渲染指令送入 coraza 编译。过滤四类环境依赖行:
//   - SecAuditLog <path>:引擎在 NewWAF 时打开审计日志文件(/app/logs 在
//     开发/CI 不存在)——路径可写性不是被测对象;
//   - SecAuditLogType lbfile:审计写插件按名注册（caddygeoip auditwriter.go
//     init），仅在 xcaddy 构建的 Caddy 二进制内可用——主模块测试二进制未
//     链入该插件，GetWriter("lbfile") 必然报「invalid logger」;插件注册与
//     `SecAuditLogType lbfile` 的编译+写盘全链路由 caddygeoip 的
//     TestAuditWriter_registeredAndInjectsLateTiming 端到端钉住;
//   - Include <crs 路径>:CRS 文件仅存在于镜像内——引擎接受「文件缺失」
//     与否不是被测对象(镜像内由 caddy validate 覆盖全量);
//   - SecRuleUpdateActionById 949110/959100:拦截页归因的 CRS 出入站抬码
//     指令——Include 被过滤后 949110/959100 不存在,该指令编译必然报错
//     （规则缺失是环境产物,非被测形状）;指令对 949110 的真实抬码由
//     security_block_status_test.go 的引擎行为实证覆盖(桩规则+真实事务)；
//     抬码对象存在性与 Include 全链路由本文件
//     TestEngineGate_crsFixtureTreeCompiles 的夹具树编译覆盖。
//
// 其余全部逐字送编译——我们自己发射的 SecRule/SecAction/SecMarker 形状
// 是本门禁的被测对象,零裁剪( 验证源直取:指令文本来自真实渲染调用)。
func compileForEngineGate(t *testing.T, directives string) {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "SecAuditLogType ") ||
			strings.HasPrefix(trimmed, "Include ") ||
			strings.HasPrefix(trimmed, "SecRuleUpdateActionById ") {
			continue
		}
		kept = append(kept, line)
	}
	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n"))); err != nil {
		t.Fatalf("coraza 引擎拒绝渲染指令:\n%v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
	}
}

// 目标形状:多策略(multiPolicy=true)+信任名单+deny 侧控制——
// 链式自排除三形状必须被引擎接受(当前 deny 在续段=编译拒绝=RED)。
func TestEngineGate_multiPolicyChainedShapes(t *testing.T) {
	trust := json.RawMessage(`["10.0.0.1"]`)
	cases := map[string]*models.SecurityPolicy{
		"deny+trust":      {AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"allow+trust":     {AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"blacklist+trust": {AnomalyThreshold: 5, Mode: "blocking", IPBlacklist: json.RawMessage(`["198.51.100.9"]`), IPWhitelistEnabled: true, IPWhitelist: trust},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test")))
		})
	}
}

// 回归形状:平原形态(单策略/无信任)与预检指令必须持续被引擎接受。
func TestEngineGate_plainAndPrecheckShapes(t *testing.T) {
	trust := json.RawMessage(`["10.0.0.1"]`)
	cases := map[string]*models.SecurityPolicy{
		"single-deny+trust":   {AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"multi-deny-no-trust": {AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`[]`)},
		"geoip-chain":         {AnomalyThreshold: 5, Mode: "blocking", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)},
		"custom-chained":      {AnomalyThreshold: 5, Mode: "blocking", CustomRules: json.RawMessage(`[{"name":"t","action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/admin"},{"target":"user_agent","operator":"contains","pattern":"bot"}]}]`)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			multi := strings.HasPrefix(name, "multi-")
			compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(p, nil, "", multi, 0, "lb_test")))
		})
	}
	t.Run("precheck-trust-union", func(t *testing.T) {
		p1 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust}
		p2 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`}
		compileForEngineGate(t, mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test")))
	})
}

// （阶段化模型收紧 890000→790000）：自定义规则 DB id ≥790000 经
// 发射偏移 +10000 后撞入 GeoIP 预检段（800000-899999，buildIPPrecheckDirectives
// 逐策略链 id=800000+policyID）——同 id 冲突会使整份 coraza 配置编译失败；
// ≥890000 仍撞 CRS 保留段（900000+）。发射侧跳过并告警，不产出冲突 id。
func TestEngineGate_customRuleIDCollisionSkipped(t *testing.T) {
	p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CustomRules: json.RawMessage(
		`[{"id":790000,"name":"collider","enabled":true,"action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`)}
	directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
	if strings.Contains(directives, "id:800000") {
		t.Fatalf("rule with db id 790000 must be skipped (emit id 800000 collides geoip precheck space), got:\n%s", directives)
	}
	if !strings.Contains(directives, "SECURITY_RULES_END") {
		t.Fatalf("marker must survive skipped rule, got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
	// 回归形状:合法 id(790000 以下)照常发射
	pOK := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", CustomRules: json.RawMessage(
		`[{"id":789999,"name":"safe","enabled":true,"action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/y"}]}]`)}
	dOK := mustDirectives(BuildCorazaDirectives(pOK, nil, "", false, 0, "lb_test"))
	if !strings.Contains(dOK, "id:799999") {
		t.Fatalf("rule with db id 789999 must still emit id:799999, got:\n%s", dOK)
	}
	compileForEngineGate(t, dOK)
}

// 阶段化模型（GeoIP 迁入预检）：预检含逐策略 GeoIP 链（链首 deny+skipAfter+
// chain、X-LB-GeoIP-Loc 续段、信任续段）的新形状必须被 coraza v3.8.1 接受——
// 「disruptive 动作仅允许链首段」约束只经编译可见。
func TestEngineGate_precheckGeoipChainShapes(t *testing.T) {
	p1 := &models.SecurityPolicy{
		ID: 42, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`),
		IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["1.2.3.4","10.0.0.0/8"]`),
	}
	p2 := &models.SecurityPolicy{
		ID: 43, Mode: "detection", GeoIPMode: "allow", GeoIPCountries: json.RawMessage(`["江苏"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))
	if !strings.Contains(directives, "id:800042,") || !strings.Contains(directives, "id:800043,") {
		t.Fatalf("precheck must carry per-policy geoip chains, got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// 引擎门禁覆盖此前未送编译的六个发射形状。每个
// 用例的断言=真实渲染产物被 coraza v3.8.1 NewWAF 接受（天然满足——
// 与既有门禁同一 compileForEngineGate 通道）。
func TestEngineGate_modeAndControlShapes(t *testing.T) {
	// ① detection 的 id:6 DetectionOnly 切换行
	t.Run("detection-id6-switch", func(t *testing.T) {
		directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "detection"}, nil, "", false, 0, "lb_test"))
		if !strings.Contains(directives, `SecAction "id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly"`) {
			t.Fatalf("detection mode must emit id:6 switch:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ② 绕过 id:3（ctl:ruleEngine=Off,ctl:auditEngine=Off）+ 绕过 占位后
	// 信任名单改 id:5 的 DetectionOnly 行
	t.Run("绕过-id3-engine-off", func(t *testing.T) {
		p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "绕过", IPACLList: `["198.51.100.9"]`,
			IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		if !strings.Contains(directives, `id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off`) {
			t.Fatalf("绕过 mode must emit id:3 engine-off rule:\n%s", directives)
		}
		if !strings.Contains(directives, `id:5,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly`) {
			t.Fatalf("trust after 绕过 must emit id:5 DetectionOnly rule:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ③ id:900 异常阈值 SecAction（AnomalyThreshold>0）
	t.Run("anomaly-threshold-id900", func(t *testing.T) {
		directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking", AnomalyThreshold: 12}, nil, "", false, 0, "lb_test"))
		if !strings.Contains(directives, `id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=12`) {
			t.Fatalf("AnomalyThreshold>0 must emit id:900 SecAction:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ④ 作用域排除 ctl id:2000000+（夹具参照 crs_exclusion_scope_test.go：
	// 组 42 在索引夹具中含 942100/942550 两条 → 逐 ID 运行时 ctl）
	t.Run("scoped-exclusion-ctl", func(t *testing.T) {
		seedCRSRuleIndexFixture(t)
		p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking",
			CRSExcludedRules: json.RawMessage(`[{"target":"42","scope":"ip","ips":"1.1.1.1"}]`)}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		if !strings.Contains(directives, `id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100`) {
			t.Fatalf("scoped exclusion must emit 2000000+ ctl rules:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ⑤ 预检双 allow 不相交（交集为空）的恒拒 @rx .* 形状
	t.Run("precheck-disjoint-allow-constant-deny", func(t *testing.T) {
		p1 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`}
		p2 := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["5.6.7.8"]`}
		directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}, 0, "lb_test"))
		if !strings.Contains(directives, `SecRule REMOTE_ADDR "@rx .*" "id:7,phase:1,deny`) {
			t.Fatalf("disjoint allow lists must emit constant-deny @rx .* rule:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ⑥ SecRequestBodyLimit 追加行（buildWafHandlerWithPolicy 在
	// BuildCorazaDirectives 产物尾部拼接，门禁直调 BuildCorazaDirectives 不经
	// 此——本用例走上层取 handler.directives 送编译）
	t.Run("request-body-limit-appended", func(t *testing.T) {
		handler, wafErr := buildWafHandlerWithPolicy("lb_gate", &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 0, 8, nil)
		if wafErr != nil {
			t.Fatalf("buildWafHandlerWithPolicy err=%v", wafErr)
		}
		if handler == nil {
			t.Fatal("blocking policy must yield a waf handler")
		}
		directives, ok := handler["directives"].(string)
		if !ok || !strings.Contains(directives, "SecRequestBodyLimit 8388608\n") {
			t.Fatalf("8MB body limit must append SecRequestBodyLimit 8388608, got:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ⑦ GREEN 形状：custom_only+仅 IP 控制（零启用自定义
	// 规则）——body processor 规则 id:9/10/11 不再发射，渲染产物仍须被
	// coraza NewWAF 接受（SecRule 发射面变更的验证终点是引擎编译）。
	t.Run("custom-only-ip-control-no-body-processors", func(t *testing.T) {
		p := &models.SecurityPolicy{Mode: "custom_only", Enabled: true,
			IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["10.0.0.0/8"]`}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		for _, id := range []string{"id:9,", "id:10,", "id:11,"} {
			if strings.Contains(directives, id) {
				t.Fatalf("custom_only+仅 IP 控制不得发射 body processor 死指令 %s:\n%s", id, directives)
			}
		}
		compileForEngineGate(t, directives)
	})
}

// 拦截页按触发策略归因（合成中断码 481+）：blockStatus>0 的新发射形状必须
// 被引擎接受（status 动作在链首段的合法性、SecRuleUpdateActionById
// 语法均不能仅靠字符串断言）。CRS 抬码指令的真实生效由
// security_block_status_test.go 的引擎行为实证覆盖；此处验证渲染产物编译。
func TestEngineGate_blockStatusSyntheticShapes(t *testing.T) {
	// ① 链式自排除 + 合成码（多策略+信任+deny，链首 status:481）
	t.Run("chained-trust-exclusion-lifted", func(t *testing.T) {
		p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`,
			IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", true, 481, "lb_test"))
		if !strings.Contains(directives, `id:2,phase:1,deny,status:481,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END,chain`) {
			t.Fatalf("chained head must carry status:481:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ② 自定义规则 deny 抬码（GeoIP 已迁预检——策略引擎零 GeoIP 段；预检
	// GeoIP 链形状由 TestEngineGate_precheckGeoipChainShapes 覆盖）
	t.Run("custom-lifted-and-geoip-absent", func(t *testing.T) {
		p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`),
			CustomRules: json.RawMessage(`[{"id":11,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}]}]`)}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 482, "lb_test"))
		if strings.Contains(directives, "msg:'GeoIP 区域拦截'") {
			t.Fatalf("policy engine must not emit geoip rules (moved to precheck):\n%s", directives)
		}
		if !strings.Contains(directives, `deny,status:482,log,setvar:`) {
			t.Fatalf("custom block rule must carry status:482:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ③ CRS 抬码指令发射形状（949 夹具文件存在 → 发射）。该子用例只断言
	// 指令行存在：门禁把 SecRuleUpdateActionById 行过滤掉（Include 被过滤后
	// 949110 不存在，送编译必然报环境错误），因此这里不构成「抬码指令可编译」
	// 证据——真实抬码行为由 security_block_status_test.go 的桩规则事务覆盖，
	// 抬码对象存在性由本文件 TestEngineGate_crsFixtureTreeCompiles 覆盖。
	t.Run("crs-949-lift-emitted", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules", "REQUEST-949-BLOCKING-EVALUATION.conf"), []byte("# stub"), 0o644); err != nil {
			t.Fatal(err)
		}
		useCRSDirectivesDir(t, dir)
		directives := mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 481, "lb_test"))
		if !strings.Contains(directives, `SecRuleUpdateActionById 949110 "deny,status:481"`) {
			t.Fatalf("949 file present must emit CRS status lift:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
}

func TestEngineGate_precheckGeoIPTrustContinuationExemptsTrustedIP(t *testing.T) {
	// Given a three-segment GeoIP chain: private-IP guard, location, then NOT trust.
	policy := &models.SecurityPolicy{
		ID: 77, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`),
		IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["203.0.113.9"]`),
	}
	directives := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_geoip_trust"))
	if !strings.Contains(directives, `X-LB-GeoIP-Loc "@rx ^(?:海外)$" "t:none,chain"`) {
		t.Fatalf("location segment must chain to the trust continuation:\n%s", directives)
	}
	compileForEngineGate(t, directives)
	waf := newPrecheckBehaviorWAF(t, directives)
	run := func(clientIP string) bool {
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection(clientIP, 12345, "127.0.0.1", 443)
		tx.ProcessURI("/", "GET", "HTTP/1.1")
		tx.AddRequestHeader("X-LB-GeoIP-Loc", "海外")
		return tx.ProcessRequestHeaders() != nil
	}

	// When/Then the trusted address fails the negated third segment and is not denied.
	if run("203.0.113.9") {
		t.Fatal("trusted IP must be exempted by the third chain segment")
	}
	// Regression shape: an untrusted overseas address still reaches the chain-head deny.
	if !run("198.51.100.7") {
		t.Fatal("untrusted overseas IP must be denied")
	}

	// Without the optional third segment, the location segment must terminate the chain.
	policy.IPWhitelist = json.RawMessage(`[]`)
	withoutTrust := mustDirectives(buildIPPrecheckDirectives([]*models.SecurityPolicy{policy}, 403, "lb_geoip_no_trust"))
	if strings.Contains(withoutTrust, `X-LB-GeoIP-Loc "@rx ^(?:海外)$" "t:none,chain"`) {
		t.Fatalf("location segment must not chain to a missing trust segment:\n%s", withoutTrust)
	}
	compileForEngineGate(t, withoutTrust)
}

func TestEngineGate_trustOnlyOffAndCustomOnlyDoNotEmitIdleWAF(t *testing.T) {
	trust := json.RawMessage(`["203.0.113.9"]`)
	enabledCustom := json.RawMessage(`[{"id":1,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`)
	// 启用但发射侧必跳过（空条件）：摘要按 customRuleEmittable 判 false，
	// 发射侧必须同判据——否则引擎为一条永不发射的规则而开（且摘要少报
	// 引擎实际承载的信任规则能力）。
	unemittableCustom := json.RawMessage(`[{"id":55,"name":"bad","enabled":true,"action":"block","score":5,"conditions":[]}]`)
	cases := []struct {
		name       string
		policy     *models.SecurityPolicy
		wantEngine bool
	}{
		{name: "off trust only", policy: &models.SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: trust}},
		{name: "custom only trust only", policy: &models.SecurityPolicy{Mode: "custom_only", IPWhitelistEnabled: true, IPWhitelist: trust}},
		// anomaly_threshold 是类型①值型列（写侧枚举 + 启动回填），真实库行恒为正；
		// custom_only 分支的 body processor 守卫计分对它做 fail-visible 门，
		// 故夹具按真实形态给 5（零值不是可达的生产形状）。
		{name: "custom only trust and custom", policy: &models.SecurityPolicy{Mode: "custom_only", AnomalyThreshold: 5, IPWhitelistEnabled: true, IPWhitelist: trust, CustomRules: enabledCustom}, wantEngine: true},
		{name: "custom only trust and unemittable custom", policy: &models.SecurityPolicy{Mode: "custom_only", IPWhitelistEnabled: true, IPWhitelist: trust, CustomRules: unemittableCustom}},
		{name: "off trust and ACL", policy: &models.SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: trust, IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.7"]`}, wantEngine: true},
		{name: "off trust and parked custom", policy: &models.SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: trust, CustomRules: enabledCustom}},
		{name: "stage0 trust", policy: &models.SecurityPolicy{Mode: "off", PolicyType: models.PolicyTypeStage0, IPWhitelistEnabled: true, IPWhitelist: trust}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			directives := mustDirectives(BuildCorazaDirectives(tc.policy, nil, "", false, 0, "lb_idle_trust"))
			if got := directives != ""; got != tc.wantEngine {
				t.Fatalf("engine emitted=%v, want %v:\n%s", got, tc.wantEngine, directives)
			}
			if got := SecurityPolicyHasIPControl(tc.policy); got != tc.wantEngine {
				t.Fatalf("SecurityPolicyHasIPControl=%v, want %v", got, tc.wantEngine)
			}
			if tc.wantEngine {
				compileForEngineGate(t, directives)
			}
		})
	}
}

// crsRemovalTouchesInfra 报告一条 SecRuleRemoveById 目标是否触及基础设施组
// （901 初始化 / 949 请求评估 / 959 响应评估）——引擎行为断言之外的形状门。
func crsRemovalTouchesInfra(target string) bool {
	lo, hi, ok := crsNumericIDRange(strings.TrimSpace(target))
	if !ok {
		return false
	}
	for _, infra := range []struct{ lo, hi int }{
		{901000, 901999}, {949000, 949999}, {959000, 959999},
	} {
		if lo <= infra.hi && hi >= infra.lo {
			return true
		}
	}
	return false
}

// 基础设施组（901/949/959）缺失即静默失效：blocking 策略的 CRS 排除面不得
// 摘除评估组，否则评分永不评估、全部命中退化为 logged。验证终点=引擎级：
// 渲染产物里不得出现触及基础设施段的 SecRuleRemoveById，且真实事务仍被
// 949110 拦截（负对照证明「摘除后确实不再拦截」，即该守卫不是纸面规则）。
func TestEngineGate_infraCRSExclusionsCannotDisableBlocking(t *testing.T) {
	dir := t.TempDir()
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"REQUEST-901-INITIALIZATION.conf",
		"REQUEST-949-BLOCKING-EVALUATION.conf",
		"RESPONSE-959-BLOCKING-EVALUATION.conf",
		"REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
	} {
		if err := os.WriteFile(filepath.Join(rulesDir, name), []byte("# stub"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	useCRSDirectivesDir(t, dir)

	removalLines := func(directives string) []string {
		var out []string
		for _, line := range strings.Split(directives, "\n") {
			if strings.HasPrefix(line, "SecRuleRemoveById ") {
				out = append(out, strings.TrimSpace(strings.TrimPrefix(line, "SecRuleRemoveById ")))
			}
		}
		return out
	}

	infraTargets := []string{
		"01", "49", "59",
		"901100", "949110", "959100",
		"REQUEST-901-INITIALIZATION.conf",
		"REQUEST-949-BLOCKING-EVALUATION.conf",
		"RESPONSE-959-BLOCKING-EVALUATION.conf",
		"900000-902000", "948000-950000", "959500-960000",
	}
	for _, target := range infraTargets {
		t.Run("skip-"+target, func(t *testing.T) {
			raw, err := json.Marshal([]map[string]string{{"target": target, "scope": "all"}})
			if err != nil {
				t.Fatal(err)
			}
			p := &models.SecurityPolicy{ID: 7, AnomalyThreshold: 5, Mode: "blocking", CRSExcludedRules: raw}
			directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
			for _, removed := range removalLines(directives) {
				if crsRemovalTouchesInfra(removed) {
					t.Fatalf("基础设施组排除不得发射 SecRuleRemoveById %s（blocking 会静默退化为仅记录）:\n%s", removed, directives)
				}
			}
			compileForEngineGate(t, directives)
		})
	}

	// 非基础设施排除照常发射（回归形状）。
	t.Run("keep-942", func(t *testing.T) {
		raw, _ := json.Marshal([]map[string]string{{"target": "942100", "scope": "all"}})
		p := &models.SecurityPolicy{ID: 7, AnomalyThreshold: 5, Mode: "blocking", CRSExcludedRules: raw}
		directives := mustDirectives(BuildCorazaDirectives(p, nil, "", false, 0, "lb_test"))
		if !strings.Contains(directives, "SecRuleRemoveById 942100") {
			t.Fatalf("非基础设施排除必须照常发射:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})

	// 引擎行为：949110 在场时事务被拦截；显式摘除后不再拦截（负对照）。
	stub := "SecRuleEngine On\n" +
		`SecRule REQUEST_URI "@rx .*" "id:949110,phase:1,deny,log"` + "\n"
	interrupts := func(directives string) bool {
		waf, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(directives))
		if err != nil {
			t.Fatalf("engine rejected directives: %v\n%s", err, directives)
		}
		tx := waf.NewTransaction()
		defer func() { _ = tx.Close() }()
		tx.ProcessConnection("203.0.113.9", 5555, "127.0.0.1", 80)
		tx.ProcessURI("/anything", "GET", "HTTP/1.1")
		return tx.ProcessRequestHeaders() != nil
	}
	if !interrupts(stub) {
		t.Fatal("基线：949110 deny 必须拦截（否则断言无意义）")
	}
	if interrupts(stub + "SecRuleRemoveById 949110\n") {
		t.Fatal("负对照：显式摘除 949110 后必须不再拦截（证明基础设施排除确实会废掉 blocking）")
	}
}

// custom_only 模式的 body processor 守卫计分（id:11 setvar +<阈值>）同样必须
// fail-visible：anomaly_threshold<=0（NULL 哨兵/带外直写负值）曾直接拼进 setvar，
// 负值渲染成 `=+-5`，coraza 拒绝整份配置——保存/重载失败且报错指向引擎而非
// 字段。引擎是唯一裁判：合法阈值必须编译通过，非法阈值必须在渲染期报错。
func TestEngineGate_customOnlyBodyProcessorThreshold(t *testing.T) {
	customRules := json.RawMessage(`[{"id":1,"name":"t","enabled":true,"action":"block","score":5,"conditions":[{"target":"body","operator":"contains","pattern":"secret"}]}]`)
	// 正形状：合法阈值下 id:9/10/11 与自定义规则共同被引擎接受。
	compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{
		Mode: "custom_only", AnomalyThreshold: 5, CustomRules: customRules,
	}, nil, "", false, 0, "lb_test")))

	// 故障形状：<=0 必须返回 error（不得渲染 `=+-5` 交给引擎）。
	directives, err := BuildCorazaDirectives(&models.SecurityPolicy{
		Mode: "custom_only", AnomalyThreshold: -5, CustomRules: customRules,
	}, nil, "", false, 0, "lb_test")
	if err == nil {
		t.Fatalf("custom_only + anomaly_threshold=-5 必须渲染期报错，实际产物:\n%s", directives)
	}
	if strings.Contains(directives, "setvar:tx.inbound_anomaly_score_pl1=+-") {
		t.Fatalf("负阈值被拼进 setvar: %s", directives)
	}
}
