package services

// SECLB33-1 P0(第 33 轮审计)/ TDD 强化 §11 + R-10 引擎编译门禁:
// 配置生成类修复的验证终点是「引擎接受」——字符串形状断言不构成行为验证
// (coraza「disruptive 动作仅允许链首段」约束在文本层不可见,坏形状曾随
// v2.2.11 出厂)。本文件的测试把 BuildCorazaDirectives/buildIPPrecheckDirectives
// 的真实渲染产物直接送入 coraza v3.7.0(与 Dockerfile coraza-caddy v2.6.1
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

// compileForEngineGate 把渲染指令送入 coraza 编译。过滤三类环境依赖行:
//   - SecAuditLog <path>:引擎在 NewWAF 时打开审计日志文件(/app/logs 在
//     开发/CI 不存在)——路径可写性不是被测对象;
//   - Include <crs 路径>:CRS 文件仅存在于镜像内——引擎接受「文件缺失」
//     与否不是被测对象(镜像内由 caddy validate 覆盖全量);
//   - SecRuleUpdateActionById 949110:拦截页归因的 CRS 抬码指令——Include
//     被过滤后 949110 不存在,该指令编译必然报错(规则缺失是环境产物,
//     非被测形状);指令对 949110 的真实抬码由
//     security_block_status_test.go 的引擎行为实证覆盖(桩规则+真实事务)。
//
// 其余全部逐字送编译——我们自己发射的 SecRule/SecAction/SecMarker 形状
// 是本门禁的被测对象,零裁剪(R-8 验证源直取:指令文本来自真实渲染调用)。
func compileForEngineGate(t *testing.T, directives string) {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "Include ") ||
			strings.HasPrefix(trimmed, "SecRuleUpdateActionById ") {
			continue
		}
		kept = append(kept, line)
	}
	if _, err := coraza.NewWAF(coraza.NewWAFConfig().WithDirectives(strings.Join(kept, "\n"))); err != nil {
		t.Fatalf("coraza 引擎拒绝渲染指令:\n%v\n--- directives ---\n%s", err, strings.Join(kept, "\n"))
	}
}

// SECLB33-1 目标形状:多策略(multiPolicy=true)+信任名单+deny 侧控制——
// 链式自排除三形状必须被引擎接受(当前 deny 在续段=编译拒绝=RED)。
func TestEngineGate_multiPolicyChainedShapes(t *testing.T) {
	trust := json.RawMessage(`["10.0.0.1"]`)
	cases := map[string]*models.SecurityPolicy{
		"deny+trust":      {Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"allow+trust":     {Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"blacklist+trust": {Mode: "blocking", IPBlacklist: json.RawMessage(`["198.51.100.9"]`), IPWhitelistEnabled: true, IPWhitelist: trust},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			compileForEngineGate(t, BuildCorazaDirectives(p, nil, "", true, 0))
		})
	}
}

// 回归形状:平原形态(单策略/无信任)与预检指令必须持续被引擎接受。
func TestEngineGate_plainAndPrecheckShapes(t *testing.T) {
	trust := json.RawMessage(`["10.0.0.1"]`)
	cases := map[string]*models.SecurityPolicy{
		"single-deny+trust":   {Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust},
		"multi-deny-no-trust": {Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: false, IPWhitelist: json.RawMessage(`[]`)},
		"geoip-chain":         {Mode: "blocking", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["CN"]`)},
		"custom-chained":      {Mode: "blocking", CustomRules: json.RawMessage(`[{"name":"t","action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/admin"},{"target":"user_agent","operator":"contains","pattern":"bot"}]}]`)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			multi := strings.HasPrefix(name, "multi-")
			compileForEngineGate(t, BuildCorazaDirectives(p, nil, "", multi, 0))
		})
	}
	t.Run("precheck-trust-union", func(t *testing.T) {
		p1 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust}
		p2 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`}
		compileForEngineGate(t, buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}))
	})
}

// SEC40-B1-2（阶段化模型收紧 890000→790000）：自定义规则 DB id ≥790000 经
// 发射偏移 +10000 后撞入 GeoIP 预检段（800000-899999，buildIPPrecheckDirectives
// 逐策略链 id=800000+policyID）——同 id 冲突会使整份 coraza 配置编译失败；
// ≥890000 仍撞 CRS 保留段（900000+）。发射侧跳过并告警，不产出冲突 id。
func TestEngineGate_customRuleIDCollisionSkipped(t *testing.T) {
	p := &models.SecurityPolicy{Mode: "blocking", CustomRules: json.RawMessage(
		`[{"id":790000,"name":"collider","enabled":true,"action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`)}
	directives := BuildCorazaDirectives(p, nil, "", false, 0)
	if strings.Contains(directives, "id:800000") {
		t.Fatalf("rule with db id 790000 must be skipped (emit id 800000 collides geoip precheck space), got:\n%s", directives)
	}
	if !strings.Contains(directives, "SECURITY_RULES_END") {
		t.Fatalf("marker must survive skipped rule, got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
	// 回归形状:合法 id(790000 以下)照常发射
	pOK := &models.SecurityPolicy{Mode: "blocking", CustomRules: json.RawMessage(
		`[{"id":789999,"name":"safe","enabled":true,"action":"block","conditions":[{"target":"uri","operator":"contains","pattern":"/y"}]}]`)}
	dOK := BuildCorazaDirectives(pOK, nil, "", false, 0)
	if !strings.Contains(dOK, "id:799999") {
		t.Fatalf("rule with db id 789999 must still emit id:799999, got:\n%s", dOK)
	}
	compileForEngineGate(t, dOK)
}

// 阶段化模型（GeoIP 迁入预检）：预检含逐策略 GeoIP 链（链首 deny+skipAfter+
// chain、X-GeoIP-Loc 续段、信任续段）的新形状必须被 coraza v3.7.0 接受——
// 「disruptive 动作仅允许链首段」约束只经编译可见（R-10）。
func TestEngineGate_precheckGeoipChainShapes(t *testing.T) {
	p1 := &models.SecurityPolicy{
		ID: 42, Mode: "off", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`),
		IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["1.2.3.4","10.0.0.0/8"]`),
	}
	p2 := &models.SecurityPolicy{
		ID: 43, Mode: "detection", GeoIPMode: "allow", GeoIPCountries: json.RawMessage(`["江苏"]`),
	}
	directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})
	if !strings.Contains(directives, "id:800042,") || !strings.Contains(directives, "id:800043,") {
		t.Fatalf("precheck must carry per-policy geoip chains, got:\n%s", directives)
	}
	compileForEngineGate(t, directives)
}

// SEC41-3（第 41 轮审计）：引擎门禁覆盖此前未送编译的六个发射形状。每个
// 用例的断言=真实渲染产物被 coraza v3.7.0 NewWAF 接受（R-10 天然满足——
// 与既有门禁同一 compileForEngineGate 通道）。
func TestEngineGate_modeAndControlShapes(t *testing.T) {
	// ① detection 的 id:6 DetectionOnly 切换行
	t.Run("detection-id6-switch", func(t *testing.T) {
		directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "detection"}, nil, "", false, 0)
		if !strings.Contains(directives, `SecAction "id:6,phase:1,nolog,pass,ctl:ruleEngine=DetectionOnly"`) {
			t.Fatalf("detection mode must emit id:6 switch:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ② bypass id:3（ctl:ruleEngine=Off,ctl:auditEngine=Off）+ bypass 占位后
	// 信任名单改 id:5 的 DetectionOnly 行
	t.Run("bypass-id3-engine-off", func(t *testing.T) {
		p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "bypass", IPACLList: `["198.51.100.9"]`,
			IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
		directives := BuildCorazaDirectives(p, nil, "", false, 0)
		if !strings.Contains(directives, `id:3,phase:1,pass,nolog,ctl:ruleEngine=Off,ctl:auditEngine=Off`) {
			t.Fatalf("bypass mode must emit id:3 engine-off rule:\n%s", directives)
		}
		if !strings.Contains(directives, `id:5,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly`) {
			t.Fatalf("trust after bypass must emit id:5 DetectionOnly rule:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ③ id:900 异常阈值 SecAction（AnomalyThreshold>0）
	t.Run("anomaly-threshold-id900", func(t *testing.T) {
		directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking", AnomalyThreshold: 12}, nil, "", false, 0)
		if !strings.Contains(directives, `id:900,phase:1,nolog,pass,setvar:tx.inbound_anomaly_score_threshold=12`) {
			t.Fatalf("AnomalyThreshold>0 must emit id:900 SecAction:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ④ 作用域排除 ctl id:2000000+（夹具参照 crs_exclusion_scope_test.go：
	// 组 42 在索引夹具中含 942100/942550 两条 → 逐 ID 运行时 ctl）
	t.Run("scoped-exclusion-ctl", func(t *testing.T) {
		seedCRSRuleIndexFixture(t)
		p := &models.SecurityPolicy{Mode: "blocking",
			CRSExcludedRules: json.RawMessage(`[{"target":"42","scope":"ip","ips":"1.1.1.1"}]`)}
		directives := BuildCorazaDirectives(p, nil, "", false, 0)
		if !strings.Contains(directives, `id:2000001,phase:1,pass,nolog,ctl:ruleRemoveById=942100`) {
			t.Fatalf("scoped exclusion must emit 2000000+ ctl rules:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ⑤ 预检双 allow 不相交（交集为空）的恒拒 @rx .* 形状
	t.Run("precheck-disjoint-allow-constant-deny", func(t *testing.T) {
		p1 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`}
		p2 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["5.6.7.8"]`}
		directives := buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2})
		if !strings.Contains(directives, `SecRule REMOTE_ADDR "@rx .*" "id:7,phase:1,deny`) {
			t.Fatalf("disjoint allow lists must emit constant-deny @rx .* rule:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ⑥ SecRequestBodyLimit 追加行（buildWafHandlerWithPolicy 在
	// BuildCorazaDirectives 产物尾部拼接，门禁直调 BuildCorazaDirectives 不经
	// 此——本用例走上层取 handler.directives 送编译）
	t.Run("request-body-limit-appended", func(t *testing.T) {
		handler := buildWafHandlerWithPolicy("lb_gate", &models.SecurityPolicy{Mode: "blocking"}, nil, "", false, 0, 8)
		if handler == nil {
			t.Fatal("blocking policy must yield a waf handler")
		}
		directives, ok := handler["directives"].(string)
		if !ok || !strings.Contains(directives, "SecRequestBodyLimit 8388608\n") {
			t.Fatalf("8MB body limit must append SecRequestBodyLimit 8388608, got:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
}

// 拦截页按触发策略归因（合成中断码 481+）：blockStatus>0 的新发射形状必须
// 被引擎接受（R-10——status 动作在链首段的合法性、SecRuleUpdateActionById
// 语法均不能仅靠字符串断言）。CRS 抬码指令的真实生效由
// security_block_status_test.go 的引擎行为实证覆盖；此处验证渲染产物编译。
func TestEngineGate_blockStatusSyntheticShapes(t *testing.T) {
	// ① 链式自排除 + 合成码（多策略+信任+deny，链首 status:481）
	t.Run("chained-trust-exclusion-lifted", func(t *testing.T) {
		p := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`,
			IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["10.0.0.1"]`)}
		directives := BuildCorazaDirectives(p, nil, "", true, 481)
		if !strings.Contains(directives, `id:2,phase:1,deny,status:481,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END,chain`) {
			t.Fatalf("chained head must carry status:481:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ② 自定义规则 deny 抬码（GeoIP 已迁预检——策略引擎零 GeoIP 段；预检
	// GeoIP 链形状由 TestEngineGate_precheckGeoipChainShapes 覆盖）
	t.Run("custom-lifted-and-geoip-absent", func(t *testing.T) {
		p := &models.SecurityPolicy{Mode: "blocking", GeoIPMode: "deny", GeoIPCountries: json.RawMessage(`["海外"]`),
			CustomRules: json.RawMessage(`[{"id":11,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/admin"}]}]`)}
		directives := BuildCorazaDirectives(p, nil, "", false, 482)
		if strings.Contains(directives, "msg:'GeoIP 区域拦截'") {
			t.Fatalf("policy engine must not emit geoip rules (moved to precheck):\n%s", directives)
		}
		if !strings.Contains(directives, `deny,status:482,log,setvar:`) {
			t.Fatalf("custom block rule must carry status:482:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
	// ③ CRS 抬码指令形状（949 夹具文件存在 → 发射；门禁过滤该指令行——
	// Include 被过滤后 949110 不存在，编译必然报错是环境产物非被测形状）
	t.Run("crs-949-lift-emitted-and-compilable", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "rules"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "rules", "REQUEST-949-BLOCKING-EVALUATION.conf"), []byte("# stub"), 0o644); err != nil {
			t.Fatal(err)
		}
		useCRSDirectivesDir(t, dir)
		directives := BuildCorazaDirectives(&models.SecurityPolicy{Mode: "blocking"}, nil, "", false, 481)
		if !strings.Contains(directives, `SecRuleUpdateActionById 949110 "deny,status:481"`) {
			t.Fatalf("949 file present must emit CRS status lift:\n%s", directives)
		}
		compileForEngineGate(t, directives)
	})
}
