package services

// 始终发射收敛钉测（2026-10-15 用户裁定）：ipListRuleOperand 空名单投影空
// 文件恒发射 @ipListFast（空集=匹配器永不命中=与无规则语义等价），上层
// 「全空则不发该 SecRule」的内容门控对发射面 flag 为真实 opt-in 的热路径
// 可变名单随之一并收敛（R-12 同族扫描清单）——空↔非空降为纯内容变化全走
// 投影热路径。收敛范围实证边界：
//   · deny·bypass ACL：ip_acl_enabled 表默认 0，flag 为刻意 opt-in → 收敛；
//   · stage0 保留检测：trust_detection 为刻意 opt-in → 收敛（id:12）；
// 不可收敛例外（语义钉测锁定现状）：
//   · 信任名单：ip_whitelist_enabled 表默认值即 1（非刻意 opt-in，flag 门控
//     会使全部默认策略/站点凭空获得引擎与信任规则——门禁钉测实证），维持
//     内容门控（空↔非空仍走全量链）；
//   · allow 模式 ACL（!@ipListFast 否定算子）：空集=恒命中=全拒，与「无规则
//     =全放」语义不等价且有全站锁死风险——维持内容门控；
//   · 遗留黑名单 ip_blacklist：内联字段仅经策略保存（全量链）变化，收敛无
//     热路径收益——维持内容门控。

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"lazy-balancer-v2/internal/models"
)

// R-10 引擎编译门禁（RED 先行）：始终发射收敛引入的新形状=「@ipListFast 指
// 向空投影文件」的 SecRule。coraza 算子构建期新鲜加载该文件——当前实现拒绝
// 空文件（名单为空 error）→ 本测试 RED；wafiplist 收敛后引擎必须接受。
// 字符串形状断言（上方各钉测）不构成行为验证，本门禁为验证终点。
func TestEngineGate_ipListFastEmptyFileOperatorAccepted(t *testing.T) {
	path, err := writeIPListFile("u-enginegate-empty", nil)
	if err != nil {
		t.Fatalf("空投影: %v", err)
	}
	directives := fmt.Sprintf("SecRuleEngine On\nSecRule REMOTE_ADDR \"@ipListFast %s\" \"id:2,phase:1,deny,status:403,log,msg:'IP 黑名单拒绝',skipAfter:SECURITY_RULES_END\"\nSecMarker SECURITY_RULES_END\n", path)
	compileForEngineGate(t, directives)
}

// R-10 引擎编译门禁（真实渲染产物）：空名单恒发射的全部新形状逐字送 coraza
// 编译——策略引擎（空 deny ACL/空信任/stage0 空 id:12）与预检合并段（空并集）。
func TestEngineGate_alwaysEmitRenderedShapes(t *testing.T) {
	t.Run("engine-empty-deny-acl", func(t *testing.T) {
		compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`}, nil, "", false, 0, "lb_test")))
	})
	t.Run("engine-empty-trust", func(t *testing.T) {
		compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`[]`)}, nil, "", false, 0, "lb_test")))
	})
	t.Run("engine-stage0-detection-empty", func(t *testing.T) {
		compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(&models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}, nil, "", false, 0, "lb_test", []string{})))
	})
	t.Run("engine-empty-multi-chain", func(t *testing.T) {
		// 多策略链式自排除（negTrustOperand）在 deny 名单为空时指向空投影
		// 文件——链形状必须被引擎接受（SECLB33-1 同门禁口径）。信任名单非空
		// 使链排除段保持既有形状（信任不收敛）。
		p := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`, IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`["198.51.100.7"]`)}
		compileForEngineGate(t, mustDirectives(BuildCorazaDirectives(p, nil, "", true, 0, "lb_test")))
	})
	t.Run("precheck-empty-unions", func(t *testing.T) {
		policies := []*models.SecurityPolicy{
			{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`},
			{PolicyType: models.PolicyTypeStage0, IPWhitelistEnabled: true, TrustDetection: true, IPWhitelist: json.RawMessage(`[]`)},
		}
		directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
		if err != nil {
			t.Fatal(err)
		}
		compileForEngineGate(t, directives)
	})
}

// deny ACL 开启且合并集为空：引擎开启、id:2 恒发射指向空投影文件（p0-acl.txt）。
func TestBuildCorazaDirectives_emptyDenyACLAlwaysEmits(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if !strings.Contains(directives, "SecRuleEngine On") {
		t.Fatalf("deny ACL 开启（空名单）必须开启引擎:\n%s", directives)
	}
	if !strings.Contains(directives, `"id:2,phase:1,deny`) || !strings.Contains(directives, "@ipListFast ") {
		t.Fatalf("deny ACL 开启（空名单）必须恒发射 id:2 @ipListFast:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "-acl"); got != "" {
		t.Fatalf("空 deny 名单文件内容=%q, want 空文件", got)
	}
}

// 信任名单开启且合并集为空（不收敛例外）：ip_whitelist_enabled 表默认值=1
// 非刻意 opt-in——维持内容门控，空信任不发射规则不开引擎（门禁钉测实证的
// 发射面边界）。
func TestBuildCorazaDirectives_emptyTrustKeepsContentGate(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "off", IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`[]`)}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if directives != "" {
		t.Fatalf("信任开启（空名单，默认 flag 非 opt-in）不得发射规则/开引擎: %q", directives)
	}
}

// stage0 保留检测策略在（并集可空）：id:12 恒发射——发射面 flag 与内容解耦
// （变参非 nil 空切片=策略在），空↔非空纯内容变化走热路径。
func TestBuildCorazaDirectives_stage0DetectionEmptyAlwaysEmitsID12(t *testing.T) {
	policy := &models.SecurityPolicy{AnomalyThreshold: 5, Mode: "blocking"}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test", []string{}))
	if !strings.Contains(directives, `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("保留检测策略在（空并集）必须恒发射 id:12:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-trust12"); got != "" {
		t.Fatalf("空保留检测文件=%q, want 空文件", got)
	}
}

// allow 模式空名单：P1-SEC-02 失败关闭——必须发射拒绝规则（否定算子命中
// 全部来源），不得静默放行。
func TestBuildCorazaDirectives_emptyAllowACLKeepsContentGate(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "off", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if !strings.Contains(directives, "!@ipListFast") || !strings.Contains(directives, "deny") {
		t.Fatalf("allow 模式空名单必须发射失败关闭拒绝规则: %q", directives)
	}
}

// 遗留黑名单空（内联字段非热路径）：维持内容门控——无 id:4、不开引擎。
func TestBuildCorazaDirectives_emptyBlacklistKeepsContentGate(t *testing.T) {
	policy := &models.SecurityPolicy{Mode: "off", IPBlacklist: json.RawMessage(`[]`)}
	directives := mustDirectives(BuildCorazaDirectives(policy, nil, "", false, 0, "lb_test"))
	if directives != "" || strings.Contains(directives, "id:4,") {
		t.Fatalf("黑名单空（内容门控保留）不得发射 id:4/开引擎: %q", directives)
	}
}

// 预检合并段：deny ACL 开启且并集为空 → id:2 恒发射指向空 u-deny 文件。
func TestBuildIPPrecheckDirectives_emptyDenyACLAlwaysEmits(t *testing.T) {
	policies := []*models.SecurityPolicy{{IPACLEnabled: true, IPACLMode: "deny", IPACLList: `[]`}}
	directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(directives, `"id:2,phase:1,deny`) {
		t.Fatalf("deny ACL 开启（空并集）预检必须恒发射 id:2:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-deny"); got != "" {
		t.Fatalf("空 deny 并集文件=%q, want 空文件", got)
	}
}

// 预检合并段：stage0 保留检测在（并集可空）→ id:12 恒发射，空文件投影就位。
func TestBuildIPPrecheckDirectives_emptyStage0DetectionAlwaysEmits(t *testing.T) {
	policies := []*models.SecurityPolicy{
		{PolicyType: models.PolicyTypeStage0, IPWhitelistEnabled: true, TrustDetection: true, IPWhitelist: json.RawMessage(`[]`)},
	}
	directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(directives, `"id:12,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`) {
		t.Fatalf("stage0 保留检测在（空并集）预检必须恒发射 id:12:\n%s", directives)
	}
	if got := readRenderedIPList(t, directives, "u-trust12"); got != "" {
		t.Fatalf("空保留检测文件=%q, want 空文件", got)
	}
}

// 预检合并段：非 stage0 信任开启但并集为空（不收敛例外，默认 flag 非
// opt-in）→ 不发射 id:3。
func TestBuildIPPrecheckDirectives_emptyTrustKeepsContentGate(t *testing.T) {
	policies := []*models.SecurityPolicy{
		{IPWhitelistEnabled: true, IPWhitelist: json.RawMessage(`[]`)},
	}
	directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
	if err != nil {
		t.Fatal(err)
	}
	if directives != "" || strings.Contains(directives, "id:3,") {
		t.Fatalf("信任开启（空并集）预检不得发射 id:3/预检本体: %q", directives)
	}
}

// 预检合并段：allow 模式空名单 → 失败关闭，必须发射 id:7 拒绝（否定算子命中
// 全部来源）。
func TestBuildIPPrecheckDirectives_emptyAllowACLKeepsContentGate(t *testing.T) {
	policies := []*models.SecurityPolicy{{IPACLEnabled: true, IPACLMode: "allow", IPACLList: `[]`}}
	directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(directives, "id:7,") {
		t.Fatalf("allow 模式空名单预检必须发射 id:7 拒绝:\n%s", directives)
	}
}

// 预检合并段：无任何 IP 特性维持整体缺席（早退语义不变——收敛只去除
// 热路径可变名单的内容门控，不为恒空策略凭空造预检）。
func TestBuildIPPrecheckDirectives_noFeaturesStillSkipsPrecheck(t *testing.T) {
	policies := []*models.SecurityPolicy{{Mode: "off"}}
	directives, err := buildIPPrecheckDirectives(policies, 0, "lb_test")
	if err != nil {
		t.Fatal(err)
	}
	if directives != "" {
		t.Fatalf("无 IP 特性预检须缺席（早退语义不变）: %q", directives)
	}
}
