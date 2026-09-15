package services

// SECLB33-1 P0(第 33 轮审计)/ TDD 强化 §11 + R-10 引擎编译门禁:
// 配置生成类修复的验证终点是「引擎接受」——字符串形状断言不构成行为验证
// (coraza「disruptive 动作仅允许链首段」约束在文本层不可见,坏形状曾随
// v2.2.11 出厂)。本文件的测试把 BuildCorazaDirectives/buildIPPrecheckDirectives
// 的真实渲染产物直接送入 coraza v3.7.0(与 Dockerfile coraza-caddy v2.6.1
// 同版)编译——编译拒绝即测试失败,字符串测试无法覆盖的引擎约束在此拦截。

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"lazy-balancer-v2/internal/models"
)

// compileForEngineGate 把渲染指令送入 coraza 编译。过滤两类环境依赖行:
//   - SecAuditLog <path>:引擎在 NewWAF 时打开审计日志文件(/app/logs 在
//     开发/CI 不存在)——路径可写性不是被测对象;
//   - Include <crs 路径>:CRS 文件仅存在于镜像内——引擎接受「文件缺失」
//     与否不是被测对象(镜像内由 caddy validate 覆盖全量)。
// 其余全部逐字送编译——我们自己发射的 SecRule/SecAction/SecMarker 形状
// 是本门禁的被测对象,零裁剪(R-8 验证源直取:指令文本来自真实渲染调用)。
func compileForEngineGate(t *testing.T, directives string) {
	t.Helper()
	var kept []string
	for _, line := range strings.Split(directives, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "SecAuditLog ") || strings.HasPrefix(trimmed, "Include ") {
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
			compileForEngineGate(t, BuildCorazaDirectives(p, nil, "", true))
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
		"custom-chained":      {Mode: "blocking", CustomRules: json.RawMessage(`[{"name":"t","action":"block","conditions":[{"target":"uri","operator":"contains","value":"/admin"},{"target":"user_agent","operator":"contains","value":"bot"}]}]`)},
	}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			multi := strings.HasPrefix(name, "multi-")
			compileForEngineGate(t, BuildCorazaDirectives(p, nil, "", multi))
		})
	}
	t.Run("precheck-trust-union", func(t *testing.T) {
		p1 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "deny", IPACLList: `["198.51.100.9"]`, IPWhitelistEnabled: true, IPWhitelist: trust}
		p2 := &models.SecurityPolicy{Mode: "blocking", IPACLEnabled: true, IPACLMode: "allow", IPACLList: `["1.2.3.4"]`}
		compileForEngineGate(t, buildIPPrecheckDirectives([]*models.SecurityPolicy{p1, p2}))
	})
}
