package services

// D40-2-1(第 40 轮,用户裁定:配置项页面与 coraza 默认值统一为 128M):
// 有效限额三态归一——规则级>0 用规则级;否则全局>0 用全局;否则 128。
// request_body handler 恒按有效值发射(「0=不限」语义废除);WAF 活跃时
// SecRequestBodyLimit 恒发射 min(有效值,1GiB)。R-10:渲染产物送 coraza 编译。

import (
	"strings"
	"testing"
)

func findHandlerInChain(t *testing.T, route map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	chain, _ := route["handle"].([]interface{})
	for _, h := range chain {
		m, ok := h.(map[string]interface{})
		if !ok {
			continue
		}
		if n, _ := m["handler"].(string); n == name {
			return m
		}
	}
	return nil
}

func wafDirectivesOf(t *testing.T, route map[string]interface{}) string {
	t.Helper()
	waf := findHandlerInChain(t, route, "waf")
	if waf == nil {
		t.Fatalf("no waf handler in chain: %v", handlerNames(t, route))
	}
	directives, _ := waf["directives"].(string)
	if directives == "" {
		t.Fatal("waf handler has no directives")
	}
	return directives
}

func TestRequestBodyLimit_unifiedDefault128(t *testing.T) {
	_, database := newClusterTestService(t)

	// 形状③:global=0 + 无 WAF → request_body handler 恒发射 max_size=128MiB
	if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=0`); err != nil {
		t.Fatal(err)
	}
	rule := mpGenHTTPRule("bl-plain-r", "bl-plain.test")
	_, mainRoute := mpGenRoutes(t, database, rule)
	rb := findHandlerInChain(t, mainRoute, "request_body")
	if rb == nil {
		t.Fatalf("request_body handler must be emitted with 128MiB default (0 no longer means unlimited): %v", handlerNames(t, mainRoute))
	}
	if got, _ := rb["max_size"].(int64); got != int64(134217728) {
		t.Fatalf("request_body max_size=%v, want 134217728 (128MiB)", got)
	}

	// 形状①:global=0 + WAF 活跃 → SecRequestBodyLimit 134217728 且引擎可编译
	mpGenBindPolicy(t, database, "bl-plain-r", "p-bl1", mpGenPolicySpec{mode: "blocking", enabled: true})
	_, mainRouteWaf := mpGenRoutes(t, database, rule)
	directives := wafDirectivesOf(t, mainRouteWaf)
	if !strings.Contains(directives, "SecRequestBodyLimit 134217728") {
		t.Fatalf("directives missing SecRequestBodyLimit 134217728 (128MiB default):\n%s", directives)
	}
	compileForEngineGate(t, directives)

	// 形状②:global=256 → 268435456(handler 与 WAF 指令同值)
	if _, err := database.Exec(`UPDATE global_config SET request_body_max_size_mb=256`); err != nil {
		t.Fatal(err)
	}
	rule256 := mpGenHTTPRule("bl-256-r", "bl-256.test")
	rule256.GlobalRequestBodyMaxSizeMB = 256
	mpGenBindPolicy(t, database, "bl-256-r", "p-bl2", mpGenPolicySpec{mode: "blocking", enabled: true})
	_, mainRoute256 := mpGenRoutes(t, database, rule256)
	rb256 := findHandlerInChain(t, mainRoute256, "request_body")
	if rb256 == nil {
		t.Fatalf("request_body handler missing for global=256: %v", handlerNames(t, mainRoute256))
	}
	if got, _ := rb256["max_size"].(int64); got != int64(268435456) {
		t.Fatalf("request_body max_size=%v, want 268435456 (256MiB)", got)
	}
	directives256 := wafDirectivesOf(t, mainRoute256)
	if !strings.Contains(directives256, "SecRequestBodyLimit 268435456") {
		t.Fatalf("directives missing SecRequestBodyLimit 268435456:\n%s", directives256)
	}
	compileForEngineGate(t, directives256)

	// 形状④:规则级覆盖(global=256, rule=64) → 67108864
	rule64 := mpGenHTTPRule("bl-64-r", "bl-64.test")
	rule64.RequestBodyMaxSizeMB = 64
	rule64.GlobalRequestBodyMaxSizeMB = 256
	mpGenBindPolicy(t, database, "bl-64-r", "p-bl3", mpGenPolicySpec{mode: "blocking", enabled: true})
	_, mainRoute64 := mpGenRoutes(t, database, rule64)
	rb64 := findHandlerInChain(t, mainRoute64, "request_body")
	if rb64 == nil {
		t.Fatalf("request_body handler missing for rule override: %v", handlerNames(t, mainRoute64))
	}
	if got, _ := rb64["max_size"].(int64); got != int64(67108864) {
		t.Fatalf("request_body max_size=%v, want 67108864 (64MiB rule override)", got)
	}
	directives64 := wafDirectivesOf(t, mainRoute64)
	if !strings.Contains(directives64, "SecRequestBodyLimit 67108864") {
		t.Fatalf("directives missing SecRequestBodyLimit 67108864:\n%s", directives64)
	}
	compileForEngineGate(t, directives64)
}
