package services

// 看门狗/启动守卫的路由认领必须与渲染侧归属判据（RouteIDBelongsToRule 的
// 生成式后缀白名单）同源：裸 ruleID+"_" 前缀会把「恰为下划线前缀」的另一条
// 规则主路由（lb_web 与 lb_web_path 并存，v1 导入/历史 ID 允许下划线）误认领，
// 漂移明细漏报该路由。

import (
	"testing"
)

func TestDiffRunningExtra_prefixSiblingRuleNotClaimed(t *testing.T) {
	expected := map[string]string{"lb_web": "规则A"}
	running := map[string]bool{
		"lb_web":          true,
		"lb_web_path_0":   true, // 生成式子路由 → 归主规则
		"lb_web_redirect": true,
		"lb_web_path":     true, // 另一条规则的主路由（下划线前缀兄弟）→ 不得认领
		"lb_web_extra":    true, // 白名单外后缀 → 多余
	}
	extra := diffRunningExtra(expected, running)
	want := []string{"lb_web_extra", "lb_web_path"}
	if len(extra) != len(want) {
		t.Fatalf("extra=%v, want %v（前缀兄弟规则路由必须计入多余）", extra, want)
	}
	for i := range want {
		if extra[i] != want[i] {
			t.Fatalf("extra=%v, want %v", extra, want)
		}
	}
}

func TestForeignRunningRuleRoutes_prefixSiblingRuleIsForeign(t *testing.T) {
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"s":{"routes":[
		{"@id":"lb_web","handle":[]},
		{"@id":"lb_web_path_0","handle":[]},
		{"@id":"lb_web_path","handle":[]}
	]}}}}}`)
	foreign, err := ForeignRunningRuleRoutes(server.URL, map[string]bool{"lb_web": true})
	if err != nil {
		t.Fatalf("ForeignRunningRuleRoutes: %v", err)
	}
	if len(foreign) != 1 || foreign[0] != "lb_web_path" {
		t.Fatalf("foreign=%v, want [lb_web_path]（前缀兄弟不得被裸前缀认领）", foreign)
	}
}

// :80「已是 HTTPS 不再跳转」诊断路由的 @id 不带规则前缀。渲染侧只在生成至少
// 一条跳转子路由（<规则ID>_redirect）时才渲染它；看门狗与启动守卫按同一约定
// 认领——否则每次重启都把它报成「多余规则路由」，横幅常亮且「重启服务恢复」无效。
func TestDiffRunningExtra_httpsRedirectDiagnosticRouteFollowsRedirectSubRoutes(t *testing.T) {
	expected := map[string]string{"lb_web": "规则A"}
	// Given 被认领的跳转子路由在运行配置里，When 诊断路由同批出现，Then 不计多余。
	if extra := diffRunningExtra(expected, map[string]bool{"lb_web": true, "lb_web_redirect": true, httpsRedirectLoopDiagnosticRouteID: true}); len(extra) != 0 {
		t.Fatalf("extra=%v, want []（诊断路由随被认领的跳转子路由出现，属本库配置）", extra)
	}
	// Given 没有任何跳转子路由，When 诊断路由出现，Then 是残留/外来路由，照常计入多余。
	if extra := diffRunningExtra(expected, map[string]bool{"lb_web": true, httpsRedirectLoopDiagnosticRouteID: true}); len(extra) != 1 || extra[0] != httpsRedirectLoopDiagnosticRouteID {
		t.Fatalf("extra=%v, want [%s]（无跳转子路由时诊断路由必须计入多余）", extra, httpsRedirectLoopDiagnosticRouteID)
	}
	// Given 只伴随未被认领的跳转子路由（对应规则已不在库），Then 两者都是多余。
	if extra := diffRunningExtra(expected, map[string]bool{"lb_web": true, "lb_gone_redirect": true, httpsRedirectLoopDiagnosticRouteID: true}); len(extra) != 2 {
		t.Fatalf("extra=%v, want 2 条（残留跳转子路由与诊断路由都计入多余）", extra)
	}
}

func TestForeignRunningRuleRoutes_httpsRedirectDiagnosticRouteFollowsRedirectSubRoutes(t *testing.T) {
	own := map[string]bool{"lb_web": true}
	server := fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"s":{"routes":[
		{"@id":"lb_web","handle":[]},
		{"@id":"lb_web_redirect","handle":[]},
		{"@id":"lb_https_redirect_loop_diagnostic","handle":[]}
	]}}}}}`)
	foreign, err := ForeignRunningRuleRoutes(server.URL, own)
	if err != nil {
		t.Fatalf("ForeignRunningRuleRoutes: %v", err)
	}
	if len(foreign) != 0 {
		t.Fatalf("foreign=%v, want []（伴随本库跳转子路由的诊断路由不是外来路由）", foreign)
	}
	server = fakeCaddyWithRoutes(t, `{"apps":{"http":{"servers":{"s":{"routes":[
		{"@id":"lb_web","handle":[]},
		{"@id":"lb_https_redirect_loop_diagnostic","handle":[]}
	]}}}}}`)
	foreign, err = ForeignRunningRuleRoutes(server.URL, own)
	if err != nil {
		t.Fatalf("ForeignRunningRuleRoutes: %v", err)
	}
	if len(foreign) != 1 || foreign[0] != httpsRedirectLoopDiagnosticRouteID {
		t.Fatalf("foreign=%v, want [%s]（无本库跳转子路由时诊断路由仍是外来路由）", foreign, httpsRedirectLoopDiagnosticRouteID)
	}
}
