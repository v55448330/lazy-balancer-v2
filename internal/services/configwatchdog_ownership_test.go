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
