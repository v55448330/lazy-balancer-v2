package services

import "testing"

// routeClaimedByAny/claimedRouteIDs 行为钉——认领判据与渲染侧归属函数
// RouteIDBelongsToRule 同源：精确匹配 / 生成式子路由（path_<序号>/geoip/
// redirect）归主规则 / 裸下划线前缀兄弟不得误认 / 白名单外后缀不认领 /
// 空集恒 false。
func TestRouteClaimedByAny_ownershipWhitelist(t *testing.T) {
	expected := map[string]string{
		"lb_abc":       "rule-a",
		"lb_abc-extra": "rule-b", // 前缀兄弟：lb_abc 不得认领 lb_abc-extra*
		"lb_xy":        "rule-c",
	}
	claimed := claimedRouteIDs(expected)
	cases := []struct {
		routeID string
		want    bool
	}{
		{"lb_abc", true},              // 精确匹配
		{"lb_abc_path_0", true},       // 生成式子路由归主规则
		{"lb_abc_redirect", true},     // 生成式子路由归主规则
		{"lb_abc_geoip", true},        // 生成式子路由归主规则
		{"lb_abc_", false},            // 空后缀不在生成式白名单
		{"lb_abc_extra", false},       // 白名单外后缀不认领
		{"lb_abc-extra", true},        // 前缀兄弟自身精确匹配
		{"lb_abc-extra_path_0", true}, // 前缀兄弟的生成式子路由
		{"lb_xy", true},
		{"lb_xy_", false},
		{"lb_unknown", false},
		{"lb_abcx", false}, // 无下划线标签边界 → 不认领
		{"lb_abc-extrax", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := routeClaimedByAny(tc.routeID, claimed); got != tc.want {
			t.Errorf("routeClaimedByAny(%q)=%v, want %v", tc.routeID, got, tc.want)
		}
	}
	if routeClaimedByAny("lb_anything", claimedRouteIDs(nil)) {
		t.Error("empty expected set must claim nothing")
	}
}
