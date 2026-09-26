package handlers

import "testing"

// 第 58 轮（用户裁定）：安全总览攻击类型分布支持按阶段展示（默认）——
// stageCategorizeAttack 将事件归入与触发阶段一致的五桶：
//   信任名单 / IP 访问控制（黑白名单+地域+威胁库）/ WAF（CRS+自定义）/
//   请求体异常 / 其他。
// 具体分类（取消勾选）沿用既有 categorizeAttack，不在此测试范围。
func TestStageCategorizeAttack_buckets(t *testing.T) {
	cases := []struct {
		name          string
		ruleTriggered string
		ruleMsg       string
		want          string
	}{
		// 信任名单：id 3/12
		{"trust id 3", "3", "", "信任名单"},
		{"trust id 12", "12", "", "信任名单"},
		// IP 访问控制：黑白名单（2/4/5/7）+ 地域（8/8xxxxx）+ 威胁库（14）
		{"acl blacklist id 2", "2", "", "IP 访问控制"},
		{"acl blacklist id 4", "4", "", "IP 访问控制"},
		{"acl allow id 5", "5", "", "IP 访问控制"},
		{"acl allow id 7", "7", "", "IP 访问控制"},
		{"geo legacy id 8", "8", "", "IP 访问控制"},
		{"geo precheck id", "800123", "", "IP 访问控制"},
		{"threat id 14", "14", "", "IP 访问控制"},
		{"threat via msg", "", "威胁情报库拦截", "IP 访问控制"},
		{"geo via msg", "", "GeoIP 区域拦截", "IP 访问控制"},
		{"acl via msg", "", "命中 IP 黑名单", "IP 访问控制"},
		// WAF：CRS 6 位 9xxxxx + 自定义（5 位 / 1 开头 ≥7 位合成）
		{"crs sqli", "942100", "SQLi", "WAF"},
		{"crs scanner", "913100", "Scanner", "WAF"},
		{"crs protocol", "920350", "Protocol", "WAF"},
		{"crs custom 5-digit", "10001", "自定义拦截", "WAF"},
		{"crs synthetic custom", "1000001", "旧版规则", "WAF"},
		// 请求体异常：id 11
		{"body id 11", "11", "", "请求体异常"},
		// 其他
		{"empty", "", "", "其他"},
		{"unmatched", "123456", "something else", "其他"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stageCategorizeAttack(tc.ruleTriggered, tc.ruleMsg); got != tc.want {
				t.Fatalf("stageCategorizeAttack(%q, %q) = %q, want %q", tc.ruleTriggered, tc.ruleMsg, got, tc.want)
			}
		})
	}
}
