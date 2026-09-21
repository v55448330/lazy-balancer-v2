package handlers

import "testing"

// 第 47 轮 F-47-23：OIDC return_to 此前仅要求以 "/" 开头——协议相对值 `//evil.com`
// 可绕过后端校验并写入 OIDC state；最终拦截点只剩前端页面键白名单
// （web/src/App.vue isPageId），开放重定向防护成为跨层单点依赖。
// 修复后在漏斗处直接拒绝 "//" 前缀（含 "/\" 变体），前端白名单退化为第二道防线。
func TestSanitizeOIDCReturnTo(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"站内相对路径放行", "/security-policies", "/security-policies"},
		{"站内带 query 放行", "/rules?tab=2", "/rules?tab=2"},
		{"空值放行（回落默认）", "", ""},
		{"协议相对值拒绝（目标形状）", "//evil.example.com", ""},
		{"三斜杠拒绝", "///evil.example.com", ""},
		{"反斜杠变体拒绝", "/\\evil.example.com", ""},
		{"绝对 URL 拒绝（既有口径回归）", "https://evil.example.com", ""},
		{"裸域名拒绝（既有口径回归）", "evil.example.com", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeOIDCReturnTo(tc.in); got != tc.want {
				t.Fatalf("sanitizeOIDCReturnTo(%q)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}
