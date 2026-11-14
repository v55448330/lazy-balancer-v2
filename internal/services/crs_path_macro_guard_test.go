package services

// scope=path 的 CRS 排除 path 字段不得含 %{...} 宏：@beginsWith 操作数在
// coraza 内包成 Macro 运行期展开（begins_with.go 的 macro.NewMacro），宏会让
// 排除前缀随请求变量静默动态化（排除面不可控）。自定义规则写侧对非 regex
// 运算符已拒同款（validateCustomRulePattern），两处共用同一判据。

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidCRSExclusionPath_rejectsMacroSequences(t *testing.T) {
	for _, path := range []string{
		"/api/%{REMOTE_ADDR}",
		"/%{TX.x}/public",
		"/api/%{",
	} {
		if ValidCRSExclusionPath(path) {
			t.Fatalf("path %q 含 %%{ 宏序列，必须拒绝（与自定义规则写侧同口径）", path)
		}
	}
	// 回归形状：合法 path 不受影响；单个 % 不构成宏，照常放行。
	for _, path := range []string{"/api/public", "/a%20b", "/100%"} {
		if !ValidCRSExclusionPath(path) {
			t.Fatalf("合法 path %q 不得被误拒", path)
		}
	}
}

// 渲染守卫与写侧同源：带外直写的宏 path 条目跳过不发射（少排除=拦截更多，
// 方向安全），不得把 %{...} 拼进 @beginsWith 操作数。
func TestBuildCorazaDirectives_pathScopeMacroGuard(t *testing.T) {
	scopedExclusionFixture(t)
	raw, err := json.Marshal([]map[string]string{{"target": "942100", "scope": "path", "path": "/api/%{REMOTE_ADDR}"}})
	if err != nil {
		t.Fatal(err)
	}
	directives := mustDirectives(BuildCorazaDirectives(pathScopePolicy(string(raw)), nil, "", false, 0, "lb_path_macro"))
	if strings.Contains(directives, "@beginsWith") || strings.Contains(directives, "%{") {
		t.Fatalf("宏 path 必须被渲染守卫跳过，不得发射:\n%s", directives)
	}
}
