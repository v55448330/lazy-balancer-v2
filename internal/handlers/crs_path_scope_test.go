package handlers

// path 作用域排除（scope=path）写侧校验矩阵。目录数据源由既有
// GET /security/crs/rule-index 提供（同 services.GetCRSRuleIndex，形状见
// apidocs.go），本文件不含目录端点用例（冗余端点已按裁定退役）。

import (
	"strings"
	"testing"
)

func TestValidateCRSExcludedRulesPayload_pathScope(t *testing.T) {
	useCRSRuleIndexFixture(t)
	over := "/" + strings.Repeat("a", 256) // 257 字符 > 上限 256
	cases := []struct {
		name    string
		payload string
		wantErr string
	}{
		{"valid single id", `[{"target":"942100","scope":"path","path":"/api/public"}]`, ""},
		{"valid group", `[{"target":"42","scope":"path","path":"/api"}]`, ""},
		{"missing path", `[{"target":"942100","scope":"path"}]`, "必须填写 path"},
		{"empty path", `[{"target":"942100","scope":"path","path":""}]`, "必须填写 path"},
		{"no leading slash", `[{"target":"942100","scope":"path","path":"api/x"}]`, "以 / 开头"},
		{"over 256", `[{"target":"942100","scope":"path","path":"` + over + `"}]`, "256"},
		{"whitespace", `[{"target":"942100","scope":"path","path":"/api public"}]`, "空白"},
		{"control char", `[{"target":"942100","scope":"path","path":"/api\u0007x"}]`, "空白"},
		{"double quote", `[{"target":"942100","scope":"path","path":"/api\"x"}]`, "双引号或反斜杠"},
		{"backslash", `[{"target":"942100","scope":"path","path":"/api\\x"}]`, "双引号或反斜杠"},
		{"with ips", `[{"target":"942100","scope":"path","path":"/api","ips":"1.1.1.1"}]`, "不允许携带 ips/listRefs"},
		{"with listRefs", `[{"target":"942100","scope":"path","path":"/api","listRefs":[3]}]`, "不允许携带 ips/listRefs"},
		{"stale target", `[{"target":"999999","scope":"path","path":"/api"}]`, "规则 ID 不存在于当前 CRS"},
		{"filename target scoped", `[{"target":"REQUEST-942-APPLICATION-ATTACK-SQLI.conf","scope":"path","path":"/api"}]`, "仅支持 scope=all"},
		{"unknown scope still rejected", `[{"target":"942100","scope":"global"}]`, "scope 无效"},
		{"legacy format unaffected", `["942100"]`, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			val := tc.payload
			err := validateCRSExcludedRulesPayload(&val, true)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
	// 基础设施组守卫与 scope 无关（checkIndices=false 时索引存在性门豁免通道
	// 也不放行——901/949/959 排除无合法用途）。夹具索引不含 949110，故走
	// false 通道命中 infra 守卫。
	infraVal := `[{"target":"949110","scope":"path","path":"/api"}]`
	if err := validateCRSExcludedRulesPayload(&infraVal, false); err == nil || !strings.Contains(err.Error(), "基础设施规则组") {
		t.Fatalf("path 作用域基础设施排除必须拒绝: err=%v", err)
	}
}
