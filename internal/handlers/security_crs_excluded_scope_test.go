package handlers

import (
	"strings"
	"testing"
)

// crs_excluded_rules 新格式的 scope 校验必须闭合：每个 scope 只消费自己的
// 目标字段，携带互补字段会原样落库但渲染端不消费（保存成功、意图不生效的
// 静默死配置）。scope=all/path 已拒绝互补字段，ip/list 与非 path 的 path
// 同样必须拒绝。
func TestValidateCRSExcludedRulesPayloadRejectsComplementaryScopeFields(t *testing.T) {
	rejected := []struct {
		name     string
		payload  string
		fragment string
	}{
		{
			name:     "scope=ip 携带 listRefs",
			payload:  `[{"target":"942100","scope":"ip","ips":"1.2.3.4","listRefs":[5]}]`,
			fragment: "listRefs",
		},
		{
			name:     "scope=list 携带 ips",
			payload:  `[{"target":"942100","scope":"list","listRefs":[5],"ips":"1.2.3.4"}]`,
			fragment: "ips",
		},
		{
			name:     "scope=all 携带 path",
			payload:  `[{"target":"942100","scope":"all","path":"/admin"}]`,
			fragment: "path",
		},
		{
			name:     "scope=ip 携带 path",
			payload:  `[{"target":"942100","scope":"ip","ips":"1.2.3.4","path":"/admin"}]`,
			fragment: "path",
		},
		{
			name:     "scope=list 携带 path",
			payload:  `[{"target":"942100","scope":"list","listRefs":[5],"path":"/admin"}]`,
			fragment: "path",
		},
	}
	for _, tc := range rejected {
		t.Run(tc.name, func(t *testing.T) {
			payload := tc.payload
			err := validateCRSExcludedRulesPayload(&payload, false)
			if err == nil {
				t.Fatalf("%s：互补字段被静默落库（保存成功但渲染端不消费）", tc.name)
			}
			if !strings.Contains(err.Error(), tc.fragment) {
				t.Fatalf("%s：错误未点名被拒字段 %q：%v", tc.name, tc.fragment, err)
			}
		})
	}

	// 合法单字段形态不得被新门误拦。
	for _, payload := range []string{
		`[{"target":"942100","scope":"ip","ips":"1.2.3.4"}]`,
		`[{"target":"942100","scope":"list","listRefs":[5]}]`,
		`[{"target":"942100","scope":"path","path":"/admin"}]`,
		`[{"target":"942100","scope":"all"}]`,
		`[{"target":"942100"}]`,
	} {
		value := payload
		if err := validateCRSExcludedRulesPayload(&value, false); err != nil {
			t.Fatalf("合法形态被误拦 %s: %v", payload, err)
		}
	}
}
