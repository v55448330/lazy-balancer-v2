package handlers

import (
	"strings"
	"testing"
)

// 拦截页正文/JSON 变体的 64KB 上限是保存/编辑门的既有契约
// （validateBlockPagePayload）。导入侧必须同口径拒绝并点名该条，
// 不得静默放行让数百 KB 正文落库并进入 Caddy 渲染配置。
func TestValidateV2BackupRejectsOversizeBlockPageBody(t *testing.T) {
	newBackupTestHandlers(t)
	oversize := strings.Repeat("x", 64<<10+1)

	cases := []struct {
		name  string
		field string
		row   map[string]any
	}{
		{
			name:  "content 超 64KB",
			field: "content",
			row:   map[string]any{"id": 1, "name": "超大拦截页", "content": oversize},
		},
		{
			name:  "json_content 超 64KB",
			field: "json_content",
			row:   map[string]any{"id": 2, "name": "超大 JSON 拦截页", "content": "<html></html>", "json_content": oversize},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tables := map[string][]map[string]any{"security_block_pages": {tc.row}}
			err := validateV2BackupSecurityPolicies(tables, false)
			if err == nil {
				t.Fatalf("%s：导入校验放行（保存侧同字段已 64KB 拒绝）", tc.field)
			}
			if !strings.Contains(err.Error(), "64KB") || !strings.Contains(err.Error(), "拦截页面 #1") {
				t.Fatalf("%s：错误未点名该条与上限: %v", tc.field, err)
			}
		})
	}
}
