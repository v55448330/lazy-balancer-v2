package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestUpdateSecurityPolicy_crsFieldsRejectWhitespaceEntries 验证 R47 B-#1 校验侧：
// crs_rule_groups / crs_excluded_rules 条目不允许首尾空白。旧校验先 TrimSpace 再
// 检查，" 42"/"42 "/"\t42" 全部通过并按原样落库，而发射端用原始值拼接 Include
// glob（REQUEST-9 42-*.conf）→ 零匹配 → coraza 静默跳过，blocking 模式该组
// CRS 规则（如 942 SQL 注入检测）完全缺失且无任何报错。拒绝时必须点名问题条目。
func TestUpdateSecurityPolicy_crsFieldsRejectWhitespaceEntries(t *testing.T) {
	// Given 一个存在的策略
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	id := createTestPolicy(t, router, map[string]any{"name": "空白条目策略"})

	// When 提交首尾空白条目（Update 路径，两个字段对称）
	// Then 一律 400，message 含字段名与"首尾空白"说明
	for _, field := range []string{"crs_rule_groups", "crs_excluded_rules"} {
		for _, entry := range []string{" 42", "42 ", " 42 ", "\t42"} {
			payload, err := json.Marshal([]string{entry})
			if err != nil {
				t.Fatalf("marshal payload: %v", err)
			}
			recorder := putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{field: string(payload)})
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("%s %q status=%d body=%s, want 400", field, entry, recorder.Code, recorder.Body.String())
			}
			body := recorder.Body.String()
			if !strings.Contains(body, field) || !strings.Contains(body, "首尾空白") {
				t.Fatalf("%s %q rejection must name the field and the whitespace cause: %s", field, entry, body)
			}
		}
	}

	// And Create 路径同样收紧
	recorder := postJSON(t, router, "/security/policies", map[string]any{"name": "空白组号策略", "crs_rule_groups": `[" 42"]`})
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("create with whitespace group status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}

	// And 干净条目不受影响：两位数字组号与合法排除文件名均接受
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_rule_groups": `["42","90"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("clean groups status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	recorder = putJSON(t, router, fmt.Sprintf("/security/policies/%d", id), map[string]any{"crs_excluded_rules": `["942100","REQUEST-942-APPLICATION-ATTACK-SQLI.conf"]`})
	if recorder.Code != http.StatusOK {
		t.Fatalf("clean excluded rules status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
}
