package handlers

// OpenAPI 契约文本与实现上限单源：单规则安全策略绑定上限已按用户
// 裁定升为 maxBindingsPerRule=10，apidocs 的错误码/正文仍停留在 max_8/「最多
// 8 条」——消费方按文档匹配错误码会失配。

import (
	"fmt"
	"strings"
	"testing"
)

func TestAPIDocs_policyBindingLimitMatchesImplementation(t *testing.T) {
	for _, route := range apiDocRoutes {
		if route.Method != "PUT" || route.Path != "/security/rules/:caddy_id/policies" {
			continue
		}
		errorsText := strings.Join(route.Errors, " ")
		if want := fmt.Sprintf("max_%d", maxBindingsPerRule); !strings.Contains(errorsText, want) {
			t.Fatalf("错误码文本=%q 缺少 %q", errorsText, want)
		}
		if strings.Contains(errorsText, "max_8") {
			t.Fatalf("错误码文本仍含 max_8: %q", errorsText)
		}
		if want := fmt.Sprintf("最多 %d 条", maxBindingsPerRule); !strings.Contains(route.Description, want) {
			t.Fatalf("正文=%q 缺少 %q", route.Description, want)
		}
		if strings.Contains(route.Description, "最多 8 条") {
			t.Fatalf("正文仍含「最多 8 条」: %q", route.Description)
		}
		return
	}
	t.Fatal("apiDocRoutes 缺少 PUT /security/rules/:caddy_id/policies")
}
