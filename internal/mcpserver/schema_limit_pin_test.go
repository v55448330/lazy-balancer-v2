package mcpserver

// 上限跨栈对表钉：MCP schema 的 policy_ids maxItems 必须与后端
// maxBindingsPerRule 同值（handlers 包常量）——schema 是 Agent 唯一构参契约，
// 漂移会让 REST 已放开的能力在 MCP 面文档性不可达（上限调整轮实录：schema
// 漏随常量同步）。直接读 Go 声明对表（与前端 goConstInt 同形态）。

import (
	"os"
	"regexp"
	"strconv"
	"testing"
)

func goConstIntFromSource(t *testing.T, path, constName string) int {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?:const|var)\s+` + constName + `\s*=\s*(\d+)`)
	m := re.FindSubmatch(src)
	if m == nil {
		t.Fatalf("%s: 未找到 %s 声明（漂移或改名）", path, constName)
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		t.Fatalf("%s: %s=%s 非整数", path, constName, m[1])
	}
	return n
}

func TestSetRuleSecurityPoliciesSchema_matchesMaxBindingsPerRule(t *testing.T) {
	backend := goConstIntFromSource(t, "../handlers/security.go", "maxBindingsPerRule")
	re := regexp.MustCompile(`"maxItems":(\d+)`)
	all := re.FindAllStringSubmatch(setRuleSecurityPoliciesSchema, -1)
	if len(all) != 1 {
		t.Fatalf("setRuleSecurityPoliciesSchema maxItems 出现 %d 次（恰好 1 处才算无歧义锚）", len(all))
	}
	got, err := strconv.Atoi(all[0][1])
	if err != nil {
		t.Fatalf("maxItems=%q 非整数", all[0][1])
	}
	if got != backend {
		t.Fatalf("MCP schema maxItems=%d ≠ 后端 maxBindingsPerRule=%d——Agent 构参契约漂移，两处须同批同步", got, backend)
	}
}
