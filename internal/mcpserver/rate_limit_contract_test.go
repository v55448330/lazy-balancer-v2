package mcpserver

import (
	"os"
	"strconv"
	"strings"
	"testing"
)

func TestMCPRateLimitContractDocumentsRetryBehavior(t *testing.T) {
	playbook, err := os.ReadFile("playbook.md")
	if err != nil {
		t.Fatal(err)
	}
	docs, err := os.ReadFile("../../docs/mcp.zh-CN.md")
	if err != nil {
		t.Fatal(err)
	}
	// 限额数字从 middleware 实现派生（常量未导出，跨包读源码——手抄字面量
	// 会在限额变更时静默漂移）。
	limit := strconv.Itoa(goConstInt(t, "../middleware/middleware.go", "mcpRateLimitPerMinute"))
	for name, text := range map[string]string{
		"server instructions": serverInstructions,
		"playbook":            string(playbook),
		"user documentation":  string(docs),
	} {
		for _, want := range []string{"429", limit, "Retry-After", "指数退避"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks rate-limit contract term %q", name, want)
			}
		}
	}
}
