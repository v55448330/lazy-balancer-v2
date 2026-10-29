package mcpserver

import (
	"os"
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
	for name, text := range map[string]string{
		"server instructions": serverInstructions,
		"playbook":            string(playbook),
		"user documentation":  string(docs),
	} {
		for _, want := range []string{"429", "120", "Retry-After", "指数退避"} {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks rate-limit contract term %q", name, want)
			}
		}
	}
}
