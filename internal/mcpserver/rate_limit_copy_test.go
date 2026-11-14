package mcpserver

import (
	"os"
	"strings"
	"testing"
)

// 429 文案必须如实描述分桶口径：Key 桶按 (来源 IP, API Key) 计费——同一 Key
// 从多个来源 IP 调用各享独立额度，"每 API Key 每分钟 N 次" 的单 Key 总额表述
// 与实现不符。
func TestMCPRateLimitCopyDescribesPerKeyPerSourceBucket(t *testing.T) {
	playbookBytes, err := os.ReadFile("playbook.md")
	if err != nil {
		t.Fatal(err)
	}
	docsBytes, err := os.ReadFile("../../docs/mcp.zh-CN.md")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{
		"server instructions": serverInstructions,
		"playbook":            string(playbookBytes),
		"user documentation":  string(docsBytes),
	} {
		if !strings.Contains(text, "每 API Key 每来源 IP") {
			t.Errorf("%s 缺少 (来源 IP, API Key) 分桶口径文案", name)
		}
		if strings.Contains(text, "每 API Key 每分钟") {
			t.Errorf("%s 仍含单 Key 总额旧口径（与按来源分桶实现不符）", name)
		}
	}
}
