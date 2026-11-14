package dnspod

import (
	"strings"
	"testing"
)

// 已知明文残差检查必须双侧 ToLower（与 tencent/aliyun/cloudflare 同口径）：
// 定向替换是大小写敏感的，厂商/网关的大小写变体回声（不参与替换但同为泄露）
// 必须触发整段丢弃，凭据不得进错误链落 cert_jobs（全体登录用户可读）。
func TestSanitizeHTTPErrorBody_variantEchoWithheld(t *testing.T) {
	const secret = "12345,s3cr3tkeyvalue"
	cases := map[string]string{
		"全大写变体":   `upstream rejected token 12345,S3CR3TKEYVALUE`,
		"混合大小写分段": `echo: token S3cr3tKeyValue not allowed`,
		"无分隔变体":   `credential 12345,S3CR3TKEYVALUE rejected by upstream`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			got := sanitizeHTTPErrorBody(body, secret)
			if strings.Contains(strings.ToLower(got), "s3cr3tkeyvalue") {
				t.Fatalf("凭据变体进入错误文案: %q", got)
			}
			if !strings.HasPrefix(got, "[response body withheld:") {
				t.Fatalf("变体回声应整段丢弃（fail-closed）: %q", got)
			}
		})
	}
	// 回归形状：精确明文仍走定向替换（保留排障上下文），干净文案不误伤。
	if got := sanitizeHTTPErrorBody("echo: token s3cr3tkeyvalue not allowed", secret); !strings.Contains(got, "***") {
		t.Fatalf("精确明文定向替换回归: %q", got)
	}
	if got := sanitizeHTTPErrorBody("gateway timeout from upstream", secret); got != "gateway timeout from upstream" {
		t.Fatalf("干净文案误伤: %q", got)
	}
}
