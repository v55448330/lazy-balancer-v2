package services

// 自动封禁隐私披露文档钉测（个保法/GDPR 告知义务）：docs/security.zh-CN.md
// 自动封禁段必须披露五项采集/处置事实——IPv6 /64 归一的连带面、保留地址
// 硬排除、NAT 会话指纹采集属个人信息处理、累犯渐进升级档位语义、会话封禁
// 本地态。配置弹框琥珀边线告知（前端）与本文档同口径，任一面缺失即红。

import (
	"os"
	"strings"
	"testing"
)

// autobanDocsSection 截取 docs 自动封禁段（### 自动封禁 → 下一个同级标题）。
func autobanDocsSection(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile("../../docs/security.zh-CN.md")
	if err != nil {
		t.Fatalf("read docs/security.zh-CN.md: %v", err)
	}
	text := string(raw)
	start := strings.Index(text, "### 自动封禁")
	if start < 0 {
		t.Fatal("docs/security.zh-CN.md 缺「### 自动封禁」段")
	}
	rest := text[start+len("### 自动封禁"):]
	end := strings.Index(rest, "\n### ")
	if end >= 0 {
		rest = rest[:end]
	}
	return rest
}

// Given 安全文档自动封禁段。
// When 逐项核对隐私披露五要素。
// Then 全部在场（/64 连带、保留地址排除、指纹个人信息告知、升级档位、会话本地态）。
func TestSecurityDocs_autobanPrivacyDisclosure(t *testing.T) {
	section := autobanDocsSection(t)
	for _, want := range []string{
		"/64",        // IPv6 归一粒度
		"连带",         // 同 /64 无辜主机波及披露
		"保留",         // 保留/私网/回环地址排除
		"个人信息",       // 指纹采集属个人信息处理（个保法/GDPR 告知）
		"Cookie",     // 指纹来源之一：人机验证 Cookie 签名段
		"User-Agent", // 指纹兜底来源
		"standard",   // 渐进升级档位语义
		"aggressive", // 渐进升级档位语义
		"24h",        // standard 二次档时长
		"永久",         // 三次+永久档
		"本地",         // 会话封禁本地态（仅本节点）
		"不跨节点",       // 会话封禁不同步
	} {
		if !strings.Contains(section, want) {
			t.Errorf("自动封禁段隐私披露缺 %q", want)
		}
	}
}
