package notify

// QQ markdown 换行规范回归（用户实测表格不渲染）：表格行须保持连续单换行
// （空行断表），段落空行分隔。旧实现把全部 \n 翻倍致表格语法失效。

import (
	"strings"
	"testing"
)

func TestNormalizeQQMarkdownPreservesTable(t *testing.T) {
	md := "# 日报\n| 指标 | 数值 |\n|---|---|\n| 请求数 | 100 |\n| 拦截 | 5 |\n备注：以上。"
	out := normalizeQQMarkdown(md)
	// 表格四行须连续（行间单换行，无空行）
	tableBlock := "| 指标 | 数值 |\n|---|---|\n| 请求数 | 100 |\n| 拦截 | 5 |"
	if !strings.Contains(out, tableBlock) {
		t.Errorf("表格行被空行断开（markdown 表格失效）:\n%s", out)
	}
	// 标题与表格之间、表格与备注之间有空行分段
	if !strings.Contains(out, "# 日报\n\n| 指标") {
		t.Errorf("标题与表格间应空行分段:\n%s", out)
	}
	if !strings.Contains(out, "| 拦截 | 5 |\n\n备注") {
		t.Errorf("表格与备注间应空行分段:\n%s", out)
	}
}

func TestNormalizeQQMarkdownParagraphSpacing(t *testing.T) {
	out := normalizeQQMarkdown("第一行\n第二行")
	if out != "第一行\n\n第二行" {
		t.Errorf("普通段落应空行分隔, got %q", out)
	}
}

func TestNormalizeQQMarkdownPreservesList(t *testing.T) {
	md := "- 项一\n- 项二\n- 项三"
	out := normalizeQQMarkdown(md)
	if !strings.Contains(out, "- 项一\n- 项二\n- 项三") {
		t.Errorf("列表行应保持连续单换行:\n%s", out)
	}
}
