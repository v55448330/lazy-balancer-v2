package notify

// 日报富项渲染钉测：新增明细项（TOP IP/临期证书/运行时长/威胁库）进入分节渲染，
// items 裁剪仍生效；markdown/text/html 三形态口径一致。

import (
	"strings"
	"testing"
)

func richValues() map[string]string {
	return map[string]string{
		"requests":      "1200",
		"blocked":       "34",
		"top_ips":       "45.33.32.9 ×321\n1.2.3.4 ×120",
		"cert_expiring": "a.com · 2026-11-25\nb.com · 2026-11-28",
		"uptime":        "32 天 4 小时",
		"threat_db":     "CRS 4.0 · IP库 2026-11",
		"login_status":  "成功 40 / 失败 3 / MFA失败 1",
	}
}

func TestRenderDailyRich_itemsAndTrim(t *testing.T) {
	items := []string{"requests", "top_ips", "cert_expiring", "uptime", "threat_db", "login_status"}
	md := renderDailyFromValues("2026-11-19", richValues(), items, "markdown")
	// 2026-11-22 多值项表格化设计后：TOP IP/临期证书出语义表格（非裸列表）
	for _, want := range []string{"| 45.33.32.9 | 321 |", "| a.com | 2026-11-25 |", "32 天 4 小时", "CRS 4.0", "MFA失败 1", "| 请求数 | 1200 |"} {
		if !strings.Contains(md, want) {
			t.Fatalf("markdown 缺富项 %q:\n%s", want, md)
		}
	}
	if strings.Contains(md, "拦截次数") {
		t.Fatalf("items 裁剪失效（blocked 未选却渲染）:\n%s", md)
	}

	txt := renderDailyFromValues("2026-11-19", richValues(), items, "text")
	if strings.Contains(txt, "<") || strings.Contains(txt, "|") {
		t.Fatalf("text 应为纯文本无标记:\n%s", txt)
	}
	if !strings.Contains(txt, "45.33.32.9 ×321") {
		t.Fatalf("text 缺 TOP IP 明细:\n%s", txt)
	}

	html := renderDailyFromValues("2026-11-19", richValues(), items, "html")
	if !strings.Contains(html, "<table") || !strings.Contains(html, "a.com") {
		t.Fatalf("html 应为表格且含临期证书:\n%s", html)
	}
}

func TestDailyItemIDs_labelsComplete(t *testing.T) {
	for _, id := range DailyItemIDs {
		if _, ok := DailyItemLabels[id]; !ok {
			t.Fatalf("DailyItemIDs %q 缺标签", id)
		}
	}
	// 分节引用的项目必须都在 IDs 白名单（渲染裁剪一致性）。
	inIDs := map[string]bool{}
	for _, id := range DailyItemIDs {
		inIDs[id] = true
	}
	for _, sec := range dailySections {
		for _, it := range sec.items {
			if !inIDs[it] {
				t.Fatalf("分节 %q 引用未登记项目 %q", sec.title, it)
			}
		}
	}
}

// 日报 markdown 多值项表格化设计（2026-11-22 用户裁定：攻击源/攻击路径/
// 证书明细/各节点摘要原为「加粗标签+裸行」无设计）——按内容语义各配表格：
// 节点摘要=节点/请求/拦截/独立IP/备注五列；TOP 列表=名目/次数两列右对齐；
// 临期证书=域名/到期日两列。任何行解析失败整项回退旧列表形态（fail-safe）。
func TestRenderDailyMarkdown_multiValueTableDesign(t *testing.T) {
	values := map[string]string{
		"requests":      "128340",
		"top_ips":       "45.33.32.9 ×321\n1.2.3.4 ×120",
		"top_paths":     "/login ×200\n/api ×150",
		"cert_expiring": "a.com · 2026-11-25\nb.com · 2026-11-28",
		"nodes_summary": "slave-a：请求 22014 · 拦截 156 · 独立IP 402\nslave-b：请求 9821 · 拦截 12 · 独立IP 210 · TOP 规则 SQLi · CC 2 · 自动封禁 1",
	}
	got := renderDailyFromValues("2026-11-21", values, []string{"requests", "top_ips", "top_paths", "cert_expiring", "nodes_summary"}, "markdown")
	for _, want := range []string{
		"| 节点 | 请求 | 拦截 | 独立IP | 备注 |",
		"| --- | ---: | ---: | ---: | --- |",
		"| slave-a | 22014 | 156 | 402 | — |",
		"| slave-b | 9821 | 12 | 210 | TOP 规则 SQLi · CC 2 · 自动封禁 1 |",
		"| 攻击源 IP | 次数 |",
		"| 45.33.32.9 | 321 |",
		"| 攻击路径 | 次数 |",
		"| /login | 200 |",
		"| 域名 | 到期日 |",
		"| a.com | 2026-11-25 |",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("多值表格设计缺 %q:\n%s", want, got)
		}
	}
	// 标量指标表回归不变
	if !strings.Contains(got, "| 指标 | 数值 |") {
		t.Fatalf("标量指标表回归丢失:\n%s", got)
	}
	// 旧列表形态不得残留于这些项
	if strings.Contains(got, "- 45.33.32.9") || strings.Contains(got, "- a.com") {
		t.Fatalf("多值项不得再回退裸列表（可解析行）:\n%s", got)
	}
}

// fail-safe：解析失败的行（如数据损坏节点）整项回退旧「加粗标签+列表」形态。
func TestRenderDailyMarkdown_multiValueFallbackOnBadLine(t *testing.T) {
	values := map[string]string{
		"nodes_summary": "slave-a：请求 22014 · 拦截 156 · 独立IP 402\nbad-node：数据损坏",
	}
	got := renderDailyFromValues("2026-11-21", values, []string{"nodes_summary"}, "markdown")
	if strings.Contains(got, "| 节点 |") {
		t.Fatalf("含不可解析行时不得出表格（回退列表）:\n%s", got)
	}
	if !strings.Contains(got, "**各节点摘要**") || !strings.Contains(got, "- bad-node：数据损坏") {
		t.Fatalf("回退形态必须保留加粗标签+列表:\n%s", got)
	}
}
