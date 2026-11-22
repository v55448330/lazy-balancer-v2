package notify

// 日报富项渲染钉测：新增明细项（TOP IP/临期证书/运行时长/威胁库）进入分节渲染，
// items 裁剪仍生效；markdown/text/html 三形态口径一致。

import (
	"strings"
	"testing"
	"time"
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

// 空值项目四格式真正省略（不渲染「各节点摘要」空行）。
// 单机默认配置下 nodes_summary 恒空——旧实现每份日报都带一行空标签。
func TestRenderDailyOmitsEmptyValuesAllFormats(t *testing.T) {
	values := map[string]string{
		"requests":       "1200",
		"cluster_status": "正常（主节点）",
		"nodes_summary":  "", // 单机：无从节点
		"uptime":         "3 天",
	}
	items := []string{"cluster_status", "nodes_summary", "uptime", "requests"}
	cases := []struct {
		format string
		marker string // 空值标签/键不得出现的形态
	}{
		{"html", "各节点摘要"},
		{"markdown", "各节点摘要"},
		{"text", "各节点摘要"},
		{"json", `"nodes_summary"`},
	}
	for _, c := range cases {
		got := renderDailyFromValues("2026-11-21", values, items, c.format)
		if strings.Contains(got, c.marker) {
			t.Fatalf("format=%s 空值 nodes_summary 仍渲染 %q:\n%s", c.format, c.marker, got)
		}
	}
	// 有值时照常渲染（省略规则只针对空值，不能吞掉正常数据）。
	values["nodes_summary"] = "slave-a：请求 44 · 拦截 1 · 独立IP 3"
	if got := renderDailyFromValues("2026-11-21", values, items, "markdown"); !strings.Contains(got, "各节点摘要") {
		t.Fatalf("有值 nodes_summary 被误省略:\n%s", got)
	}
}

// 多值表格 fail-safe 回退分支也必须留块间空行——坏行项
// （回退列表）与良行项（表格）相邻时，下一块标签/表头不得被上一块吞并。
func TestRenderDailyMarkdown_fallbackBlockSeparated(t *testing.T) {
	values := map[string]string{
		"top_ips":   "1.2.3.4 ×9\nbogus-line-without-count",
		"top_paths": "/login ×200\n/api ×150",
	}
	got := renderDailyFromValues("2026-11-21", values, []string{"top_ips", "top_paths"}, "markdown")
	if !strings.Contains(got, "- bogus-line-without-count\n\n**TOP 攻击路径**") {
		t.Fatalf("回退列表与下一块之间缺空行（标签会被吞）:\n%s", got)
	}
	if !strings.Contains(got, "| /login | 200 |") {
		t.Fatalf("良行项表格缺失:\n%s", got)
	}
}

// 自定义模板（QQ markdown）的多值日报变量同样出语义表格（2026-11-22 用户
// 裁定：模板里 {{top_ips}}/{{cert_expiring}}/{{nodes_summary}} 不能是裸行——
// 与内置模板同族设计）。模板提供上下文标签，变量只展开表格本体。
func TestBotDailyTemplate_multiValueVarsAsTables(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Body: "成品",
		Fields: map[string]string{
			"top_ips":       "45.33.32.9 ×321\n1.2.3.4 ×120",
			"cert_expiring": "a.com · 2026-11-25",
			"nodes_summary": "slave-a：请求 22014 · 拦截 156 · 独立IP 402",
			"requests":      "1200",
		}}
	tpl := "**TOP 攻击源 IP**\n{{top_ips}}\n**临期证书明细**\n{{cert_expiring}}\n**各节点摘要**\n{{nodes_summary}}\n请求 {{requests}}"
	got := renderBotMessage(tpl, msg, time.Unix(0, 0), "qq")
	for _, want := range []string{
		"| 攻击源 IP | 次数 |", "| 45.33.32.9 | 321 |",
		"| 域名 | 到期日 |", "| a.com | 2026-11-25 |",
		"| 节点 | 请求 | 拦截 | 独立IP | 备注 |", "| slave-a | 22014 | 156 | 402 | — |",
		"请求 1200",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("自定义模板多值变量缺表格 %q:\n%s", want, got)
		}
	}
	// 微信（纯文本协议）不得注入 markdown 表格标记
	gotWx := renderBotMessage(tpl, msg, time.Unix(0, 0), "wx_clawbot")
	if strings.Contains(gotWx, "| 域名 |") || strings.Contains(gotWx, "| ---") {
		t.Fatalf("微信通道不得注入 markdown 表格:\n%s", gotWx)
	}
}

// 多值块空行契约（2026-11-22 用户实测攻击路径表头被吞成数据行）：标签与表格
// 之间、相邻块之间必须空行——粘连时 markdown 解析器把下一块标签/表头/分隔行
// 吞成上一表的正文行。钉内置链与自定义模板变量两侧的产出形态。
func TestDailyMultiValueBlocksBlankLineSeparated(t *testing.T) {
	values := map[string]string{
		"top_ips":   "45.33.32.9 ×321\n1.2.3.4 ×120",
		"top_paths": "/login ×200\n/api ×150",
	}
	md := renderDailyFromValues("2026-11-21", values, []string{"top_ips", "top_paths"}, "markdown")
	if !strings.Contains(md, "**TOP 攻击源 IP**\n\n| 攻击源 IP | 次数 |") {
		t.Fatalf("标签与表格间须空行:\n%q", md)
	}
	if !strings.Contains(md, "| 1.2.3.4 | 120 |\n\n**TOP 攻击路径**") {
		t.Fatalf("相邻块之间须空行（否则表头被吞）:\n%q", md)
	}

	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Fields: map[string]string{
		"top_ips": "45.33.32.9 ×321", "top_paths": "/login ×200",
	}}
	got := renderBotMessage("**A**\n{{top_ips}}\n**B**\n{{top_paths}}", msg, time.Unix(0, 0), "qq")
	if !strings.Contains(got, "**A**\n\n| 攻击源 IP | 次数 |") {
		t.Fatalf("自定义模板变量展开后标签与表格间须空行:\n%q", got)
	}
	if !strings.Contains(got, "| 45.33.32.9 | 321 |\n\n**B**") {
		t.Fatalf("变量表格后与下一标签间须空行:\n%q", got)
	}
}
