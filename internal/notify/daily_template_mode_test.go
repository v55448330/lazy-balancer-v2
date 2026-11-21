package notify

// 日报「模板模式」变量全量替换钉测（2026-11-22 用户裁定：模块选择与自定义
// 正文模板二选一——选模板时用户自行写样式+放置变量，全部日常变量可用）。
// 缺陷形态：机器人模板只认 7 个日报变量子集；邮件/Webhook 模板对日报变量
// 完全不替换（原样保留 {{requests}}），模板对日报形同无效。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// 机器人模板：7 个子集之外的日常变量（allowed/distinct_ips/nodes_summary）同样替换。
func TestFormatBotTextWithTemplate_replacesAllDailyFields(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Body: "渲染成品",
		Fields: map[string]string{
			"date": "2026-11-21", "requests": "1200", "allowed": "1100",
			"distinct_ips": "88", "nodes_summary": "slave-a：请求 44", "top_ips": "1.2.3.4×9",
		}}
	tpl := "请求 {{requests}} 放行 {{allowed}}\n独立IP {{distinct_ips}}\n节点 {{nodes_summary}}\nTOP IP {{top_ips}}"
	got := formatBotTextWithTemplate(tpl, msg, time.Now())
	for _, want := range []string{"请求 1200 放行 1100", "独立IP 88", "slave-a：请求 44", "1.2.3.4×9"} {
		if !strings.Contains(got, want) {
			t.Fatalf("变量未替换 %q: %s", want, got)
		}
	}
	if strings.Contains(got, "{{") {
		t.Fatalf("残留未替换变量: %s", got)
	}
}

// 邮件模板（renderStyleTemplate）：日报变量同样替换（此前完全不认）。
func TestRenderStyleTemplate_replacesDailyFields(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Body: "<p>成品</p>",
		Fields: map[string]string{"date": "2026-11-21", "requests": "1200", "nodes_summary": "节点甲：拦截 3"}}
	got := renderStyleTemplate(`<h1>日报 {{date}}</h1><p>请求 {{requests}}</p><div>{{nodes_summary}}</div>{{body}}`, msg, time.Now())
	for _, want := range []string{"2026-11-21", "请求 1200", "节点甲：拦截 3", "<p>成品</p>"} {
		if !strings.Contains(got, want) {
			t.Fatalf("邮件模板变量未替换 %q: %s", want, got)
		}
	}
	if strings.Contains(got, "{{requests}}") {
		t.Fatalf("残留未替换变量: %s", got)
	}
}

// Webhook JSON 模板：日报变量经 JSON 编码嵌入，输出必须是合法 JSON。
func TestRenderStyleTemplateJSON_replacesDailyFields(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Body: "成品",
		Fields: map[string]string{"date": "2026-11-21", "requests": "1200", "nodes_summary": "节点甲：拦截 3"}}
	tpl := `{"title": {{title}},"date": {{date}},"requests": {{requests}},"nodes": {{nodes_summary}}}`
	got := renderStyleTemplateJSON(tpl, msg, time.Now())
	var obj map[string]any
	if err := json.Unmarshal([]byte(got), &obj); err != nil {
		t.Fatalf("日报 JSON 模板非合法 JSON（变量未编码或未替换）: %v\n%s", err, got)
	}
	if obj["date"] != "2026-11-21" || obj["requests"] != "1200" || obj["nodes"] != "节点甲：拦截 3" {
		t.Fatalf("变量值错误: %v", obj)
	}
}

// 回归：非日报消息携带同名字段也不得被替换（事件模板不受日报变量影响）。
func TestRenderStyleTemplate_eventIgnoresDailyFields(t *testing.T) {
	msg := Message{EventType: "cfg.caddy_apply_failed", Title: "t", Body: "b"}
	got := renderStyleTemplate(`{{title}} {{requests}}`, msg, time.Now())
	if !strings.Contains(got, "{{requests}}") {
		t.Fatalf("非日报未知占位符应原样保留: %s", got)
	}
}

// 各节点摘要三格式渲染（markdown/html/text 都必须带节点行——集群视角可见）。
func TestRenderDaily_includesNodesSummaryAllFormats(t *testing.T) {
	data := DailyData{Date: "2026-11-21", Requests: 1200, Blocked: 30,
		NodesSummary: "slave-a：请求 22014 · 拦截 156 · 独立IP 402\nslave-b：请求 9821 · 拦截 12 · 独立IP 210"}
	items := []string{"requests", "blocked", "cluster_status", "nodes_summary", "uptime"}
	for _, format := range []string{"markdown", "html", "text", "json"} {
		got := RenderDaily(data, items, format)
		if !strings.Contains(got, "slave-a") || !strings.Contains(got, "slave-b") {
			t.Fatalf("format=%s 缺各节点摘要行:\n%s", format, got)
		}
	}
	// 未勾选 nodes_summary 时不得出现（模块裁剪契约）
	got := RenderDaily(data, []string{"requests", "blocked", "cluster_status"}, "markdown")
	if strings.Contains(got, "slave-a") {
		t.Fatalf("未勾选 nodes_summary 却渲染了节点行:\n%s", got)
	}
}

// 级别汉化（用户裁定 2026-11-22 第三轮）：中文消息里不再出现英文级别词——
// 机器人/邮件模板 {{level}} 渲染中文；webhook 默认载荷保留机器枚举并补 level_label。
func TestLevelLabelZh_rendersInTemplates(t *testing.T) {
	if got := levelLabelZh("critical"); got != "严重" || levelLabelZh("warn") != "警告" || levelLabelZh("info") != "信息" {
		t.Fatalf("级别映射=%q/%q/%q，want 严重/警告/信息", levelLabelZh("critical"), levelLabelZh("warn"), levelLabelZh("info"))
	}
	msg := Message{EventType: "cfg.caddy_apply_failed", Level: "warn", Title: "t", Body: "b"}
	if got := formatBotTextWithTemplate("级别 {{level}}", msg, time.Now()); got != "级别 警告" {
		t.Fatalf("机器人模板级别=%q，want 中文", got)
	}
	if got := renderStyleTemplate("级别 {{level}}", msg, time.Now()); got != "级别 警告" {
		t.Fatalf("邮件模板级别=%q，want 中文", got)
	}
	if got := renderStyleTemplateJSON(`{"level": {{level}}}`, msg, time.Now()); got != `{"level": "warn"}` {
		t.Fatalf("webhook JSON 模板级别=%q，want 保留机器枚举", got)
	}
}

// 从节点标签拼装（name+ip:port；地址缺失退化）。
func TestSlaveNodeLabel_formats(t *testing.T) {
	if got := SlaveNodeLabel("s1", "10.1.1.2", 8001); got != "从节点 s1(10.1.1.2:8001)" {
		t.Fatalf("标签=%q", got)
	}
	if got := SlaveNodeLabel("s1", "", 0); got != "从节点 s1" {
		t.Fatalf("缺地址标签=%q", got)
	}
}
