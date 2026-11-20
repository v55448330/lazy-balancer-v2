package notify

// 日报按通道格式渲染钉测（用户裁定「不同通道用不同样式」）：
//   - 非日报事件原样透传（渲染挂钩不得影响其它事件）
//   - 载荷解析失败回退原文（fail-visible）
//   - 通道映射：webhook=JSON / email=HTML / qq=markdown / wx=纯文本 / 未知=text
//   - items 裁剪在载荷侧已定（勾选项目之外不渲染）

import (
	"strings"
	"testing"
	"time"
)

func dailyPayloadBody(items []string) string {
	return `{"date":"2026-11-17","items":["requests","blocked"],"values":{"requests":"1200","blocked":"34","attack_top":"sql-i","autoban":"2","cert_status":"活跃 3 / 失败 0","cluster_status":"正常（主节点）"}}`
}

func TestRenderDailyForChannel_nonDailyPassThrough(t *testing.T) {
	msg := Message{EventType: "auth.login_success", Body: "原文正文"}
	if got := renderDailyForChannel(msg, "webhook", ""); got != "原文正文" {
		t.Fatalf("非日报事件被改写: %q", got)
	}
}

func TestRenderDailyForChannel_corruptPayloadFallsBack(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: "not-json{{"}
	if got := renderDailyForChannel(msg, "webhook", ""); got != "not-json{{" {
		t.Fatalf("坏载荷未回退原文: %q", got)
	}
}

func TestRenderDailyForChannel_channelFormats(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: dailyPayloadBody(nil), Title: "每日日报"}

	webhook := renderDailyForChannel(msg, "webhook", "")
	if !strings.Contains(webhook, `"requests": "1200"`) || strings.Contains(webhook, "attack_top") {
		t.Fatalf("webhook 渲染非 JSON 或未按 items 裁剪: %s", webhook)
	}

	email := renderDailyForChannel(msg, "email", "")
	if !strings.Contains(email, "<table") || !strings.Contains(email, "1200") || strings.Contains(email, "攻击") {
		t.Fatalf("email 渲染非 HTML 或未裁剪: %s", email)
	}

	qq := renderDailyForChannel(msg, "qq", "")
	if !strings.Contains(qq, "| 请求数 | 1200 |") || strings.Contains(qq, "攻击") {
		t.Fatalf("qq 渲染非 markdown 表格（QQ 实测支持表格）或未裁剪: %s", qq)
	}

	wx := renderDailyForChannel(msg, "wx_clawbot", "")
	if !strings.Contains(wx, "拦截次数：34") || strings.Contains(wx, "**") {
		t.Fatalf("wx 应为纯文本协议（无 markdown 标记）: %s", wx)
	}

	text := renderDailyForChannel(msg, "mcp_push", "")
	if !strings.Contains(text, "请求数：1200") || strings.Contains(text, "<") {
		t.Fatalf("未知通道兜底非纯文本: %s", text)
	}
}

// TestRenderDailyForChannel_styleOverride 机器人协议固定（qq 样式 text 不生效，
// 缺省 markdown）；非机器人通道卡 daily_format 覆盖自动映射；日报页 per-channel
// 配置优先于一切。
func TestRenderDailyForChannel_styleOverride(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: dailyPayloadBody(nil), Title: "每日日报"}
	got := renderDailyForChannel(msg, "qq", "text")
	if !strings.Contains(got, "| 请求数 | 1200 |") {
		t.Fatalf("qq 协议固定应 markdown（样式 text 不覆盖）: %q", got)
	}
	// 非机器人：通道卡 daily_format=text 覆盖自动映射（webhook 缺省 json）。
	wh := renderDailyForChannel(msg, "webhook", "text")
	if strings.Contains(wh, "{") || !strings.Contains(wh, "请求数：1200") {
		t.Fatalf("webhook style 覆盖未生效（应纯文本）: %q", wh)
	}
	// 机器人协议固定优先于一切配置：payload.formats.qq=text 仍 markdown。
	msg.Body = strings.Replace(dailyPayloadBody(nil),
		`"values":`, `"formats":{"qq":"text"},"values":`, 1)
	got = renderDailyForChannel(msg, "qq", "text")
	if !strings.Contains(got, "| 请求数 | 1200 |") {
		t.Fatalf("qq 协议固定应不受配置覆盖: %q", got)
	}
	// 非机器人日报页配置优先：payload.formats.webhook=html → html 胜出。
	msg.Body = strings.Replace(dailyPayloadBody(nil),
		`"values":`, `"formats":{"webhook":"html"},"values":`, 1)
	wh = renderDailyForChannel(msg, "webhook", "text")
	if !strings.Contains(wh, "<table") {
		t.Fatalf("日报页配置未优先于通道样式: %q", wh)
	}
}

// TestFormatBotTextWithTemplate_dailyVariables 日报内容模板变量替换：
// deliverOne 注入 msg.Fields（载荷 values+date）后，{{requests}}/{{date}} 等
// 被替换；{{body}} 仍为渲染成品；非日报消息无这些键不替换。
func TestFormatBotTextWithTemplate_dailyVariables(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Title: "每日日报", Body: "渲染成品",
		Fields: map[string]string{"date": "2026-11-17", "requests": "1200", "blocked": "34"}}
	tpl := "# 日报 {{date}}\n请求 {{requests}} 拦截 {{blocked}}\n{{body}}"
	got := formatBotTextWithTemplate(tpl, msg, time.Now())
	for _, want := range []string{"# 日报 2026-11-17", "请求 1200 拦截 34", "渲染成品"} {
		if !strings.Contains(got, want) {
			t.Fatalf("日报变量未替换 %q: %s", want, got)
		}
	}
	if strings.Contains(got, "{{requests}}") {
		t.Fatalf("残留未替换变量: %s", got)
	}
}
