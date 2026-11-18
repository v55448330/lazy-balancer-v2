package notify

// 日报按通道格式渲染钉测（用户裁定「不同通道用不同样式」）：
//   - 非日报事件原样透传（渲染挂钩不得影响其它事件）
//   - 载荷解析失败回退原文（fail-visible）
//   - 通道映射：webhook=JSON / email=HTML / qq·wx=markdown / 未知=text
//   - items 裁剪在载荷侧已定（勾选项目之外不渲染）

import (
	"strings"
	"testing"
)

func dailyPayloadBody(items []string) string {
	return `{"date":"2026-11-17","items":["requests","blocked"],"values":{"requests":"1200","blocked":"34","attack_top":"sql-i","autoban":"2","cert_status":"活跃 3 / 失败 0","cluster_status":"正常（主节点）"}}`
}

func TestRenderDailyForChannel_nonDailyPassThrough(t *testing.T) {
	msg := Message{EventType: "auth.login_success", Body: "原文正文"}
	if got := renderDailyForChannel(msg, "webhook"); got != "原文正文" {
		t.Fatalf("非日报事件被改写: %q", got)
	}
}

func TestRenderDailyForChannel_corruptPayloadFallsBack(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: "not-json{{"}
	if got := renderDailyForChannel(msg, "webhook"); got != "not-json{{" {
		t.Fatalf("坏载荷未回退原文: %q", got)
	}
}

func TestRenderDailyForChannel_channelFormats(t *testing.T) {
	msg := Message{EventType: EvtDailyReport, Body: dailyPayloadBody(nil), Title: "每日日报"}

	webhook := renderDailyForChannel(msg, "webhook")
	if !strings.Contains(webhook, `"requests": "1200"`) || strings.Contains(webhook, "attack_top") {
		t.Fatalf("webhook 渲染非 JSON 或未按 items 裁剪: %s", webhook)
	}

	email := renderDailyForChannel(msg, "email")
	if !strings.Contains(email, "<h3>") || !strings.Contains(email, "1200") || strings.Contains(email, "攻击") {
		t.Fatalf("email 渲染非 HTML 或未裁剪: %s", email)
	}

	qq := renderDailyForChannel(msg, "qq")
	if !strings.Contains(qq, "- **请求数**：1200") || strings.Contains(qq, "攻击") {
		t.Fatalf("qq 渲染非 markdown 或未裁剪: %s", qq)
	}

	wx := renderDailyForChannel(msg, "wx_clawbot")
	if !strings.Contains(wx, "- **拦截次数**：34") {
		t.Fatalf("wx 渲染异常: %s", wx)
	}

	text := renderDailyForChannel(msg, "mcp_push")
	if !strings.Contains(text, "请求数：1200") || strings.Contains(text, "<") {
		t.Fatalf("未知通道兜底非纯文本: %s", text)
	}
}
