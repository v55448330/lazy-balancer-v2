package notify

// 参数超配截断钉测：测试样例统一供 6 参而事件模板动词数不同，超配不得产出
// %!(EXTRA …)；事件模板渲染结果经 renderDailyForChannel 非日报透传不被覆盖。

import (
	"strings"
	"testing"
)

func TestRenderBody_trimsExtraArgs(t *testing.T) {
	entry := catalogEntry{ID: EvtCertIssued, TitleFormat: "证书签发成功", BodyFormat: "%s 签发成功（%s）"}
	evt := Event{Type: EvtCertIssued, Fields: map[string]string{
		"1": "example.com", "2": "示例详情", "3": "样例来源", "4": "3", "5": "样例", "6": "样例",
	}}
	body := renderBody(entry, evt)
	if strings.Contains(body, "EXTRA") || strings.Contains(body, "%!") {
		t.Fatalf("超配参数未截断: %q", body)
	}
	if body != "example.com 签发成功（示例详情）" {
		t.Fatalf("正文=%q, want 前 two 参渲染", body)
	}
}

func TestRenderDailyForChannel_eventPassthrough(t *testing.T) {
	// 非日报：renderDailyForChannel 必须原样透传（保留上游事件模板渲染结果）。
	msg := Message{EventType: EvtCertIssued, Body: "事件模板渲染成品"}
	if got := renderDailyForChannel(msg, "qq", "text"); got != "事件模板渲染成品" {
		t.Fatalf("事件正文被覆盖: %q", got)
	}
}

func TestRenderDailyForChannel_qqProtocolMarkdown(t *testing.T) {
	// 机器人协议固定：qq 缺省=markdown 表格，通道样式 text 不得覆盖。
	msg := Message{EventType: EvtDailyReport, Body: dailyPayloadBody(nil)}
	got := renderDailyForChannel(msg, "qq", "text")
	if !strings.Contains(got, "| 请求数 |") {
		t.Fatalf("qq 日报应为 markdown 表格（协议固定）: %q", got)
	}
	wx := renderDailyForChannel(msg, "wx_clawbot", "markdown")
	if strings.Contains(wx, "|") {
		t.Fatalf("wx 日报应为纯文本（协议固定）: %q", wx)
	}
}
