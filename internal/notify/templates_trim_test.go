package notify

// 参数超配截断钉测：测试样例统一供 6 参而事件模板动词数不同，超配不得产出
// %!(EXTRA …)；事件模板渲染结果经 renderDailyForChannel 非日报透传不被覆盖。

import (
	"strings"
	"testing"
	"time"
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
	msg := Message{EventType: EvtDailyReport, Body: dailyPayloadBody()}
	got := renderDailyForChannel(msg, "qq", "text")
	if !strings.Contains(got, "| 请求数 |") {
		t.Fatalf("qq 日报应为 markdown 表格（协议固定）: %q", got)
	}
	wx := renderDailyForChannel(msg, "wx_clawbot", "markdown")
	if strings.Contains(wx, "|") {
		t.Fatalf("wx 日报应为纯文本（协议固定）: %q", wx)
	}
}

func TestRenderTitle_zeroVerbNoExtra(t *testing.T) {
	// 标题 0 动词 + 测试 6 参：不得产出 %!(EXTRA …)。
	entry := catalogEntry{ID: EvtClusterOffline, TitleFormat: "集群节点失联", BodyFormat: "节点 %s 失联（最后活动 %s）"}
	evt := Event{Type: EvtClusterOffline, Fields: map[string]string{"1": "example.com", "2": "示例详情", "3": "样例来源", "4": "3", "5": "样例", "6": "样例"}}
	if got := renderTitle(entry, evt); got != "集群节点失联" {
		t.Fatalf("0 动词标题超配: %q", got)
	}
	if got := renderBody(entry, evt); strings.Contains(got, "EXTRA") {
		t.Fatalf("正文超配: %q", got)
	}
}

func TestRenderBody_stringDaysNoVerbMismatch(t *testing.T) {
	// Fields 全字符串：%d 动词会产 %!d(string=3)；目录已改 %s。
	entry, _ := catalogByID(EvtAPIKeyExpiryWarning)
	evt := Event{Type: EvtAPIKeyExpiryWarning, Fields: map[string]string{"1": "test1", "2": "2026-11-23", "3": "3"}}
	got := renderBody(entry, evt)
	if strings.Contains(got, "%!") || !strings.Contains(got, "剩余 3 天") {
		t.Fatalf("字符串参数动词不匹配: %q", got)
	}
}

func TestBotTemplate_nodeAndEventTitleRendered(t *testing.T) {
	// {{node}}/{{event_title}} 必须被替换，不得残留字面量；事件元信息用可读标题。
	msg := Message{EventType: EvtAPIKeyExpiryWarning, Title: "API 密钥临期", Body: "正文", Node: "node-a", Level: "warn"}
	got := renderBotMessage("", msg, time.Now(), "qq")
	if strings.Contains(got, "{{node}}") || strings.Contains(got, "{{event_title}}") || strings.Contains(got, "{{event}}") {
		t.Fatalf("bot 模板变量残留: %q", got)
	}
	if !strings.Contains(got, "node-a") || !strings.Contains(got, "API 密钥临期") || strings.Contains(got, "apikey.expiry_warning") {
		t.Fatalf("bot 元信息应可读标题+节点: %q", got)
	}
}

func TestEventDisplayTitle(t *testing.T) {
	if got := eventDisplayTitle(EvtAPIKeyExpiryWarning); got != "API 密钥临期" {
		t.Fatalf("可读标题=%q", got)
	}
	if got := eventDisplayTitle(EvtClusterOffline); got != "集群节点失联" {
		t.Fatalf("0 动词标题=%q", got)
	}
}
