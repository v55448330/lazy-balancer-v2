package notify

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// —— 模板作用域与通道形态（模板三来源对齐）——

func scopeTestEventMessage() Message {
	return Message{EventType: "cert.failed", Level: "warn", Title: "证书签发失败",
		Body: "rule-a 的证书任务失败", Node: "node-a", Time: time.Now(),
		Fields: map[string]string{"rule": "rule-a"}}
}

func scopeTestDailyMessage() Message {
	body := `{"date":"2026-11-24","items":["requests","blocked"],"values":{"requests":"100","blocked":"3","brand":"Lazy Balancer"},"formats":{}}`
	return Message{EventType: EvtDailyReport, Level: "info", Title: "每日日报", Body: body,
		Node: "node-a", Time: time.Now(), Fields: DailyFieldsFromBody(body)}
}

func scopeTestWebhook(t *testing.T, style, channelTpl string, msg Message) (map[string]any, string) {
	t.Helper()
	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ = io.ReadAll(r.Body)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	res := sendOneChannel(context.Background(),
		deliveryTarget{Type: "webhook", Target: `{"url":"` + srv.URL + `"}`, StyleConfig: style}, channelTpl, "", msg)
	if !res.sent {
		t.Fatalf("webhook send failed: %s", res.errMsg)
	}
	var top map[string]any
	_ = json.Unmarshal(raw, &top)
	return top, string(raw)
}

// scopeTestEmail 发送一封邮件并返回 (Content-Type 头, 解码后的正文)。
func scopeTestEmail(t *testing.T, style, channelTpl string, msg Message) (string, string) {
	t.Helper()
	newNotifySettingsDB(t)
	srv := newFakeSMTPServer(t)
	host, port, _ := net.SplitHostPort(srv.addr())
	if err := SetSettings(map[string]string{KeySMTPHost: host, KeySMTPPort: port, KeySMTPFrom: "lb@example.com", KeySMTPTLS: "0"}); err != nil {
		t.Fatalf("SetSettings: %v", err)
	}
	t.Cleanup(func() { _ = SetSettings(map[string]string{KeySMTPHost: "", KeySMTPPort: "", KeySMTPFrom: ""}) })
	res := sendOneChannel(context.Background(),
		deliveryTarget{Type: "email", Target: `{"email":"ops@example.com"}`, StyleConfig: style}, channelTpl, "", msg)
	if !res.sent {
		t.Fatalf("email send failed: %s", res.errMsg)
	}
	_, _, data := srv.capture()
	contentType := ""
	var b64 strings.Builder
	inBody := false
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "Content-Type:") {
			contentType = line
		}
		if inBody && line != "" {
			b64.WriteString(line)
		}
		if line == "" {
			inBody = true
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(b64.String())
	if err != nil {
		t.Fatalf("正文 base64 解码失败: %v", err)
	}
	return contentType, string(decoded)
}

// 日报模板与事件模板必须是两套键：日报卡写入的正文模板只作用于日报；事件
// 消息只认事件正文模板（API 写入的既有语义）。存量行按「显式 daily_mode 或
// 含日报变量」归一为日报模板——否则日报卡一保存，事件通知就会被同一条
// 模板改写（机器人丢标题正文、webhook 载荷非法 JSON）。
func TestChannelStyle_dailyTemplatesSeparatedFromEventTemplates(t *testing.T) {
	// 显式 daily_mode：日报卡产物 → 归一进 daily_*，事件键清空。
	s := ParseChannelStyle(`{"daily_mode":"template","payload_template":"{\"requests\": {{requests}}}"}`)
	if s.DailyPayloadTemplate == "" || s.PayloadTemplate != "" {
		t.Fatalf("日报卡存量模板必须归一为日报模板: %+v", s)
	}
	// 无 daily_mode 但含日报变量（显式开关上线前的存量形态）→ 同样归一日报。
	s = ParseChannelStyle(`{"body_template":"<p>{{requests}}</p>"}`)
	if s.DailyBodyTemplate == "" || s.BodyTemplate != "" {
		t.Fatalf("含日报变量的存量模板必须归一为日报模板: %+v", s)
	}
	// 无 daily_mode 且无日报变量 = 事件模板（API 写入语义）→ 保持事件侧。
	s = ParseChannelStyle(`{"payload_template":"{\"title\": {{title}}}"}`)
	if s.PayloadTemplate == "" || s.DailyPayloadTemplate != "" {
		t.Fatalf("事件模板不得被归一日报: %+v", s)
	}
	// 日报模式推断只看日报模板键。
	if !(ChannelStyle{}).DailyModuleModeEffective() {
		t.Fatal("空样式必须判模块拼装")
	}
	if (ChannelStyle{DailyPayloadTemplate: "x"}).DailyModuleModeEffective() {
		t.Fatal("有日报模板必须判模板模式")
	}
	if !(ChannelStyle{PayloadTemplate: "x"}).DailyModuleModeEffective() {
		t.Fatal("仅事件模板不影响日报模式")
	}
}

func TestSendOneChannel_dailyTemplatesNotAppliedToEvents(t *testing.T) {
	dailyStyle := `{"daily_mode":"template","daily_payload_template":"{\"date\": {{date}}, \"requests\": {{requests}}}"}`

	// webhook 事件：日报模板不套用 → 默认七键信封且合法 JSON。
	top, raw := scopeTestWebhook(t, dailyStyle, "", scopeTestEventMessage())
	if !json.Valid([]byte(raw)) {
		t.Fatalf("事件载荷必须合法 JSON: %s", raw)
	}
	if top["requests"] != nil || top["body"] == nil || top["title"] == nil {
		t.Fatalf("日报模板不得改写事件载荷: %v", top)
	}
	// webhook 日报：日报模板生效。
	top, _ = scopeTestWebhook(t, dailyStyle, "", scopeTestDailyMessage())
	if top["requests"] != "100" {
		t.Fatalf("日报模板必须作用于日报: %v", top)
	}

	// email 事件：日报 body_template 不套用 → 默认 HTML 卡片。
	emailStyle := `{"daily_mode":"template","daily_body_template":"<p>日报 {{requests}}</p>","body_format":"html"}`
	contentType, body := scopeTestEmail(t, emailStyle, "", scopeTestEventMessage())
	if !strings.Contains(contentType, "text/html") || strings.Contains(body, "日报 {{requests}}") || !strings.Contains(body, "证书签发失败") {
		t.Fatalf("日报模板不得改写事件邮件: content-type=%q body=%.160q", contentType, body)
	}
	// email 日报：日报模板生效。
	contentType, body = scopeTestEmail(t, emailStyle, "", scopeTestDailyMessage())
	if !strings.Contains(contentType, "text/html") || !strings.Contains(body, "日报 100") {
		t.Fatalf("日报模板必须作用于日报邮件: content-type=%q body=%.160q", contentType, body)
	}
}

// 规则弹框里的「事件×通道模板」按通道形态渲染：webhook 的 JSON 模板成为
// POST 载荷本体（兼容裹引号的旧写法）；邮件的 HTML 模板按 HTML 发送且占位符
// 值转义；机器人保持文本渲染。
func TestSendOneChannel_ruleTemplateRenderedByChannelForm(t *testing.T) {
	jsonTpl := "{\n  \"level\": {{level}},\n  \"title\": {{title}},\n  \"event\": {{event}}\n}"
	top, raw := scopeTestWebhook(t, `{}`, jsonTpl, scopeTestEventMessage())
	if !json.Valid([]byte(raw)) || top["event"] != "cert.failed" || top["body"] != nil {
		t.Fatalf("webhook 规则模板必须成为载荷本体: valid=%v payload=%s", json.Valid([]byte(raw)), raw)
	}

	quotedTpl := "{\n  \"level\": \"{{level}}\",\n  \"title\": \"{{title}}\"\n}"
	top, raw = scopeTestWebhook(t, `{}`, quotedTpl, scopeTestEventMessage())
	if !json.Valid([]byte(raw)) || top["level"] != "warn" || !strings.Contains(top["title"].(string), "证书签发失败") {
		t.Fatalf("裹引号旧模板必须兼容为合法 JSON: payload=%s", raw)
	}

	eventMsg := scopeTestEventMessage()
	eventMsg.Body = `<img src=x onerror=alert(1)>`
	contentType, body := scopeTestEmail(t, `{}`, "<p><b>{{title}}</b>{{body}}</p>", eventMsg)
	if !strings.Contains(contentType, "text/html") {
		t.Fatalf("邮件规则 HTML 模板必须 text/html: %q", contentType)
	}
	if strings.Contains(body, "<img src") || !strings.Contains(body, "&lt;img") {
		t.Fatalf("邮件规则模板的占位符值必须 HTML 转义: %.200q", body)
	}
}

// 作用域显式：同一通道上「事件正文模板 + 日报模板」并存时两套键各管各的。
// 读时归一只凭行形态识别存量日报模板，必须让位给显式声明——对应 daily_*
// 键已出现（含空串）= 行已按新布局写入，事件键就是事件模板；只有「事件键
// 非空 + 无 daily_* 键 + 带 daily_mode」的未改动存量行才归一。
func TestChannelStyle_eventAndDailyTemplatesCoexist(t *testing.T) {
	const eventTpl = `{"ev": {{event}}, "title": {{title}}}`
	const dailyTpl = `{"date": {{date}}, "requests": {{requests}}}`
	style := `{"daily_mode":"template","payload_template":` + strconv.Quote(eventTpl) +
		`,"daily_payload_template":` + strconv.Quote(dailyTpl) + `}`

	// 事件：走事件模板（不被日报模板覆盖，也不退回默认信封）。
	top, _ := scopeTestWebhook(t, style, "", scopeTestEventMessage())
	if title, _ := top["title"].(string); top["ev"] != "cert.failed" || !strings.HasPrefix(title, "证书签发失败") {
		t.Fatalf("事件必须走事件模板: %v", top)
	}
	// 日报：走日报模板。
	top, _ = scopeTestWebhook(t, style, "", scopeTestDailyMessage())
	if top["requests"] != "100" {
		t.Fatalf("日报必须走日报模板: %v", top)
	}

	// 显式空 daily_* 键（带 daily_mode 的通道上写入事件模板时的作用域声明）：
	// 事件模板保持事件侧，日报仍按模块拼装。
	s := ParseChannelStyle(`{"daily_mode":"modules","daily_payload_template":"","payload_template":"{\"title\": {{title}}}"}`)
	if s.PayloadTemplate == "" || s.DailyPayloadTemplate != "" || !s.DailyModuleModeEffective() {
		t.Fatalf("显式作用域下事件模板不得被归一日报: %+v", s)
	}
}

// 存量行：自定义日报模板不含任何日报变量，只能靠显式 daily_mode 识别。发送器
// 读的是样式合并进 target 之后的 JSON——合并必须带上 daily_mode，否则这类
// 模板在投递路径上认不出来：事件被它改写，日报反而丢了模板。
func TestSendOneChannel_legacyDailyModeTemplateNotAppliedToEvents(t *testing.T) {
	legacy := `{"daily_mode":"template","payload_template":"{\"note\": \"daily-only\"}"}`

	top, _ := scopeTestWebhook(t, legacy, "", scopeTestEventMessage())
	if top["note"] != nil || top["title"] == nil {
		t.Fatalf("存量日报模板不得改写事件载荷: %v", top)
	}
	top, _ = scopeTestWebhook(t, legacy, "", scopeTestDailyMessage())
	if top["note"] != "daily-only" {
		t.Fatalf("存量日报模板必须作用于日报: %v", top)
	}
}

// 规则级 webhook 模板不是合法 JSON（保存门上线前落库、或保存门被绕过）时，
// 不得把非 JSON 文本直接当 POST 体发出——回落默认信封。
func TestSendOneChannel_ruleWebhookTemplateNonJSONFallsBackToEnvelope(t *testing.T) {
	top, raw := scopeTestWebhook(t, "{}", "plain text {{title}}", scopeTestEventMessage())
	if !json.Valid([]byte(raw)) || top["title"] == nil {
		t.Fatalf("非 JSON 规则模板必须回落默认信封: %s", raw)
	}
}

// 规则级邮件模板的发送格式由内容决定：含 HTML 标签按 text/html（占位符值
// 转义），纯文本模板按 text/plain 原文发送（换行保留）——规则弹框的格式行
// 用同一判据，预览即实发形态。
func TestSendOneChannel_ruleEmailTemplateFormatFollowsContent(t *testing.T) {
	contentType, body := scopeTestEmail(t, "{}", `<div style="color:red">{{title}}<br>{{body}}</div>`, scopeTestEventMessage())
	if !strings.Contains(contentType, "text/html") || !strings.Contains(body, "<div") || !strings.Contains(body, "证书签发失败") {
		t.Fatalf("含 HTML 标签的规则模板必须按 text/html 发送: content-type=%q body=%.160q", contentType, body)
	}
	contentType, body = scopeTestEmail(t, "{}", "{{title}}\n{{body}}", scopeTestEventMessage())
	if !strings.Contains(contentType, "text/plain") || !strings.Contains(body, "证书签发失败\nrule-a 的证书任务失败") {
		t.Fatalf("纯文本规则模板必须按 text/plain 原文发送: content-type=%q body=%.160q", contentType, body)
	}
}
