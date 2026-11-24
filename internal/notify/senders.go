package notify

// 通道适配器注册表：每个通道类型一个 Sender（发送+测试）。发送均短连按需
// （webhook/email/MCP）或经连接管理器单例下发（QQ/微信长连由连接器 Daemon
// 维护，Sender 只把消息交给连接管理器队列——连接离线时返回明确错误）。

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"
)

// Message 已渲染的通知消息（标题+正文+级别）。
// Time/Node/Fields 为通道载荷透传位：投递行已落 node 列（pendingDeliveries
// 回读后由 deliverOne 透传 Node）；Time 未落列——webhook 载荷以发送时刻兜底
// 零值；Fields 仅日报由载荷 values 注入（模板 {{requests}} 等变量源），其他
// 事件为空。
type Message struct {
	EventType string
	Level     string
	Title     string
	Body      string
	Time      time.Time
	Node      string
	Fields    map[string]string
	// ContentFormat 已渲染正文的实际格式（"html"/"markdown"/"text"/"json"；
	// 空=未标注）。日报按通道渲染时由派发侧写入（renderDailyForChannelFormat），
	// 邮件通道据此决定 Content-Type——只有 html 渲染可按 text/html 发送
	// （markdown/text 的未转义内容不得进 HTML 上下文）。
	ContentFormat string
	// TemplateApplied 事件级/事件×通道模板已在派发侧完成**全量布局渲染**——
	// Body 即最终消息，通道样式模板（机器人 content_template/邮件 body_template/
	// webhook payload_template）不得再套一层（2026-11-22 用户实测双渲染：
	// 标题/正文各两份+外层 ** 字面量泄漏）。默认链（无事件模板）不置位。
	TemplateApplied bool
	// TemplateFormat TemplateApplied 正文的通道形态（规则级通道模板按通道
	// 渲染时由派发侧写入）："json"=Body 已是 webhook 载荷 JSON 文本（可直接
	// 作为 POST 体）；"html"=Body 已是转义后的 HTML（邮件按 text/html 发送）；
	// 空=文本/markdown 布局（webhook 进默认信封、邮件 text/plain 原文直发）。
	// 事件级模板（所有通道共用一份文本版式）不置位，维持文本语义。
	TemplateFormat string
	// DailyModuleMode 日报渲染模式=模块拼装（通道 style_config.daily_mode
	// 显式选择/存量推断，daemon 派发时置位）：该通道已存正文模板保留但不
	// 生效，日报走 items 分节渲染（2026-11-22 二选一显式开关）。
	DailyModuleMode bool
}

// dailyTemplatesSuppressed 日报是否抑制通道正文模板（模块拼装模式）；
// 事件消息不受影响。
func (m Message) dailyTemplatesSuppressed() bool {
	return m.EventType == EvtDailyReport && m.DailyModuleMode
}

// RegisterSenderForTest 测试用通道替换（注册表同名覆盖走后复原）。
func RegisterSenderForTest(t *testing.T, typ string, s Sender) {
	t.Helper()
	sendersMu.Lock()
	old, had := senders[typ]
	senders[typ] = s
	sendersMu.Unlock()
	t.Cleanup(func() {
		sendersMu.Lock()
		if had {
			senders[typ] = old
		} else {
			delete(senders, typ)
		}
		sendersMu.Unlock()
	})
}

// channelValidationBody 通道验证/绑定成功共用的视觉结构：标题由调用方给，
// 正文在 QQ 文本、微信纯文本、邮件 HTML 三端都保持同一信息层级。
func channelValidationBody(channel, note string) string {
	return "✅ 通道连接正常\n────────────\n通道：" + channel + "\n状态：消息可达，配置有效\n说明：" + note
}

// testNotificationMessage 通道「测试」按钮共用的测试消息。
func testNotificationMessage() Message {
	return testNotificationMessageFor("通知通道")
}

// testNotificationMessageFor 通道测试消息（带通道名，三端统一文案）。
func testNotificationMessageFor(channel string) Message {
	return Message{
		Level:     string(LevelInfo),
		Time:      time.Now(),
		Node:      MasterNodeLabel(),
		EventType: "",
		Title:     "通知通道验证成功",
		Body:      channelValidationBody(channel, "收到这条消息，表示该通道已可用于接收通知。"),
	}
}

// Sender 通道发送适配器。
type Sender interface {
	// Send 把一条消息投递到通道目标。target 为通道 JSON 配置的解码形态，
	// 实现侧自行解析（字段契约见各实现）。
	Send(ctx context.Context, targetJSON string, msg Message) error
	// Test 发送一条测试消息（通道卡片「测试」按钮）。
	Test(ctx context.Context, targetJSON string) error
}

var (
	sendersMu sync.RWMutex
	senders   = map[string]Sender{}
)

// RegisterSender 注册通道适配器（同名覆盖仅限测试）。
func RegisterSender(typ string, s Sender) {
	sendersMu.Lock()
	defer sendersMu.Unlock()
	senders[typ] = s
}

// senderFor 取通道适配器。
func senderFor(typ string) (Sender, error) {
	sendersMu.RLock()
	defer sendersMu.RUnlock()
	s, ok := senders[typ]
	if !ok {
		return nil, fmt.Errorf("未知通知通道类型 %q", typ)
	}
	return s, nil
}

// sendToChannel 单通道发送（含测试形态）。错误原样返回（调用方留痕/重试）。
func sendToChannel(ctx context.Context, typ, targetJSON string, msg Message) error {
	s, err := senderFor(typ)
	if err != nil {
		return err
	}
	return s.Send(ctx, targetJSON, msg)
}

// testChannel 通道测试（发送测试消息）。
func testChannel(ctx context.Context, typ, targetJSON string) error {
	s, err := senderFor(typ)
	if err != nil {
		return err
	}
	return s.Test(ctx, targetJSON)
}

// TestChannel 通道测试（导出：handlers 通知中心「测试」按钮）。
func TestChannel(ctx context.Context, typ, targetJSON string) error {
	return testChannel(ctx, typ, targetJSON)
}
