package notify

// 通道适配器注册表：每个通道类型一个 Sender（发送+测试）。发送均短连按需
// （webhook/email/MCP）或经连接管理器单例下发（QQ/微信长连由连接器 Daemon
// 维护，Sender 只把消息交给连接管理器队列——连接离线时返回明确错误）。

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Message 已渲染的通知消息（标题+正文+级别）。
// Time/Node/Fields 为通道载荷透传位：投递行当前未落这三列（deliveries 表
// 无对应列），webhook 侧 Time 零值以发送时刻兜底、Node/Fields 空值原样呈现；
// 后续投递行扩列后由投递 Daemon 透传即可，Sender 侧无需再改。
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
	// （NOTIF153-02：markdown/text 的未转义内容不得进 HTML 上下文）。
	ContentFormat string
	// TemplateApplied 事件级/事件×通道模板已在派发侧完成**全量布局渲染**——
	// Body 即最终消息，通道样式模板（机器人 content_template/邮件 body_template/
	// webhook payload_template）不得再套一层（2026-11-22 用户实测双渲染：
	// 标题/正文各两份+外层 ** 字面量泄漏）。默认链（无事件模板）不置位。
	TemplateApplied bool
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

// testNotificationMessage 通道「测试」按钮共用的测试消息。
func testNotificationMessage() Message {
	return Message{
		Level:     string(LevelInfo),
		Time:      time.Now(),
		Node:      MasterNodeLabel(),
		EventType: EvtNotifyChannelRecovered, // 占位真实事件键：{{event_title}} 等占位符有值可渲染
		Title:     "通知中心测试消息",
		Body:      "这是一条来自通知中心的测试消息；收到即表示该通道配置有效。",
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
