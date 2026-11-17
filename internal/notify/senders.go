package notify

// 通道适配器注册表：每个通道类型一个 Sender（发送+测试）。发送均短连按需
// （webhook/email/MCP）或经连接管理器单例下发（QQ/微信长连由连接器 Daemon
// 维护，Sender 只把消息交给连接管理器队列——连接离线时返回明确错误）。

import (
	"context"
	"fmt"
	"sync"
)

// Message 已渲染的通知消息（标题+正文+级别）。
type Message struct {
	EventType string
	Level     string
	Title     string
	Body      string
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
