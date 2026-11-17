// Package notify 通知中心核心：事件目录、发布总线、订阅过滤、投递留痕与
// 通道适配器注册点。
//
// 形态（2026-11-18 用户裁定方案）：
//   - 事件源埋点直调 Publish；Publish 仅入进程内缓冲队列（满则丢弃+计数，
//     绝不阻塞事件源）——事实已在库，通知丢失不丢数据。
//   - dispatcher 单消费者：查订阅矩阵 → 写 notification_deliveries(pending)
//     → 唤醒投递 Daemon。
//   - 投递 Daemon（taskengine notification-delivery）取 pending 按通道发送、
//     失败重试、健康探测、MCP 会话清理。
//   - 通道：webhook / email / qq(官方 WebSocket) / wx_clawbot(iLink) / mcp。
//     QQ 与微信为长连出站（各自 Daemon 维护连接），发送经连接管理器下发；
//     webhook/email/MCP 为按需短连，由投递 Daemon 直接调用。
package notify

import (
	"time"
)

// Level 通知级别（订阅矩阵的最低级别过滤口径）。
type Level string

const (
	LevelInfo     Level = "info"
	LevelWarn     Level = "warn"
	LevelCritical Level = "critical"
)

// levelRank 级别序：事件级别 ≥ 订阅下限才投递。
var levelRank = map[Level]int{LevelInfo: 0, LevelWarn: 1, LevelCritical: 2}

// AtLeast 报告 evt 级别是否达到订阅下限。
func AtLeast(evt, min Level) bool { return levelRank[evt] >= levelRank[min] }

// Event 一条待分发通知事件。
type Event struct {
	Type   string // 事件 ID（catalog.go 常量，如 CertFailed）
	Level  Level
	Time   time.Time
	Node   string // 发生节点标识（空=本机）
	Title  string
	Body   string
	Fields map[string]string // 结构化附加字段（通道可格式化呈现）
}
