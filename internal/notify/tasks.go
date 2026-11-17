package notify

// taskengine 四任务 Run 函数（注册点 services/notification_tasks.go）：
//   notification-delivery        Daemon  投递+健康探测+MCP 会话清理
//   notification-daily-report    Scheduled 日报渲染→Publish
//   qq-bot-connection            Daemon  QQ 官方 WebSocket 出站（仅主节点）
//   wx-bot-connection            Daemon  微信 iLink 长连（仅主节点）
//
// 通道发送全部经 senders 注册表；QQ/微信 Sender 把消息交给连接管理器单例
// （qqbot.go/wxbot.go），连接离线返回明确错误（投递行 dead+原因可见）。

import (
	"fmt"
	"log"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// DeliveryDaemonRun 投递 Daemon：tick 循环（默认 15s）——pending 扫描发送、
// 通道健康探测、MCP 会话超时清理。实现细节见 daemon.go。
func DeliveryDaemonRun(rc taskengine.RunContext) error {
	return RunDeliveryLoop(rc.Ctx)
}

// DailyReportRun 日报 Scheduled：渲染昨日摘要 → Publish(daily_report)。
// 发送全走投递 Daemon（生产者/消费者分离，见方案 §任务表）。
func DailyReportRun(rc taskengine.RunContext) error {
	return RenderAndPublishDailyReport(rc.Ctx, time.Now())
}

// QQBotConnectionRun QQ 官方 WebSocket 出站连接 Daemon（主节点；Role 门由
// 注册 RunsOn 承担）。凭据未配置时 EnabledFn 关闭（不空转）。
func QQBotConnectionRun(rc taskengine.RunContext) error {
	return RunQQBotConnection(rc.Ctx)
}

// QQBotConnectionEnabled QQ 凭据已配置（EnabledFn）。
func QQBotConnectionEnabled() bool { return QQBotConfigured() }

// WxBotConnectionRun 微信 iLink 长连连接 Daemon（主节点）。
func WxBotConnectionRun(rc taskengine.RunContext) error {
	return RunWxBotConnection(rc.Ctx)
}

// WxBotConnectionEnabled 微信登录态已配置（EnabledFn）。
func WxBotConnectionEnabled() bool { return WxBotConfigured() }

var _ = fmt.Sprintf // 占位：连接器实现（qqbot.go/wxbot.go）引用
var _ = log.Println
var _ = db.DB
