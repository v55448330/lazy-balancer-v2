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
	"time"

	"lazy-balancer-v2/internal/taskengine"
)

// DailyReportRun 日报 Scheduled：遍历启用用户按各自配置渲染+直接落投递
// （不经事件订阅面——日报独立区块语义，与手动触发单源 DeliverDailyForAll）。
func DailyReportRun(rc taskengine.RunContext) error {
	_, err := DeliverDailyForAll(time.Now())
	return err
}
