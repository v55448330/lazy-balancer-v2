package services

// 通知中心 4 任务的注册点（通知中心方案：全部纳入统一 taskengine，
// 零外部队列组件）。事件目录与发布见 internal/notify。

import (
	"time"

	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/taskengine"
)

// registerNotificationTasks 注册通知相关任务（由 InitTaskEngine 调用）。
func registerNotificationTasks(te *taskengine.Engine) {
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "notification-delivery",
		Family:      "notification",
		Name:        "通知投递",
		Description: "常驻投递：扫描通知投递队列按用户通道发送（webhook/邮件/QQ/微信/MCP 推送），失败重试，通道健康探测与 MCP 会话清理",
		Category:    "通知",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error {
			return notify.RunDeliveryLoop(rc.Ctx)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "notification-daily-report",
		Family:      "notification",
		Name:        "通知日报",
		Description: "每日 09:00 渲染昨日摘要（请求/拦截/攻击 TOP/证书/集群/封禁）并按用户订阅通道投递",
		Category:    "通知",
		Kind:        taskengine.KindScheduled,
		NextSlotFn: func() time.Time {
			// 每日 09:00 本地时间；错过（停机跨点）由下一 tick 立即补发一次。
			n := time.Now().Add(time.Minute)
			next := time.Date(n.Year(), n.Month(), n.Day(), 9, 0, 0, 0, n.Location())
			if !next.After(n) {
				next = next.AddDate(0, 0, 1)
			}
			return next
		},
		Run: func(rc taskengine.RunContext) error {
			return notify.DailyReportRun(rc)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "qq-bot-connection",
		Family:      "notification",
		Name:        "QQ 机器人连接",
		Description: "QQ 官方机器人 WebSocket 出站长连（免公网）：鉴权/心跳/重连/绑定指令处理；掉线自动告警至其它通道",
		Category:    "通知",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			// 业务门内置 Run 体（Daemon 不参与 tick 调度，EnabledFn 非法）：
			// 凭据未配置时间隔等待而非退出——设置保存落库后连接自动起，无需重启任务。
			for !notify.QQBotConfigured() {
				select {
				case <-rc.Ctx.Done():
					return nil
				case <-time.After(30 * time.Second):
				}
			}
			return notify.RunQQBotConnection(rc.Ctx)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "wx-bot-connection",
		Family:      "notification",
		Name:        "微信机器人连接",
		Description: "微信个人 Bot（iLink）出站长连（免公网）：扫码登录态维护/绑定指令/掉线检测与告警",
		Category:    "通知",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleMasterOnly,
		Run: func(rc taskengine.RunContext) error {
			// 业务门内置 Run 体：登录态未配置时间隔等待（同 QQ 口径）。
			for !notify.WxBotConfigured() {
				select {
				case <-rc.Ctx.Done():
					return nil
				case <-time.After(30 * time.Second):
				}
			}
			return notify.RunWxBotConnection(rc.Ctx)
		},
	})
}
