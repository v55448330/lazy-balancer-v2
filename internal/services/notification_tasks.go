package services

// 通知中心 4 任务的注册点（audit151 方案：全部纳入统一 taskengine，
// 零外部队列组件）。事件目录与发布见 internal/notify。

import (
	"time"

	"lazy-balancer-v2/internal/notify"
	"lazy-balancer-v2/internal/taskengine"
)

// registerNotificationTasks 注册通知相关任务（由 InitTaskEngine 调用）。
func registerNotificationTasks(te *taskengine.Engine) {
	mustRegisterTask(te, taskengine.Descriptor{
		ID:       "notification-delivery",
		Family:   "notification",
		Name:     "通知投递",
		Description: "常驻投递：扫描通知投递队列按用户通道发送（webhook/邮件/QQ/微信/MCP 推送），失败重试，通道健康探测与 MCP 会话清理",
		Category: "通知",
		Kind:     taskengine.KindDaemon,
		RunsOn:   taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error {
			return notify.DeliveryDaemonRun(rc)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:       "notification-daily-report",
		Family:   "notification",
		Name:     "通知日报",
		Description: "每日 09:00 渲染昨日摘要（请求/拦截/攻击 TOP/证书/集群/封禁）并按用户订阅通道投递",
		Category: "通知",
		Kind:     taskengine.KindScheduled,
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
		ID:       "qq-bot-connection",
		Family:   "notification",
		Name:     "QQ 机器人连接",
		Description: "QQ 官方机器人 WebSocket 出站长连（免公网）：鉴权/心跳/重连/绑定指令处理；掉线自动告警至其它通道",
		Category: "通知",
		Kind:     taskengine.KindDaemon,
		RunsOn:   taskengine.RoleMasterOnly,
		EnabledFn: notify.QQBotConnectionEnabled,
		Run: func(rc taskengine.RunContext) error {
			return notify.QQBotConnectionRun(rc)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:       "wx-bot-connection",
		Family:   "notification",
		Name:     "微信机器人连接",
		Description: "微信个人 Bot（iLink）出站长连（免公网）：扫码登录态维护/绑定指令/掉线检测与告警",
		Category: "通知",
		Kind:     taskengine.KindDaemon,
		RunsOn:   taskengine.RoleMasterOnly,
		EnabledFn: notify.WxBotConnectionEnabled,
		Run: func(rc taskengine.RunContext) error {
			return notify.WxBotConnectionRun(rc)
		},
	})
}
