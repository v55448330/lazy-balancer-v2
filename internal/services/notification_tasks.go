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
	// 日报「API 调用(今日)」数据源注入（避免 notify→services 循环依赖）。
	notify.DailyRESTCalls = func() int64 { return GetRESTCallOverview().TodayCalls }
	// 日报「本地日历日」时区与全站配置时区同源（窗口/日期标签/认证计数桶共用；
	// 未注入时 notify 回落进程 TZ，会与 task_runs 等配置时区墙钟错位）。
	notify.DailyLocation = CurrentLocation
	// 任务失败事件钩子（taskengine 不直接依赖 notify，解循环）。
	taskengine.TaskFailedHook = func(taskID, message string) {
		notify.Publish(notify.Event{Type: notify.EvtTaskFailed, Level: notify.LevelWarn,
			Fields: map[string]string{"1": taskID, "2": message}})
	}
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
		Description: "按各用户配置时间渲染昨日摘要（请求/拦截/攻击 TOP/证书/集群/封禁）并按用户订阅通道投递",
		Category:    "通知",
		Kind:        taskengine.KindScheduled,
		NextSlotFn: func() time.Time {
			// per-user 发送时间集（AllDailySendTimes 单源）：取全部启用用户
			// send_time 中「下一个会到来」的时刻。槽集合取全集而非单值，迟到
			// 的早槽不拖累后续槽；Run 体按各用户 send_time 分桶（只投当前槽
			// 到期者，宽限 5 分钟，见 notify.DeliverDailyForAll）。停机跨过的
			// 槽不追溯补发（引擎启动首轮只覆盖启动时刻附近的槽）。无配置
			// 回退 09:00。
			n := time.Now().Add(time.Minute)
			best := time.Date(n.Year(), n.Month(), n.Day(), 9, 0, 0, 0, n.Location())
			if !best.After(n) {
				best = best.AddDate(0, 0, 1)
			}
			times, err := notify.AllDailySendTimes()
			if err == nil {
				for _, ts := range times {
					t, err := time.ParseInLocation("15:04", ts, n.Location())
					if err != nil {
						continue
					}
					cand := time.Date(n.Year(), n.Month(), n.Day(), t.Hour(), t.Minute(), 0, 0, n.Location())
					if !cand.After(n) {
						cand = cand.AddDate(0, 0, 1)
					}
					if cand.Before(best) {
						best = cand
					}
				}
			}
			return best
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
			for !notify.QQAnyBotConfigured() {
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
			for !notify.WxAnyBotConfigured() {
				select {
				case <-rc.Ctx.Done():
					return nil
				case <-time.After(30 * time.Second):
				}
			}
			return notify.RunWxBotConnection(rc.Ctx)
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "notification-delivery-retention",
		Family:      "notification",
		Name:        "通知投递保留清理",
		Description: "按保留期配置（基础设置→通知投递保留天数）滚动删除过期投递记录与每通道结果",
		Category:    "通知",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			result, err := NotificationDeliveryRetentionCleanup(rc.Ctx)
			if err != nil {
				TaskLogfWarnContext(rc.Ctx, "notification-delivery-retention", "cleanup", "投递保留清理失败：本轮已删投递 %d 条 · 通道结果 %d 行后中止：%v", result.Deliveries, result.Channels, err)
				return err
			}
			TaskLogfContext(rc.Ctx, "notification-delivery-retention", "cleanup", "投递保留清理完成：删除投递 %d 条 · 通道结果 %d 行 · 微信会话上下文 %d 条 · 绑定会话 %d 个（无过期为 0）", result.Deliveries, result.Channels, result.WxContexts, result.BindSessions)
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "notification-apikey-expiry",
		Family:      "notification",
		Name:        "API 密钥临期预警",
		Description: "每日扫描 7 天内到期的启用 API 密钥，发布临期预警事件（apikey.expiry_warning）",
		Category:    "通知",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			return notify.CheckAPIKeyExpiry()
		},
	})
}
