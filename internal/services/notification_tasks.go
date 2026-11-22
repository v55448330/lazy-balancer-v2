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
		Description: "常驻投递：扫描通知投递队列按用户通道发送（webhook/邮件/QQ/微信/MCP 推送），失败重试与 MCP 会话清理",
		Category:    "通知",
		Kind:        taskengine.KindDaemon,
		RunsOn:      taskengine.RoleAny,
		Run: func(rc taskengine.RunContext) error {
			// 集群集中汇聚（2026-11-22 用户裁定）：通道/订阅/日报配置只在主节点，
			// 从节点不本地投递（无通道配置=空转），只承载事件 spool 重传循环；
			// 从节点事件经 Publish 即时推送到主节点总线，由主节点统一订阅匹配与投递。
			// 从节点：无通道配置，投递收敛主节点；本 daemon 只承载事件 spool 重传
			// 节拍（RunTicker 驱动，不自建 ticker——任务引擎标准 v2.2）。
			if !te.IsMaster() {
				taskengine.RunTicker(rc.Ctx, notify.ClusterForwardSpoolRetryInterval, nil, notify.DrainClusterForwardSpool)
				return nil
			}
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
		// 集群集中汇聚（2026-11-22 用户裁定）：通道/订阅/日报配置只在主节点，
		// 日报只在主节点渲染投递（集群口径=主节点本地+各从节点上报统计）。
		// 从节点若也跑本任务，会为本地用户落 pending 行而无通道可用（空转堆积）。
		RunsOn:     taskengine.RoleMasterOnly,
		NextSlotFn: func() time.Time { return nextDailyReportSlot(time.Now()) },
		Run: func(rc taskengine.RunContext) error {
			return notify.DailyReportRun(rc)
		},
	})

	// 从节点日报统计上报（2026-11-22 主节点集中汇聚）：每日 00:05 把本节点
	// 昨日统计块上报主节点（(date,node) upsert），主节点日报「各节点摘要」
	// 由此渲染。仅从节点运行（RoleSlaveOnly，引擎角色门拦停主节点）；本任务
	// 在默认 StartLoop 清单内（角色门只拦执行，不设 loopEnabled——不列入清单
	// 会让从节点侧永不调度，统计永远缺失）。
	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "notification-node-stats-report",
		Family:      "notification",
		Name:        "节点统计上报",
		Description: "从节点每日上报本节点昨日统计块（请求/拦截/攻击 TOP/CC/封禁）至主节点，供主节点日报的集群各节点摘要使用",
		Category:    "通知",
		Kind:        taskengine.KindScheduled,
		RunsOn:      taskengine.RoleSlaveOnly,
		NextSlotFn:  func() time.Time { return nextNodeStatsSlot(time.Now()) },
		Run: func(rc taskengine.RunContext) error {
			stats, err := notify.CollectNodeStats(rc.Ctx, time.Now())
			if err != nil {
				return err
			}
			return notify.ReportNodeStatsToMaster(rc.Ctx, stats)
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
		// 与同族日报一致：清理面只在主节点（数据单点收敛，多节点并发清理
		// 只会互相干扰且无收益）。
		RunsOn:     taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 24 * time.Hour },
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
		// 单次执行只发布一条预警（去重语义由主节点单点承担）：从节点若也跑，
		// 同一把临期密钥会在各节点各发一遍。
		RunsOn:     taskengine.RoleMasterOnly,
		IntervalFn: func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			return notify.CheckAPIKeyExpiry()
		},
	})
}

// nextDailyReportSlot 日报定时任务的排程槽（NextSlotFn 唯一实现）。
//
// 引擎契约（taskengine Scheduled 分支）：求值后立即判定 due=now.After(槽)，
// 即 NextSlotFn 必须返回「已到期的槽（≤now）」引擎才会触发；返回未来槽永远
// 不 due。同时引擎在槽前 30s 前导窗内每 tick 重算槽（engine.go needEval），
// 所以实现必须做到：
//   - 有槽落在宽限窗内（刚过去，含跨零点的昨日同刻槽）→ 返回其中最近一个
//     （≤now ⇒ 立即触发；同一槽由引擎 schedDoneSlot 保证只投一次）；
//   - 否则返回下一个未来槽（最早一个，可跨日）。
//
// 早先实现以 now+1min 为基准取「下一个未来槽」：前导窗内第一次重算就把当日
// 槽推到次日，due 恒 false——定时日报永不投递。
// 时区用全站配置时区（CurrentLocation，与投递侧 dailySlotDue 的 loc 同源）：
// 容器 TZ≠配置时区时，槽与宽限必须按同一时区比较。
// nextNodeStatsSlot 从节点统计上报槽（NextSlotFn 唯一实现）。
//
// 槽语义与 nextDailyReportSlot 同源：引擎求值后立即判定 due=now.After(槽)，
// 返回严格未来槽则永不触发；同时引擎在槽前 30s 前导窗内每 tick 重算槽，
// 因此必须「宽限窗内返回已到期槽（≤now），否则返回下一个未来槽」。
// 早先实现恒返回严格未来槽（今日 00:05 已过就推次日），due 恒假——从节点
// 统计上报任务永不执行，主节点日报「各节点摘要」永远无数据。
// 每日 00:05 配置时区，次日零点后立即上报昨日块——早于默认 09:00 日报槽，
// 保证主节点渲染时数据已在。失败轮不推进槽，引擎 Scheduled 退避兜底会在
// 宽限窗内重投同一槽（瞬时故障/重启窗口的自然补报，无需任务体自建重试）。
func nextNodeStatsSlot(now time.Time) time.Time {
	loc := CurrentLocation()
	if loc == nil {
		loc = time.Local
	}
	return nodeStatsSlotAt(now, loc)
}

// nodeStatsSlotGrace 统计上报槽的到期宽限：仅覆盖槽点后 1 分钟内的 tick 抖动
// 与首档重试（引擎 Scheduled 失败退避 1s→5s→30s），窗口半开 [槽, 槽+1min)。
// 与日报的 5min 宽限刻意不同：统计上报是「昨日块」的一次性交接，只要覆盖
// 槽点附近的短重试窗即可；越过 1 分钟仍未成功就顺延到次日槽，避免与次日
// 的上一日口径重叠投递。
const nodeStatsSlotGrace = time.Minute

// nodeStatsSlotAt 统计上报槽语义纯函数（配置时区 loc；测试直驱单源）。
func nodeStatsSlotAt(now time.Time, loc *time.Location) time.Time {
	n := now.In(loc)
	slot := time.Date(n.Year(), n.Month(), n.Day(), 0, 5, 0, 0, loc)
	if !slot.After(n) {
		if n.Sub(slot) < nodeStatsSlotGrace {
			return slot // 宽限内已到期：due 成立，本 tick 上报
		}
		return slot.AddDate(0, 0, 1) // 超宽限：下一未来槽（次日 00:05）
	}
	return slot // 当日槽尚未到期（未来槽，due 不成立）
}

func nextDailyReportSlot(now time.Time) time.Time {
	times, err := notify.AllDailySendTimes()
	if err != nil || len(times) == 0 {
		// 读失败/无启用配置回退 09:00（与 GetDailyConfig 默认槽、dailySlotAt
		// 兜底一致）：宁可空跑一轮，不让排程停摆。
		times = []string{"09:00"}
	}
	loc := CurrentLocation()
	if loc == nil {
		loc = time.Local
	}
	return dailyReportSlotAt(now, times, loc)
}

// dailyReportSlotAt 槽语义纯函数（配置时区 loc；测试直驱单源）。
// sendTimes 为全部启用用户 send_time 全集——槽域=运行域：Run 体按各用户
// send_time 分桶（notify.DeliverDailyForAll），逐个时刻都必须被排程触发一次。
// 到期槽判定复用 notify.DailySlotCandidate（跨零点宽限窗与投递侧 dailySlotDue
// 同源）；本函数只额外推算「下一个未来槽」。
func dailyReportSlotAt(now time.Time, sendTimes []string, loc *time.Location) time.Time {
	n := now.In(loc)
	valid := make([]string, 0, len(sendTimes))
	for _, ts := range sendTimes {
		if _, err := time.ParseInLocation("15:04", ts, loc); err != nil {
			continue // 非法槽跳过（AllDailySendTimes 不会产出；防御配置脏值）
		}
		valid = append(valid, ts)
	}
	if len(valid) == 0 {
		valid = append(valid, "09:00")
	}
	var recent, next time.Time // 宽限内最近的已到期槽 / 最早未来槽
	for _, ts := range valid {
		if slot, ok := notify.DailySlotCandidate(now, ts, loc); ok && slot.After(recent) {
			recent = slot
		}
		cand := notify.DailySlotAt(now, ts, loc)
		if tomorrow := cand.AddDate(0, 0, 1); next.IsZero() || tomorrow.Before(next) {
			next = tomorrow // 当日槽全部过期且超宽限时的兜底（明日最早槽）
		}
		if cand.After(n) && cand.Before(next) {
			next = cand
		}
	}
	if !recent.IsZero() {
		return recent
	}
	return next
}
