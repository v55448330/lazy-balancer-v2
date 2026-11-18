package notify

// 投递 Daemon 主循环（taskengine notification-delivery Run 体）。
// 每个 tick：①扫描 pending 批次→按用户启用通道展开→逐通道发送（重试 1 次）
// ②通道健康探测（webhook/clawbot 端点 ping）③MCP 会话超时清理。

import (
	"context"
	"encoding/json"
	"log"
	"strconv"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	deliveryTickInterval = 15 * time.Second
	deliveryBatchSize    = 50
)

// RunDeliveryLoop 投递主循环（rc.Ctx 取消=引擎停止/角色门停）。
func RunDeliveryLoop(ctx context.Context) error { //scope-exempt: daemon-run-body-loop
	requeueStalePending()
	t := time.NewTicker(deliveryTickInterval) //scope-exempt: daemon-run-body-loop
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			processPendingBatch(ctx)
			cleanupExpiredMCPSessions()
		case <-deliveryWakeCh:
			// 重发唤醒：立即补扫 pending（tick 兜底仍保留）。
			processPendingBatch(ctx)
		}
	}
}

// processPendingBatch 一批 pending：逐行取用户启用通道并发送。
// 单行多通道：任一通道成功即 sent；全部失败重试 1 次后 failed；无启用通道
// 的行直接 dead（无处投递，留痕可见）。
func processPendingBatch(ctx context.Context) {
	batch, err := pendingDeliveries(deliveryBatchSize)
	if err != nil {
		log.Printf("WARN: notify pending 扫描失败: %v", err)
		return
	}
	for _, d := range batch {
		if ctx.Err() != nil {
			return
		}
		deliverOne(ctx, d.ID, d.UserID, Message{
			EventType: d.EventType, Level: d.Level, Title: d.Title, Body: d.Body,
		})
	}
}

// deliverOne 单行投递：展开订阅选定通道→逐通道发送（失败重试 1 次）→
// 每通道结果落 notification_delivery_channels（概览分布统计事实源）→主表状态收口。
func deliverOne(ctx context.Context, id, userID int64, msg Message) {
	channels, err := channelsForUser(userID)
	if err != nil {
		log.Printf("WARN: notify 通道查询失败（delivery=%d）: %v", id, err)
		return
	}
	// 订阅通道选择：channel_ids 非空=仅发选定通道（空=全部启用通道，向后兼容）
	sel := subscriptionChannelSelectionFor(userID, msg.EventType)
	if len(sel.ids) > 0 {
		filtered := channels[:0]
		for _, ch := range channels {
			if sel.ids[ch.ChannelID] {
				filtered = append(filtered, ch)
			}
		}
		channels = filtered
	}
	if len(channels) == 0 {
		markDelivery(id, "dead", true, "无启用的通知通道")
		return
	}
	var errs []string
	sentAny := false
	for _, ch := range channels {
		chMsg := msg
		chMsg.Title = msg.Title + "（" + ch.Type + "）"
		// 模板优先级链：事件×通道模板（channel_templates[channelID]）>
		// 事件级模板（body_template）> 通道级模板（style_config）> 系统默认。
		eventTpl := sel.templates[ch.ChannelID]
		if eventTpl == "" {
			eventTpl = subscriptionTemplateFor(userID, msg.EventType)
		}
		if eventTpl != "" {
			chMsg.Body = renderStyleTemplate(eventTpl, msg, time.Now())
		}
		// 日报按通道格式渲染（优先级：日报页 per-channel 配置 > 通道
		// style_config.daily_format > 自动映射；其余事件原样透传）。
		chMsg.Body = renderDailyForChannel(msg, ch.Type, ParseChannelStyle(ch.StyleConfig).DailyFormat)
		// 通道消息样式合并进 target（sender 按 target 内可选键消费）
		styledTarget := MergeStyleIntoTarget(ch.Target, ch.StyleConfig)
		sendErr := sendToChannel(ctx, ch.Type, styledTarget, chMsg)
		if sendErr != nil {
			// 单通道重试 1 次（原实现整行重试两遍=成功通道重复收到消息，已修）
			sendErr = sendToChannel(ctx, ch.Type, styledTarget, chMsg)
		}
		if sendErr != nil {
			errs = append(errs, ch.Type+": "+sendErr.Error())
			recordChannelResult(id, userID, ch, msg.EventType, "failed", sendErr.Error())
			continue
		}
		sentAny = true
		recordChannelResult(id, userID, ch, msg.EventType, "sent", "")
	}
	if sentAny {
		reason := ""
		if len(errs) > 0 {
			reason = "部分通道失败: " + strings.Join(errs, "; ")
		}
		markDelivery(id, "sent", true, reason)
		return
	}
	markDelivery(id, "failed", true, strings.Join(errs, "; "))
}

// recordChannelResult 每通道投递结果落行（统计事实源；落库失败仅告警不阻断投递）。
func recordChannelResult(deliveryID, userID int64, ch deliveryTarget, eventType, status, errMsg string) {
	_, err := db.DB.Exec(`INSERT INTO notification_delivery_channels
		(delivery_id, user_id, channel_id, channel_type, event_type, status, error, created_at)
		VALUES (?,?,?,?,?,?,?,?)`,
		deliveryID, userID, ch.ChannelID, ch.Type, eventType, status, errMsg,
		time.Now().UTC().Format("2006-01-02 15:04:05"))
	if err != nil {
		log.Printf("WARN: notify 通道结果落库失败（delivery=%d channel=%d）: %v", deliveryID, ch.ChannelID, err)
	}
}

// cleanupExpiredMCPSessions 30 分钟无活动的 MCP 会话标记离线（删除行——
// 在线 Agent 页=表内即在线）。
func cleanupExpiredMCPSessions() {
	if _, err := db.DB.Exec(`DELETE FROM mcp_sessions WHERE last_seen < datetime('now', '-30 minutes')`); err != nil {
		log.Printf("WARN: notify MCP 会话清理失败: %v", err)
	}
}

// subscriptionTemplateFor 事件级消息模板（notification_subscriptions.body_template；
// 优先于通道模板——投递 Daemon 的 renderStyleTemplate 同占位符集）。
func subscriptionTemplateFor(userID int64, eventType string) string {
	var tpl string
	_ = db.DB.QueryRow(`SELECT COALESCE(body_template,'') FROM notification_subscriptions
		WHERE user_id=? AND event_type=?`, userID, eventType).Scan(&tpl)
	return tpl
}

// channelSelection 订阅的通道选择（ids 空=全部启用通道；templates 键=通道 ID 字符串）。
type channelSelection struct {
	ids       map[int64]bool
	templates map[int64]string
}

// subscriptionChannelSelectionFor 读订阅通道选择+每通道模板（坏 JSON=零值兜底，
// 派发路径不可因配置损坏中断投递）。
func subscriptionChannelSelectionFor(userID int64, eventType string) channelSelection {
	out := channelSelection{ids: map[int64]bool{}, templates: map[int64]string{}}
	var idsRaw, tplRaw string
	_ = db.DB.QueryRow(`SELECT COALESCE(channel_ids,''), COALESCE(channel_templates,'') FROM notification_subscriptions
		WHERE user_id=? AND event_type=?`, userID, eventType).Scan(&idsRaw, &tplRaw)
	if idsRaw != "" {
		var ids []int64
		if json.Unmarshal([]byte(idsRaw), &ids) == nil {
			for _, id := range ids {
				out.ids[id] = true
			}
		}
	}
	if tplRaw != "" {
		var m map[string]string
		if json.Unmarshal([]byte(tplRaw), &m) == nil {
			for k, v := range m {
				if id, err := strconv.ParseInt(k, 10, 64); err == nil && v != "" {
					out.templates[id] = v
				}
			}
		}
	}
	return out
}
