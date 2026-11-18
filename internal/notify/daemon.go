package notify

// 投递 Daemon 主循环（taskengine notification-delivery Run 体）。
// 每个 tick：①扫描 pending 批次→按用户启用通道展开→逐通道发送（重试 1 次）
// ②通道健康探测（webhook/clawbot 端点 ping）③MCP 会话超时清理。

import (
	"context"
	"encoding/json"
	"errors"
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
	// 订阅通道选择三态：无订阅行/缺省=全部启用通道（默认订阅语义）；
	// '[]' 显式空选=不投递任何通道（用户裁定：全不选=不订阅）；
	// 非空数组=仅发选定通道。
	sel := subscriptionChannelSelectionFor(userID, msg.EventType)
	if sel.explicitEmpty {
		markDelivery(id, "dead", true, "规则未选择接收通道（不投递）")
		return
	}
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
	errs, sentAny := sendToChannels(ctx, id, userID, channels, sel.templates, msg)
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

// sendToChannels 逐通道渲染+发送（失败重试 1 次）+结果落行。deliverOne 与
// 规则测试共用：模板优先级链=事件×通道模板 > 事件级模板 > 通道样式 > 默认。
// deliveryID=0 时不落结果行（测试发送不污染投递统计）。
func sendToChannels(ctx context.Context, deliveryID, userID int64, channels []deliveryTarget, channelTpls map[int64]string, msg Message) ([]string, bool) {
	var errs []string
	sentAny := false
	for _, ch := range channels {
		chMsg := msg
		chMsg.Title = msg.Title + "（" + ch.Type + "）"
		eventTpl := channelTpls[ch.ChannelID]
		if eventTpl == "" {
			eventTpl = subscriptionTemplateFor(userID, msg.EventType)
		}
		if eventTpl != "" {
			chMsg.Body = renderStyleTemplate(eventTpl, msg, time.Now())
		}
		chMsg.Body = renderDailyForChannel(msg, ch.Type, ParseChannelStyle(ch.StyleConfig).DailyFormat)
		styledTarget := MergeStyleIntoTarget(ch.Target, ch.StyleConfig)
		sendErr := sendToChannel(ctx, ch.Type, styledTarget, chMsg)
		if sendErr != nil {
			sendErr = sendToChannel(ctx, ch.Type, styledTarget, chMsg)
		}
		if sendErr != nil {
			errs = append(errs, ch.Type+": "+sendErr.Error())
			if deliveryID > 0 {
				recordChannelResult(deliveryID, userID, ch, msg.EventType, "failed", sendErr.Error())
			}
			continue
		}
		sentAny = true
		if deliveryID > 0 {
			recordChannelResult(deliveryID, userID, ch, msg.EventType, "sent", "")
		}
	}
	return errs, sentAny
}

// TestRuleDelivery 规则测试发送（导出：handlers 通知规则「测试」按钮）：
// 按订阅选定通道+每通道模板渲染真实事件形态消息并发送；不落投递行。
// 返回逐通道错误（空=全部成功）。无选定通道/无启用通道返回明确错误。
func TestRuleDelivery(ctx context.Context, userID int64, eventType string) ([]string, error) {
	channels, err := channelsForUser(userID)
	if err != nil {
		return nil, err
	}
	sel := subscriptionChannelSelectionFor(userID, eventType)
	if sel.explicitEmpty {
		return nil, errors.New("规则未选择接收通道")
	}
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
		return nil, errors.New("无启用的通知通道")
	}
	msg := testNotificationMessage()
	msg.EventType = eventType
	errs, sentAny := sendToChannels(ctx, 0, userID, channels, sel.templates, msg)
	if !sentAny {
		return errs, errors.New("全部通道发送失败")
	}
	return errs, nil
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

// channelSelection 订阅的通道选择三态：explicitEmpty=显式 '[]'（不投递）；
// ids 非空=仅选定通道；两者皆否=全部启用通道（默认订阅语义）。
type channelSelection struct {
	ids           map[int64]bool
	templates     map[int64]string
	explicitEmpty bool
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
			if len(ids) == 0 {
				out.explicitEmpty = true // 显式空数组=不投递（区别于缺省空串=全部）
			}
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
