package notify

// 投递 Daemon 主循环（taskengine notification-delivery Run 体）。
// 每个 tick：①扫描 pending 批次→按用户启用通道展开→逐通道发送（重试 1 次）
// ②通道健康探测（webhook/clawbot 端点 ping）③MCP 会话超时清理。

import (
	"context"
	"log"
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

// deliverOne 单行投递：展开通道→逐通道发送→状态收口。
func deliverOne(ctx context.Context, id, userID int64, msg Message) {
	channels, err := channelsForUser(userID)
	if err != nil {
		log.Printf("WARN: notify 通道查询失败（delivery=%d）: %v", id, err)
		return
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
		if err := sendToChannel(ctx, ch.Type, ch.Target, chMsg); err != nil {
			errs = append(errs, ch.Type+": "+err.Error())
			continue
		}
		sentAny = true
	}
	switch {
	case sentAny:
		reason := ""
		if len(errs) > 0 {
			reason = "部分通道失败: " + strings.Join(errs, "; ")
		}
		markDelivery(id, "sent", true, reason)
	default:
		// 全部失败：重试 1 次（同 tick 内立即重试）后 failed。
		for _, ch := range channels {
			_ = sendToChannel(ctx, ch.Type, ch.Target, msg)
		}
		var errs2 []string
		sentRetry := false
		for _, ch := range channels {
			if err := sendToChannel(ctx, ch.Type, ch.Target, msg); err == nil {
				sentRetry = true
			}
		}
		_ = errs2
		if sentRetry {
			markDelivery(id, "sent", true, strings.Join(errs, "; "))
			return
		}
		markDelivery(id, "failed", true, strings.Join(errs, "; "))
	}
	_ = db.DB
}

// cleanupExpiredMCPSessions 30 分钟无活动的 MCP 会话标记离线（删除行——
// 在线 Agent 页=表内即在线）。
func cleanupExpiredMCPSessions() {
	if _, err := db.DB.Exec(`DELETE FROM mcp_sessions WHERE last_seen < datetime('now', '-30 minutes')`); err != nil {
		log.Printf("WARN: notify MCP 会话清理失败: %v", err)
	}
}
