package services

// 通知投递记录保留清理（用户裁定：滚动写入/定期清理，基础设置可配保留期）。
// 主库 notification_deliveries + notification_delivery_channels 按保留期裁剪；
// 与 security-events-retention 同族（24h Periodic 任务体），但无预聚合/行帽
// 复杂度——投递记录纯日志，年龄裁剪即可。保留期读 global_config
// notification_delivery_retention_days（默认 30，上限 3650）。

import (
	"context"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/notify"
)

// NotificationDeliveryRetentionResult 清理构成（任务日志按构成披露）。
type NotificationDeliveryRetentionResult struct {
	Deliveries   int // 主表删除行数
	Channels     int // 每通道结果删除行数
	WxContexts   int // 过期微信会话上下文 KV 清理数
	BindSessions int // 过期绑定会话清理数
}

// NotificationDeliveryRetentionCleanup 按保留期删除过期投递记录（分批，
// 批间让出写锁并响应 ctx 取消）。保留期读失败上抛（任务落 failed，不静默成功）。
func NotificationDeliveryRetentionCleanup(ctx context.Context) (NotificationDeliveryRetentionResult, error) {
	var result NotificationDeliveryRetentionResult
	if db.DB == nil {
		return result, fmt.Errorf("主库未初始化（清理未执行）")
	}
	var days int
	if err := db.DB.QueryRow(`SELECT COALESCE(notification_delivery_retention_days,?) FROM global_config WHERE id=1`,
		db.DefaultNotificationDeliveryRetentionDays).Scan(&days); err != nil {
		return result, fmt.Errorf("读取投递保留期失败（清理未执行）: %w", err)
	}
	if days < 1 {
		days = db.DefaultNotificationDeliveryRetentionDays
	}
	const batch = 500
	// 先删子表（每通道结果），再删主表——按 created_at 年龄裁剪。
	for {
		res, err := db.DB.Exec(`DELETE FROM notification_delivery_channels WHERE id IN (
			SELECT id FROM notification_delivery_channels WHERE created_at < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, batch)
		if err != nil {
			return result, err
		}
		affected, _ := res.RowsAffected()
		result.Channels += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return result, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	for {
		res, err := db.DB.Exec(`DELETE FROM notification_deliveries WHERE id IN (
			SELECT id FROM notification_deliveries WHERE created_at < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, batch)
		if err != nil {
			return result, err
		}
		affected, _ := res.RowsAffected()
		result.Deliveries += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return result, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	// 顺带清理过期微信会话上下文 KV（防 notify_settings 无界增长；7 天远超
	// 微信会话窗口，清掉仅须对方再发消息重建）。失败不阻断投递清理结果。
	if n, err := notify.PruneWxContextTokens(7 * 24 * time.Hour); err == nil {
		result.WxContexts = n
	}
	result.BindSessions = notify.PruneBindSessions(10 * time.Minute)
	return result, nil
}
