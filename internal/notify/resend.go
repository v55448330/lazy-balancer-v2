package notify

// 投递重发（REST 重发端点消费）：把一行非 pending 投递重置回 pending 并
// 唤醒投递循环立即补发。重置同时清错误与已发送时间戳、重置尝试计数，并
// 刷新 created_at——7 天过期哨兵（requeueStalePending）以 created_at 判龄，
// 不刷新会把刚重置的行再次判 dead。

import (
	"time"

	"lazy-balancer-v2/internal/db"
)

// deliveryWakeCh 投递循环唤醒信号（非阻塞投递；循环未运行时信号弃置，
// 15s tick 兜底）。
var deliveryWakeCh = make(chan struct{}, 1)

// ResendDelivery 把投递行重置回 pending 并唤醒投递循环。
// 返回 (found, reset, err)：行不存在 → found=false；行已在 pending →
// found=true, reset=false（未重复重置）。err 非空时行状态不变。
func ResendDelivery(id int64) (found, reset bool, err error) {
	res, err := db.DB.Exec(`UPDATE notification_deliveries
		SET status='pending', attempts=0, error='', sent_at=NULL, created_at=?
		WHERE id=? AND status<>'pending'`,
		time.Now().UTC().Format("2006-01-02 15:04:05"), id)
	if err != nil {
		return true, false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return true, false, err
	}
	if n == 0 {
		return false, false, nil
	}
	select {
	case deliveryWakeCh <- struct{}{}:
	default:
	}
	return true, true, nil
}
