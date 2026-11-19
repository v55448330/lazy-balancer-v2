package notify

// 投递重发（REST 重发端点消费）：把一行非 pending 投递重置回 pending 并
// 唤醒投递循环立即补发。重置同时清错误与已发送时间戳、重置尝试计数，并
// 刷新 created_at——7 天过期哨兵（requeueStalePending）以 created_at 判龄，
// 不刷新会把刚重置的行再次判 dead。
//
// failedOnly=true 且行状态 partial：只重发失败通道——失败 channel_id 落
// retry_channel_ids（JSON 数组），deliverOne 派发时按此过滤并消费后清空；
// 其余形态（全量重发/非 partial）清过滤，重发全部订阅通道。

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"time"

	"lazy-balancer-v2/internal/db"
)

// deliveryWakeCh 投递循环唤醒信号（非阻塞投递；循环未运行时信号弃置，
// 15s tick 兜底）。
var deliveryWakeCh = make(chan struct{}, 1)

// ResendDelivery 把投递行重置回 pending 并唤醒投递循环。
// 返回 (found, reset, err)：行不存在 → found=false；行已在 pending →
// found=true, reset=false（未重复重置）。err 非空时行状态不变。
func ResendDelivery(id int64, failedOnly bool) (found, reset bool, err error) {
	retryIDs := ""
	if failedOnly {
		var status string
		err := db.DB.QueryRow(`SELECT status FROM notification_deliveries WHERE id=?`, id).Scan(&status)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, false, nil
			}
			return true, false, err
		}
		if status == "partial" {
			ids, err := failedDeliveryChannelIDs(id)
			if err != nil {
				return true, false, err
			}
			if len(ids) > 0 {
				b, _ := json.Marshal(ids)
				retryIDs = string(b)
			}
		}
	}
	res, err := db.DB.Exec(`UPDATE notification_deliveries
		SET status='pending', attempts=0, error='', sent_at=NULL, created_at=?, retry_channel_ids=?
		WHERE id=? AND status<>'pending'`,
		time.Now().UTC().Format("2006-01-02 15:04:05"), retryIDs, id)
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

// failedDeliveryChannelIDs 取每通道最新结果行中仍失败的通道 ID（升序）。
// 重发会追加新结果行——按最新行判定，历史失败行不得把后续已成功的通道
// 拖回重试集。
func failedDeliveryChannelIDs(id int64) ([]int64, error) {
	rows, err := db.DB.Query(`SELECT channel_id FROM notification_delivery_channels nc
		WHERE delivery_id=? AND status='failed'
		AND id=(SELECT MAX(id) FROM notification_delivery_channels WHERE delivery_id=nc.delivery_id AND channel_id=nc.channel_id)
		ORDER BY channel_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var cid int64
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		out = append(out, cid)
	}
	return out, rows.Err()
}

// deliveryRetryChannelIDs 读 failed_only 重发通道过滤（JSON 数组；
// 空串/坏 JSON=无过滤，派发路径不可因配置损坏中断投递）。
func deliveryRetryChannelIDs(id int64) map[int64]bool {
	var raw string
	_ = db.DB.QueryRow(`SELECT COALESCE(retry_channel_ids,'') FROM notification_deliveries WHERE id=?`, id).Scan(&raw)
	if raw == "" {
		return nil
	}
	var ids []int64
	if json.Unmarshal([]byte(raw), &ids) != nil {
		return nil
	}
	out := make(map[int64]bool, len(ids))
	for _, cid := range ids {
		out[cid] = true
	}
	return out
}

// clearDeliveryRetryChannels 消费后清空重发通道过滤（一次性语义：后续
// pending 重扫/再次重发不得沿用上一轮的失败通道集）。
func clearDeliveryRetryChannels(id int64) {
	if _, err := db.DB.Exec(`UPDATE notification_deliveries SET retry_channel_ids='' WHERE id=? AND retry_channel_ids<>''`, id); err != nil {
		log.Printf("WARN: notify 重发通道过滤清除失败（id=%d）: %v", id, err)
	}
}
