package notify

import (
	"lazy-balancer-v2/internal/db"
)

// subscribersFor 返回订阅了 eventType 且级别达标、并至少启用了一条通道的用户
// ID 集合（升序去重）。默认订阅语义：无显式订阅行的用户按目录 DefaultSub 兜底
// （critical+warn 默认开）——仅当其有启用通道时才投递（无通道=无处投递，跳过）。
func subscribersFor(eventType string, level Level) ([]int64, error) {
	entry, ok := catalogByID(eventType)
	if !ok {
		return nil, nil
	}
	rows, err := db.DB.Query(`SELECT DISTINCT user_id FROM notification_subscriptions WHERE event_type=?`, eventType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byEvent := map[int64]string{}
	for rows.Next() {
		var uid int64
		var minLevel string
		if err := rows.Scan(&uid, &minLevel); err != nil {
			return nil, err
		}
		byEvent[uid] = minLevel
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// 有启用通道的用户集合（一次查询）。
	chRows, err := db.DB.Query(`SELECT DISTINCT user_id FROM notification_channels WHERE enabled=1`)
	if err != nil {
		return nil, err
	}
	defer chRows.Close()
	hasChannel := map[int64]bool{}
	for chRows.Next() {
		var uid int64
		if err := chRows.Scan(&uid); err != nil {
			return nil, err
		}
		hasChannel[uid] = true
	}
	if err := chRows.Err(); err != nil {
		return nil, err
	}

	// 全量用户兜底默认订阅（critical+warn）：无显式订阅行的用户按目录默认集。
	// user_id 从 channels/keys 侧取全集代价高——改为按 subscriptions 显式行 +
	// 「默认订阅且启用通道」两步合并：显式订阅者直接评估；未显式订阅者若启用
	// 通道且目录 DefaultSub=true 且级别达标则纳入。
	out := make([]int64, 0, len(byEvent))
	seen := map[int64]bool{}
	for uid, minLevel := range byEvent {
		if !hasChannel[uid] {
			continue
		}
		if AtLeast(level, Level(minLevel)) {
			out = append(out, uid)
			seen[uid] = true
		}
	}
	if entry.DefaultSub {
		for uid := range hasChannel {
			if !seen[uid] && AtLeast(level, entry.Level) {
				out = append(out, uid)
			}
		}
	}
	return out, nil
}
