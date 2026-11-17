package notify

import (
	"sort"

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
	rows, err := db.DB.Query(`SELECT user_id, min_level FROM notification_subscriptions WHERE event_type=?`, eventType)
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

	// 合并语义：显式订阅行是用户意志的唯一表达——凡有显式行的用户只按其
	// min_level 评估，绝不落入默认集（否则「显式订阅 min_level=critical」
	// 的用户会被 info 事件的默认兜底二次纳入，显式过滤形同虚设）。
	// 默认集仅补「本事件无任何显式行」的用户：目录 DefaultSub=true 且有
	// 启用通道且事件级别达标。
	out := make([]int64, 0, len(byEvent))
	for uid, minLevel := range byEvent {
		if !hasChannel[uid] {
			continue
		}
		if AtLeast(level, Level(minLevel)) {
			out = append(out, uid)
		}
	}
	if entry.DefaultSub {
		for uid := range hasChannel {
			if _, explicit := byEvent[uid]; explicit {
				continue
			}
			if AtLeast(level, entry.Level) {
				out = append(out, uid)
			}
		}
	}
	// 升序去重（map 遍历序不定；去重防御显式行与默认集理论上的交叠）。
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	deduped := out[:0]
	for i, uid := range out {
		if i == 0 || uid != out[i-1] {
			deduped = append(deduped, uid)
		}
	}
	return deduped, nil
}
