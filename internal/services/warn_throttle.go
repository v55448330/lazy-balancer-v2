package services

import "time"

// throttleWarnAllowed 判定同一 key 在 window 内是否应放行一次告警：放行时
// 记录时间，并顺带回收超过 retention 的键，避免 key 空间在进程生命周期内
// 单调增长。调用方持有 seen 对应的锁并保证 seen 非 nil——各告警族的锁与
// 状态仍归各调用方/测试持有，本函数只收敛「窗口判定 + 插入 + 回收」三段
// 逻辑（无键数上限，等价 throttleWarnAllowedCapped 的 cap<=0）。
//
// 节点健康解析失败、快照坏行隔离、证书候选告警此前各写一份同形实现
// （窗口 60s / 10min / 5min，GC 与窗口或长于窗口），调窗口或 GC 需要逐处
// 修改且容易漏掉某条新告警。retention 短于 window 时按 window 处理（否则
// 刚放行的键会被立即回收，限频退化为不限频）。
func throttleWarnAllowed[K comparable](seen map[K]time.Time, key K, now time.Time, window, retention time.Duration) bool {
	return throttleWarnAllowedCapped(&seen, key, now, window, retention, 0)
}

// throttleWarnAllowedCapped 是 throttleWarnAllowed 的完整形态：在窗口判定与
// 过期回收之外多一道键数上限——清扫后仍超过 cap 个键即整体重置（丢窗，
// 避免键空间因消息内嵌数字等变体无界增长）。cap<=0 表示无上限，与
// throttleWarnAllowed 语义逐位一致。
//
// 顺序是语义的一部分（先判重复 → 回收 → 判上限 → 记录）：被抑制的消息不得
// 触发清扫或重置，否则高频故障会把其它告警族的限频状态一并清掉，退化为刷屏。
// 审计轮转失败日志（auditFailureShouldLog）委托本实现，两族窗口口径因此只有
// 一处可改。
//
// seen 传指针是因为超限重置需要替换整张表；调用方持有对应锁并保证 seen 非 nil。
func throttleWarnAllowedCapped[K comparable](seen *map[K]time.Time, key K, now time.Time, window, retention time.Duration, cap int) bool {
	if retention < window {
		retention = window
	}
	if last, ok := (*seen)[key]; ok && now.Sub(last) < window {
		return false
	}
	throttleWarnEvict(*seen, now, retention)
	if cap > 0 && len(*seen) > cap {
		*seen = make(map[K]time.Time)
	}
	(*seen)[key] = now
	return true
}

// throttleWarnEvict 回收早于 retention 的键。调用方持锁。
func throttleWarnEvict[K comparable](seen map[K]time.Time, now time.Time, retention time.Duration) {
	for seenKey, seenAt := range seen {
		if now.Sub(seenAt) >= retention {
			delete(seen, seenKey)
		}
	}
}
