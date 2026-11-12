package lbhuman

import (
	"time"
)

// ccPeek 当前窗口统计快照（不增量）。窗口过期返回零值。
func ccPeek(key string, windowSec int) CCWindowStats {
	ccInit()
	shard := ccShardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	st, ok := shard.m[key]
	if !ok {
		return CCWindowStats{UASet: map[string]int{}}
	}
	now := time.Now().Unix()
	if now-st.WindowStart >= int64(windowSec) {
		return CCWindowStats{UASet: map[string]int{}}
	}
	// 返回副本（UASet 共享引用，evalCC 只读不写）
	return CCWindowStats{WindowStart: st.WindowStart, Count: st.Count, Status4xx: st.Status4xx, UASet: st.UASet}
}
