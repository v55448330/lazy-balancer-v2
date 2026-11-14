package lbhuman

// （时间源统一走 timeNow——测试替换后窗口判定与记录同钟。）

// ccPeek 当前窗口统计快照（不增量，值拷贝不携带共享 map）。窗口过期返回零值。
func ccPeek(key string, windowSec int) CCWindowStats {
	ccInit()
	shard := ccShardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	st, ok := shard.m[key]
	if !ok {
		return CCWindowStats{}
	}
	now := timeNow().Unix()
	if now-st.WindowStart >= int64(windowSec) {
		return CCWindowStats{}
	}
	return st.snapshot()
}
