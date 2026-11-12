package lbhuman

import (
	"sync"
	"time"
)

// 触发计数器（CC 检测）：(rule, IP) → 滑窗统计。
// 分片 map（16 分片互斥），窗口过期自动重置，空闲条目由 janitor 定期清理。
// 零磁盘 I/O，与 lbreqmon 分片模型同源。

const ccShards = 16

// CCWindowStats 单 (rule, IP) 滑窗统计。
type CCWindowStats struct {
	WindowStart int64          // 窗口起点（unix 秒）
	Count       int            // 窗口内请求数
	Status4xx   int            // 窗口内 4xx 数
	UASet       map[string]int // 窗口内 UA 指纹→次数（会话异常检测）
}

type ccShard struct {
	mu sync.Mutex
	m  map[string]*CCWindowStats // key = rule|ip
}

var (
	ccCounters [ccShards]ccShard
	ccOnce     sync.Once
)

func ccInit() {
	ccOnce.Do(func() {
		for i := range ccCounters {
			ccCounters[i].m = map[string]*CCWindowStats{}
		}
	})
}

func ccShardFor(key string) *ccShard {
	h := uint32(0)
	for i := 0; i < len(key); i++ {
		h = h*31 + uint32(key[i])
	}
	return &ccCounters[h%ccShards]
}

// ccRecord 记录一次请求并返回窗口统计（窗口过期自动重置）。
// 窗口=windowSec 秒滑窗（起点对齐窗口边界，非严格滑窗——近似滚动窗口，
// 与既有安全事件窗口同语义）。
func ccRecord(key string, windowSec int, is4xx bool, uaFp string) CCWindowStats {
	ccInit()
	shard := ccShardFor(key)
	shard.mu.Lock()
	defer shard.mu.Unlock()
	now := time.Now().Unix()
	st, ok := shard.m[key]
	if !ok {
		st = &CCWindowStats{UASet: map[string]int{}}
		shard.m[key] = st
	}
	if now-st.WindowStart >= int64(windowSec) {
		// 窗口过期重置
		st.WindowStart = now
		st.Count = 0
		st.Status4xx = 0
		st.UASet = map[string]int{}
	}
	st.Count++
	if is4xx {
		st.Status4xx++
	}
	if uaFp != "" {
		st.UASet[uaFp]++
	}
	return CCWindowStats{WindowStart: st.WindowStart, Count: st.Count, Status4xx: st.Status4xx, UASet: st.UASet}
}

// ccJanitor 定期清理空闲条目（无窗口活动超过 5 分钟即删）。
func ccJanitor() {
	ccInit()
	for i := range ccCounters {
		shard := &ccCounters[i]
		shard.mu.Lock()
		cutoff := time.Now().Unix() - 300
		for k, st := range shard.m {
			if st.WindowStart < cutoff {
				delete(shard.m, k)
			}
		}
		shard.mu.Unlock()
	}
}

func init() {
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			ccJanitor()
		}
	}()
}

// CCTriggerResult CC 触发判定结果。
type CCTriggerResult struct {
	Triggered bool
	Reason    string // "rps_spike" | "4xx_ratio" | "session_anomaly"
}

// evalCC 判定是否触发 CC（突刺/4xx 比例/会话异常）。
// 阈值来自渲染配置（自动封禁 CC 检测规则）。
func evalCC(stats CCWindowStats, rpsLimit, windowSec, ratio4xx, sessionUACount int, sessionAnomaly bool) CCTriggerResult {
	if stats.Count > rpsLimit && rpsLimit > 0 {
		return CCTriggerResult{Triggered: true, Reason: "rps_spike"}
	}
	if ratio4xx > 0 && stats.Count >= 20 && stats.Status4xx*100 >= stats.Count*ratio4xx {
		return CCTriggerResult{Triggered: true, Reason: "4xx_ratio"}
	}
	// 会话异常：UA 数超阈+请求量下限（>=20）——独立于 RPS 阈值，
	// 避免被 rps_spike 优先级遮蔽而无法单独观测该触发类型。
	if sessionAnomaly && sessionUACount > 0 && len(stats.UASet) > sessionUACount && stats.Count >= 20 {
		return CCTriggerResult{Triggered: true, Reason: "session_anomaly"}
	}
	return CCTriggerResult{}
}
