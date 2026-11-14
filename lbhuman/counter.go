package lbhuman

import (
	"sync"
	"time"
)

// 触发计数器（CC 检测）：(rule, IP) → 滑窗统计。
// 分片 map（16 分片互斥），窗口过期自动重置，空闲条目由 janitor 定期清理。
// 零磁盘 I/O，与 lbreqmon 分片模型同源。

const ccShards = 16

// ccUASetCap 单计数器 UA 指纹集合硬上限（与挑战材料表 challengeMaterialCap
// 同口径）：distinct-UA 洪峰（session_anomaly 开启 + 高 rpsLimit + 长窗口）
// 不得无界增长内存。超帽只递增请求计数、不再存新键——UASetSize 饱和在帽上，
// 会话异常判定（UASetSize > 阈值，阈值上限 100 ≪ 帽）语义不倒退。
const ccUASetCap = 2000

// CCWindowStats 单 (rule, IP) 滑窗统计快照（值拷贝，不携带共享 map——
// UASetSize 在分片锁内取 len(UASet)，锁外读快照无数据竞争）。
type CCWindowStats struct {
	WindowStart int64 // 窗口起点（unix 秒）
	Count       int   // 窗口内请求数
	Status4xx   int   // 窗口内 4xx 数
	UASetSize   int   // 窗口内不同 UA 指纹数（会话异常检测；饱和于 ccUASetCap）
	WindowSec   int   // 本计数器登记的窗口秒数（janitor 按窗口保留）
}

// ccEntry 分片内活计数器（UASet 仅在分片锁内读写；对外只发值快照）。
type ccEntry struct {
	WindowStart int64
	Count       int
	Status4xx   int
	UASet       map[string]int
	WindowSec   int
}

func (e *ccEntry) snapshot() CCWindowStats {
	return CCWindowStats{WindowStart: e.WindowStart, Count: e.Count, Status4xx: e.Status4xx, UASetSize: len(e.UASet), WindowSec: e.WindowSec}
}

type ccShard struct {
	mu sync.Mutex
	m  map[string]*ccEntry // key = rule|ip
}

var (
	ccCounters [ccShards]ccShard
	ccOnce     sync.Once
)

func ccInit() {
	ccOnce.Do(func() {
		for i := range ccCounters {
			ccCounters[i].m = map[string]*ccEntry{}
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
		st = &ccEntry{UASet: map[string]int{}, WindowSec: windowSec}
		shard.m[key] = st
	}
	if now-st.WindowStart >= int64(windowSec) {
		// 窗口过期重置
		st.WindowStart = now
		st.Count = 0
		st.Status4xx = 0
		st.UASet = map[string]int{}
	}
	st.WindowSec = windowSec
	st.Count++
	if is4xx {
		st.Status4xx++
	}
	if uaFp != "" {
		if _, known := st.UASet[uaFp]; known || len(st.UASet) < ccUASetCap {
			st.UASet[uaFp]++
		}
		// 超帽的新 UA 不存键：请求/4xx 计数照常，集合饱和在帽上。
	}
	return st.snapshot()
}

// ccJanitor 定期清理空闲条目：无活动超过 max(300s, 窗口长度) 即删。
// 短窗口（≤300s）保持 5 分钟清理语义；长窗口活计数器保留至窗口到期，
// 不被固定 cutoff 误删。
func ccJanitor() {
	ccInit()
	now := time.Now().Unix()
	for i := range ccCounters {
		shard := &ccCounters[i]
		shard.mu.Lock()
		for k, st := range shard.m {
			retain := int64(300)
			if int64(st.WindowSec) > retain {
				retain = int64(st.WindowSec)
			}
			if now-st.WindowStart >= retain {
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
	if sessionAnomaly && sessionUACount > 0 && stats.UASetSize > sessionUACount && stats.Count >= 20 {
		return CCTriggerResult{Triggered: true, Reason: "session_anomaly"}
	}
	return CCTriggerResult{}
}
