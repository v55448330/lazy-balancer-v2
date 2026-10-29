package services

// 威胁大屏攻击光流独立采集源：只服务光流/弹框态势，不写安全事件日志。
// 安全事件日志仍由 securityevents.go 全量落库；本环形缓冲在事务提交后追加，
// 支持 1/N 抽样与容量上限，避免大屏消费路径直接扫描 security_events。

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const threatScreenAttackFlowRingMax = 4096

// ThreatScreenAttackFlowEvent 是攻击光流的轻量事件（不含请求头/正文）。
type ThreatScreenAttackFlowEvent struct {
	Seq           uint64 `json:"seq"`
	At            int64  `json:"at"`
	ClientIP      string `json:"client_ip"`
	Action        string `json:"action"`
	RuleTriggered string `json:"rule_triggered"`
	// Weight 是写入时的采样因子：1=全量，4/8=1/N 抽样后的权重。
	// 前端用 sum(weight) 还原近似总量，避免采样档位直接改变线宽语义。
	Weight uint32 `json:"weight"`
	// key 是请求去重键（0=不可去重）：只用于跨批改判时定位环内既有条目，
	// 未导出因此不进入 JSON 下发契约。
	key uint64
}

type threatScreenAttackFlowItem struct {
	at            time.Time
	clientIP      string
	action        string
	ruleTriggered string
	// key 是请求去重键（0=不可去重），供跨批改判原地定位既有条目。
	key uint64
	// inPlace 标记「跨批改判」条目：优先原地更新同键既有环条目（上一批已入环）；
	// 环内没有该键（首轮本就不入环：爬虫放行族/采样关闭当时/已被淘汰）时按普通
	// 条目补录。同一请求因此在光流中只有一条最终结论，与事件表/自动封禁一致。
	inPlace bool
}

var (
	threatScreenAttackFlowMu      sync.Mutex
	threatScreenAttackFlowEvents  []ThreatScreenAttackFlowEvent
	threatScreenAttackFlowSeq     atomic.Uint64
	threatScreenAttackFlowAttempt atomic.Uint64
	threatScreenAttackFlowSampleN atomic.Uint32
	// 请求去重键→环内序号索引：跨批改判据此定位上一批已入环的条目。
	// 与环同生命周期——裁剪时同步删除被淘汰条目的键，避免索引无限增长。
	threatScreenAttackFlowKeySeq = map[uint64]uint64{}
	// 采样档位租约表（与 Caddy 侧 traffic_lease.go 同模型）——
	// 取代「全局单值最后写者胜」：多标签页/多租约并存时单租约释放不误杀
	// 其他租约；有效档位=存活租约的 min（最密），无租约=0（关闭）。
	threatScreenAttackFlowLeases = map[string]threatScreenAttackFlowLease{}
)

const (
	threatScreenAttackFlowLeaseTTLDefault = 30 * time.Second
	threatScreenAttackFlowLeaseTTLMin     = 5 * time.Second
	threatScreenAttackFlowLeaseTTLMax     = 120 * time.Second
	// 与 Caddy 侧同族上限：lease_id 64 字节、并发租约 64 条（续租不受限）。
	threatScreenAttackFlowLeaseIDMaxLen = 64
	threatScreenAttackFlowLeaseMax      = 64
)

type threatScreenAttackFlowLease struct {
	sampleN   int
	expiresAt time.Time
}

// clampThreatScreenAttackFlowSampleN 档位归一：0=关闭；负数按 1（全量）；
// 上限 8（与前端自适应档位一致）。
func clampThreatScreenAttackFlowSampleN(n int) int {
	if n < 0 {
		n = 1
	}
	if n > 8 {
		n = 8
	}
	return n
}

// AcquireThreatScreenAttackFlowLease 登记/续租攻击光流采样租约。
// TTL 与 Caddy 侧同族：缺省 30s、钳 [5s,120s]（前端每 10s 心跳续租）。
// sample_n 钳 [0,8]。威胁大屏关闭/崩溃后租约 TTL 过期自动停止采样。
func AcquireThreatScreenAttackFlowLease(id string, ttl time.Duration, sampleN int) error {
	return acquireThreatScreenAttackFlowLeaseAt(id, ttl, sampleN, time.Now())
}

func acquireThreatScreenAttackFlowLeaseAt(id string, ttl time.Duration, sampleN int, now time.Time) error {
	if id == "" {
		return errors.New("lease_id required")
	}
	if len(id) > threatScreenAttackFlowLeaseIDMaxLen {
		return errors.New("lease_id too long")
	}
	if ttl <= 0 {
		ttl = threatScreenAttackFlowLeaseTTLDefault
	}
	if ttl < threatScreenAttackFlowLeaseTTLMin {
		ttl = threatScreenAttackFlowLeaseTTLMin
	}
	if ttl > threatScreenAttackFlowLeaseTTLMax {
		ttl = threatScreenAttackFlowLeaseTTLMax
	}
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	// 条目上限只拦新键——续租既有键不受限（满表不应让真实标签页心跳失败）。
	if _, exists := threatScreenAttackFlowLeases[id]; !exists && len(threatScreenAttackFlowLeases) >= threatScreenAttackFlowLeaseMax {
		return errors.New("too many leases")
	}
	threatScreenAttackFlowLeases[id] = threatScreenAttackFlowLease{
		sampleN:   clampThreatScreenAttackFlowSampleN(sampleN),
		expiresAt: now.Add(ttl),
	}
	refreshThreatScreenAttackFlowSampleLocked()
	return nil
}

// ReleaseThreatScreenAttackFlowLease 释放租约；无匹配=幂等成功。
func ReleaseThreatScreenAttackFlowLease(id string) {
	releaseThreatScreenAttackFlowLeaseAt(id, time.Now())
}

func releaseThreatScreenAttackFlowLeaseAt(id string, now time.Time) {
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	delete(threatScreenAttackFlowLeases, id)
	refreshThreatScreenAttackFlowSampleLocked()
}

// sweepThreatScreenAttackFlowLeasesLocked 懒清理过期租约。调用方必须持锁。
func sweepThreatScreenAttackFlowLeasesLocked(now time.Time) {
	for id, lease := range threatScreenAttackFlowLeases {
		if !now.Before(lease.expiresAt) {
			delete(threatScreenAttackFlowLeases, id)
		}
	}
}

// refreshThreatScreenAttackFlowSampleLocked 有效档位=存活租约的最密档（最小 N）；
// sampleN=0 的租约不参与 min（与 Caddy 侧同语义：租约保留但不产事件），
// 无租约/全部 0 档=0（关闭）。调用方必须持锁。
func refreshThreatScreenAttackFlowSampleLocked() {
	n := 0
	for _, lease := range threatScreenAttackFlowLeases {
		if lease.sampleN == 0 {
			continue
		}
		if n == 0 || lease.sampleN < n {
			n = lease.sampleN
		}
	}
	threatScreenAttackFlowSampleN.Store(uint32(n))
}

// ThreatScreenAttackFlowSampleN 返回当前采样档位（0=关闭）。
// 读路径顺带懒清理过期租约——租约全过期后档位自动归 0。
func ThreatScreenAttackFlowSampleN() int {
	return threatScreenAttackFlowSampleNAt(time.Now())
}

func threatScreenAttackFlowSampleNAt(now time.Time) int {
	threatScreenAttackFlowMu.Lock()
	sweepThreatScreenAttackFlowLeasesLocked(now)
	refreshThreatScreenAttackFlowSampleLocked()
	threatScreenAttackFlowMu.Unlock()
	return int(threatScreenAttackFlowSampleN.Load())
}

// threatScreenAttackFlowFlushCalls 环形缓冲批次的加锁次数（测试观测「批内
// 一次加锁」；生产成本=每批一次原子加）。含「档位 0 / 纯改判」批次——这些
// 批次同样必须持锁（改判要读写环），不再是早退免锁。
var threatScreenAttackFlowFlushCalls atomic.Int64

// threatScreenAttackFlowRecordBatch 在 security_events 事务提交成功后调用。
// 采样在环形缓冲写入前完成；失败/回滚的日志批次不得进入光流。
// 采样门只管「新弧入环」：跨批改判（inPlace）不消耗采样配额，采样档位为 0
// 时照常原地改判（见函数体内注释）。
//
// 并发不变量：环形缓冲内 Seq 必须严格递增（消费者按 `Seq <= since` 线性
// 推进游标，乱序入环会让事件重复返回/游标回退）。采样计数与序号分配因此
// 与 append 同处一个临界区（每批一次加锁，成本=批内原子加）；逐事件加锁
// 会让锁往返与 O(ring) 尾部搬移按事件数放大。
func threatScreenAttackFlowRecordBatch(items []threatScreenAttackFlowItem) {
	if len(items) == 0 {
		return
	}
	n := threatScreenAttackFlowSampleNAt(time.Now())
	threatScreenAttackFlowFlushCalls.Add(1)
	threatScreenAttackFlowMu.Lock()
	batch := make([]ThreatScreenAttackFlowEvent, 0, len(items))
	for _, item := range items {
		// 跨批改判先于采样门处理：inPlace 项不消耗采样配额，且租约在「首轮
		// 入环」与「改判到达」之间关闭（大屏关闭/心跳 TTL 过期）时环内仍有
		// 旧结论——采样门整批早退会让同一请求残留「检测」而事件表/拦截率按
		// 「拦截」计，消费者下次 since=0 读到旧弧且不会自愈，直到被容量淘汰。
		//
		// 环内已有同请求条目时原地换结论（保留原序号与权重），不消耗采样
		// 计数、不分配新序号——消费者游标因此不回退，大屏不会为同一请求
		// 同时画出「检测」与「拦截」两条弧。
		if item.inPlace && item.key != 0 {
			if idx, ok := threatScreenAttackFlowIndexLocked(item.key); ok {
				threatScreenAttackFlowEvents[idx].Action = item.action
				threatScreenAttackFlowEvents[idx].RuleTriggered = item.ruleTriggered
				continue
			}
		}
		// 采样档位 0（无存活租约）=新弧不入环（改判项已在上面消费）。
		if n == 0 {
			continue
		}
		if n > 1 && threatScreenAttackFlowAttempt.Add(1)%uint64(n) != 0 {
			continue
		}
		if n <= 1 {
			threatScreenAttackFlowAttempt.Add(1)
		}
		seq := threatScreenAttackFlowSeq.Add(1)
		batch = append(batch, ThreatScreenAttackFlowEvent{
			Seq:           seq,
			At:            item.at.UnixMilli(),
			ClientIP:      item.clientIP,
			Action:        item.action,
			RuleTriggered: item.ruleTriggered,
			Weight:        uint32(n),
			key:           item.key,
		})
	}
	if len(batch) == 0 {
		threatScreenAttackFlowMu.Unlock()
		return
	}
	threatScreenAttackFlowEvents = append(threatScreenAttackFlowEvents, batch...)
	for _, ev := range batch {
		if ev.key != 0 {
			threatScreenAttackFlowKeySeq[ev.key] = ev.Seq
		}
	}
	if over := len(threatScreenAttackFlowEvents) - threatScreenAttackFlowRingMax; over > 0 {
		// 被淘汰条目的键同步出索引：索引必须与环同界，否则键表随请求数
		// 无界增长，且陈旧键会把改判指向已不存在的序号。
		for _, ev := range threatScreenAttackFlowEvents[:over] {
			if ev.key != 0 && threatScreenAttackFlowKeySeq[ev.key] == ev.Seq {
				delete(threatScreenAttackFlowKeySeq, ev.key)
			}
		}
		threatScreenAttackFlowEvents = threatScreenAttackFlowEvents[over:]
	}
	threatScreenAttackFlowMu.Unlock()
}

// threatScreenAttackFlowIndexLocked 用请求键定位环内条目下标（调用方须持
// threatScreenAttackFlowMu）。环按 Seq 严格递增，故对序号做二分查找；索引
// 陈旧（条目已被环淘汰）时顺手清除并报告 miss。
func threatScreenAttackFlowIndexLocked(key uint64) (int, bool) {
	seq, ok := threatScreenAttackFlowKeySeq[key]
	if !ok {
		return 0, false
	}
	i := sort.Search(len(threatScreenAttackFlowEvents), func(i int) bool {
		return threatScreenAttackFlowEvents[i].Seq >= seq
	})
	if i < len(threatScreenAttackFlowEvents) && threatScreenAttackFlowEvents[i].Seq == seq {
		return i, true
	}
	delete(threatScreenAttackFlowKeySeq, key)
	return 0, false
}

// ThreatScreenAttackFlowSnapshot 返回 since 之后的攻击流事件、next_seq 与
// 「因环形缓冲溢出而永久丢失」的事件数（gapSkipped>0 即存在空洞）。
// gap 计算与正常光流同一判据（trafficEventSnapshotWithGap）：消费者游标落在
// 最老保留序号之前 ⇒ 中间记录已被环形缓冲覆盖。since=0（首屏）不算空洞。
// 两种丢失（抽样稀疏 / 环溢出丢事件）必须可区分——否则攻击洪峰下前端只能
// 看到 seq 跳号或静默丢弧，而同屏正常流会亮「事件流有空洞」。
func ThreatScreenAttackFlowSnapshot(since uint64, limit int) ([]ThreatScreenAttackFlowEvent, uint64, uint64) {
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()

	// 比较用减法而非 since+1：since==MaxUint64 时 +1 回绕为 0 会误判空洞。
	var gapSkipped uint64
	if since > 0 && len(threatScreenAttackFlowEvents) > 0 && since < threatScreenAttackFlowEvents[0].Seq && threatScreenAttackFlowEvents[0].Seq-since > 1 {
		gapSkipped = threatScreenAttackFlowEvents[0].Seq - since - 1
	}

	out := make([]ThreatScreenAttackFlowEvent, 0, limit)
	start := 0
	if since == 0 {
		if len(threatScreenAttackFlowEvents) > limit {
			start = len(threatScreenAttackFlowEvents) - limit
		}
	} else {
		// 环按 Seq 严格递增（与 threatScreenAttackFlowIndexLocked 同一口径）：
		// 首个 Seq > since 的下标即 since 游标之后的起点，与逐条线性推进
		// 等价，避免洪峰轮上的 O(n) 前缀扫描。
		start = sort.Search(len(threatScreenAttackFlowEvents), func(i int) bool {
			return threatScreenAttackFlowEvents[i].Seq > since
		})
	}
	for _, ev := range threatScreenAttackFlowEvents[start:] {
		if len(out) >= limit {
			break
		}
		out = append(out, ev)
	}
	next := since
	if since > threatScreenAttackFlowSeq.Load() {
		next = 0
	} else if len(out) > 0 {
		next = out[len(out)-1].Seq
	}
	return out, next, gapSkipped
}

// threatScreenAttackFlowGenerationResetHookForTest 在代际复位的临界区后
// 提供确定性交错缝；生产恒 nil。
var threatScreenAttackFlowGenerationResetHookForTest func()

// threatScreenAttackFlowResetRingForGeneration 在 metrics 库代际切换（损坏隔离
// 重建）时清空环形缓冲、序号与请求键索引：新库为空、审计日志从头重放，旧环保留
// 灾前条目会让重放事件与灾前弧重复出现（同屏攻击量与拦截率翻倍）。采样租约不动
// ——租约属于展示会话，与数据代际无关。
func threatScreenAttackFlowResetRingForGeneration() {
	threatScreenAttackFlowMu.Lock()
	threatScreenAttackFlowEvents = nil
	threatScreenAttackFlowKeySeq = map[uint64]uint64{}
	threatScreenAttackFlowSeq.Store(0)
	threatScreenAttackFlowAttempt.Store(0)
	threatScreenAttackFlowMu.Unlock()
	if threatScreenAttackFlowGenerationResetHookForTest != nil {
		threatScreenAttackFlowGenerationResetHookForTest()
	}
}

// ResetThreatScreenAttackFlowForTest 测试缝：清空环形缓冲、租约表与采样状态。
func ResetThreatScreenAttackFlowForTest() {
	threatScreenAttackFlowMu.Lock()
	threatScreenAttackFlowEvents = nil
	threatScreenAttackFlowKeySeq = map[uint64]uint64{}
	threatScreenAttackFlowLeases = map[string]threatScreenAttackFlowLease{}
	threatScreenAttackFlowMu.Unlock()
	threatScreenAttackFlowSeq.Store(0)
	threatScreenAttackFlowAttempt.Store(0)
	threatScreenAttackFlowSampleN.Store(0)
}

// ThreatScreenAttackFlowAppendForTest 测试缝：直接向环形缓冲追加一条光流
// 事件并返回分配到的序号（过滤/空洞判定的跨包用例需要可控的入环序列；
// 生产路径经 threatScreenAttackFlowRecordBatch 在 security_events 事务提交后
// 写入）。绕过采样与租约——采样状态由租约函数独立布置。
func ThreatScreenAttackFlowAppendForTest(clientIP, action, ruleTriggered string) uint64 {
	threatScreenAttackFlowMu.Lock()
	defer threatScreenAttackFlowMu.Unlock()
	seq := threatScreenAttackFlowSeq.Add(1)
	threatScreenAttackFlowEvents = append(threatScreenAttackFlowEvents, ThreatScreenAttackFlowEvent{
		Seq:           seq,
		At:            time.Now().UnixMilli(),
		ClientIP:      clientIP,
		Action:        action,
		RuleTriggered: ruleTriggered,
		Weight:        1,
	})
	if over := len(threatScreenAttackFlowEvents) - threatScreenAttackFlowRingMax; over > 0 {
		threatScreenAttackFlowEvents = threatScreenAttackFlowEvents[over:]
	}
	return seq
}
