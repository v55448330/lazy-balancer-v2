// Package lbreqmon 提供 HTTP 反代请求的内存观测 Caddy 模块（零磁盘 I/O）：
//
//   - http.handlers.lb_reqmon：每请求捕获 (ts, client_ip, method, host,
//     uri, status, 耗时, 大小) 写入进程内固定容量环形缓冲（编译期常量
//     50000 条，~15MB），原子覆盖最旧记录；
//   - admin.api.lb_reqmon：GET /lb/reqmon/snapshot 快照端点（admin.api
//     模块随编译自动挂载，无需配置启用——caddygeoip TrafficStatsAdmin
//     同模式），按最新优先输出。
//
// 设计裁定（2026-11-11 用户确认）：不读取访问日志、零磁盘 I/O；容量为
// 编译期固定值不做设置项。LB 面板打开时才经 admin API 拉取快照。
//
// 并发模型：写侧 8 分片互斥（分片=下标取模），读侧依次取全部分片锁——
// 单次 push 临界区仅一条记录赋值，高并发下分片间无争用；快照读是低频
// 操作（面板打开+TTL 缓存），全锁遍历可接受。
package lbreqmon

import (
	"container/heap"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// RingCapacity 环形缓冲容量（编译期常量，用户裁定不做设置项）。
const RingCapacity = 50000

// ringShards 写侧分片数（临界区分摊）。
const ringShards = 8

// RequestRecord 单条请求观测记录（快照 JSON 字段与 LB 消费端契约锁定）。
type RequestRecord struct {
	Ts         int64   `json:"ts"` // unix 毫秒
	ClientIP   string  `json:"client_ip"`
	Method     string  `json:"method"`
	Proto      string  `json:"proto"`   // HTTP/1.1 | HTTP/2.0 | HTTP/3（r.Proto）
	Scheme     string  `json:"scheme"`  // https | http（r.TLS 判定）
	RuleID     string  `json:"rule_id"` // X-LB-Rule-ID（headers 链首 set，reqmon 在其后执行可读到）
	UA         string  `json:"ua"`      // User-Agent（完整原文，展示侧自行简化）
	Host       string  `json:"host"`
	URI        string  `json:"uri"`
	Status     int     `json:"status"`
	DurationMs float64 `json:"duration_ms"`
	Size       int64   `json:"size"`     // 响应字节数
	ReqSize    int64   `json:"req_size"` // 请求字节数（Content-Length，-1=流式/无）
}

type ringShard struct {
	mu    sync.Mutex
	slots []RequestRecord // 预分配容量
	count uint64          // 本分片累计写入数（含覆盖）
}

var (
	ringInit sync.Once
	shards   [ringShards]ringShard
	writeIdx atomic.Uint64 // 全局单调写指针（跨分片定位）
)

func ringInitOnce() {
	ringInit.Do(func() {
		per := RingCapacity / ringShards
		for i := range shards {
			shards[i].slots = make([]RequestRecord, per)
		}
	})
}

// Record 写入一条记录（路径热段：取号→分片锁→赋值）。
func Record(rec RequestRecord) {
	ringInitOnce()
	idx := writeIdx.Add(1) - 1
	shard := &shards[idx%ringShards]
	shard.mu.Lock()
	shard.slots[(idx/ringShards)%uint64(len(shard.slots))] = rec
	shard.count++
	shard.mu.Unlock()
}

// Snapshot 全量快照（最新优先；未写满时只返回已写入部分）。
// 读侧依次取全部分片锁——与写侧互斥但分片粒度不放大写延迟。
func Snapshot() []RequestRecord {
	out := snapshotRecords()
	// 最新优先（全局单调序按 Ts 排序——分片遍历序非时间序）。
	// 插入排序不适用大 N：用标准排序（50k 条 ~几 ms，低频路径可接受）。
	sortByTsDesc(out)
	if len(out) > RingCapacity {
		out = out[:RingCapacity]
	}
	return out
}

// SnapshotTopN 最新 N 条（top-N 选择，不做全量排序）。
// 分片收集与 Snapshot 同语义（依次取分片锁、允许少读极新记录）；
// 选择用容量 N 的最小堆：O(M log N)（M=已写入条数），N ≪ M 时远低于
// 全量 O(M log M) 排序；结果按 Ts 降序（N 条排序可忽略）。
// limit<=0 返回 nil（调用方回落全量快照）。
func SnapshotTopN(limit int) []RequestRecord {
	if limit <= 0 {
		return nil
	}
	h := &tsMinHeap{}
	forEachRecord(func(rec RequestRecord) {
		if h.Len() < limit {
			heap.Push(h, rec)
			return
		}
		if rec.Ts > (*h)[0].Ts {
			(*h)[0] = rec
			heap.Fix(h, 0)
		}
	})
	out := []RequestRecord(*h)
	sortByTsDesc(out)
	return out
}

// snapshotRecords 分片收集全部已写入记录（未排序）。
// 期间的新写入可能落进已锁过的分片——快照语义允许（少读到极新记录），
// 不做全局锁。
func snapshotRecords() []RequestRecord {
	ringInitOnce()
	out := make([]RequestRecord, 0, RingCapacity)
	for i := range shards {
		shards[i].mu.Lock()
		n := shards[i].count
		if n > uint64(len(shards[i].slots)) {
			out = append(out, shards[i].slots...)
		} else {
			out = append(out, shards[i].slots[:n]...)
		}
		shards[i].mu.Unlock()
	}
	return out
}

// forEachRecord 逐条访问已写入记录（分片锁内回调，调用方不得阻塞）。
func forEachRecord(fn func(RequestRecord)) {
	ringInitOnce()
	for i := range shards {
		shards[i].mu.Lock()
		n := shards[i].count
		if n > uint64(len(shards[i].slots)) {
			n = uint64(len(shards[i].slots))
		}
		for j := uint64(0); j < n; j++ {
			fn(shards[i].slots[j])
		}
		shards[i].mu.Unlock()
	}
}

// tsMinHeap 容量受限的最小堆（按 Ts）：堆顶=当前 top-N 中最旧一条，
// 新记录更晚即替换堆顶——标准 container/heap 接口。
type tsMinHeap []RequestRecord

func (h tsMinHeap) Len() int           { return len(h) }
func (h tsMinHeap) Less(i, j int) bool { return h[i].Ts < h[j].Ts }
func (h tsMinHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *tsMinHeap) Push(x any)        { *h = append(*h, x.(RequestRecord)) }
func (h *tsMinHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	old[n-1] = RequestRecord{} // 释放引用（字符串字段）
	*h = old[:n-1]
	return x
}

func sortByTsDesc(recs []RequestRecord) {
	// 50k 条标准排序 ~几 ms，快照读是低频路径（面板打开+TTL 缓存）可接受。
	if len(recs) < 2 {
		return
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Ts > recs[j].Ts })
}

// clientIP 客户端 IP 判定：优先 Caddy client_ip 变量——trusted_proxies 启用
// 时它经「回源网段 + 有序请求头」校验，伪造头不改变判定；变量缺席回落
// RemoteAddr host。绝不采信裸 X-Forwarded-For（直连客户端可任意伪造，
// 与 caddygeoip.realClientIP 同口径）。
func clientIP(r *http.Request) string {
	if ip, ok := caddyhttp.GetVar(r.Context(), caddyhttp.ClientIPVarKey).(string); ok && ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		if net.ParseIP(r.RemoteAddr) != nil {
			return r.RemoteAddr
		}
		return ""
	}
	return host
}

// statusWriter 最小响应捕获包装（嵌入原接口，只覆写计数点）。
type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += int64(n)
	return n, err
}

// Unwrap 暴露底层 ResponseWriter：http.ResponseController 依赖 Unwrap 链
// 找到 Hijacker/Flusher（缺此方法则全站 WebSocket 升级报 not supported；
// reqmon 挂全部 HTTP 规则，断链影响面=全站）。
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
