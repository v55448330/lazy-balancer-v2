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
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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
	ringInitOnce()
	total := uint64(0)
	for i := range shards {
		shards[i].mu.Lock()
		total += shards[i].count
		shards[i].mu.Unlock()
	}
	// 二次取：期间的新写入可能落进已锁过的分片——快照语义允许（少读
	// 到极新记录；总条数以第二次 count 计），不做全局锁。
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
	// 最新优先（全局单调序按 Ts 排序——分片遍历序非时间序）。
	// 插入排序不适用大 N：用标准排序（50k 条 ~几 ms，低频路径可接受）。
	sortByTsDesc(out)
	if len(out) > RingCapacity {
		out = out[:RingCapacity]
	}
	_ = total
	return out
}

func sortByTsDesc(recs []RequestRecord) {
	// 50k 条标准排序 ~几 ms，快照读是低频路径（面板打开+TTL 缓存）可接受。
	if len(recs) < 2 {
		return
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Ts > recs[j].Ts })
}

// clientIP 客户端 IP 判定：X-Forwarded-For 首值（Caddy 反代链自动追加）
// 优先，直连回落 RemoteAddr host。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			xff = xff[:idx]
		}
		if v := strings.TrimSpace(xff); v != "" {
			return v
		}
	}
	host := r.RemoteAddr
	if idx := strings.LastIndexByte(host, ':'); idx >= 0 {
		host = host[:idx]
	}
	return strings.Trim(host, "[]")
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
