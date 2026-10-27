package caddygeoip

// 全请求实时流量计数（大屏「无 accesslog 光流」数据源，Plan B）：
//   - per-country 双计数器（attack=安全拦截 isSecurityBlock 同口径；normal=
//     非 安全中断 的已处理请求）——进程级常驻内存，国名桶硬上限 512（满员
//     只丢新键，已有键继续计数），随进程生命周期，无文件/无 goroutine。
//   - 暴露：TrafficStatsAdmin 实现 caddy.AdminRouter——GET /lb/traffic-stats
//     请求到达时序列化当前快照。计数**只在采集租约有效期间推进**
//     （traffic_lease.go 的租约激活门 + TTL 自清；blocked_counter 热路径在
//     无租约时只做一次 atomic load 即返回），快照的 collecting 字段披露租约
//     当前是否有效——否则「累计不变」与「无流量」不可区分。无常驻写者：
//     页面异常关闭后租约按 TTL 自清，零残留。
//   - QPS 保险丝：单秒请求计数超过 fuseQPSPerSecond 时进入 1/N 抽样（N=8，
//     每 N 个请求计 1 次×N 还原），翻秒且上一秒计数低于阈值 1/4 时回落 N=1。
//     误差口径披露：抽样期估计量=真值±N（相位偏移 <N 的 floor 量化截断，
//     整秒累计口径无偏）——大屏光流为密度示意，可接受。
//   - 国名口径：计数/事件桶键经 geoipnames.NormalizeCountry 归一（xdb 中文
//     异体如「美国」折叠为英文规范名；「中国」保留）——app 聚合端点按翻译
//     后中文名重建 map（覆盖语义），异体分键会被丢计数；
//     客户端请求头不参与计数，本模块不加依赖。
//   - 统计边界：计数由链尾 lb_security_blocked_counter 执行；国名只来自
//     geoip2region 的服务端变量。未启用地域能力的规则没有该变量，因此不产生
//     国名桶；大屏流量卡不是全站请求总量。
//   - 注册语义：admin 服务每次（重）启动都重建 mux 并实例化全部 admin.api
//     模块，路由由新 mux 重新注册——本模块无实例状态（只读全局计数器），
//     reload 不存在「同路径重复注册」问题。

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"

	"lazy-balancer-v2/geoipnames"
)

type trafficEntry struct {
	attack atomic.Uint64
	normal atomic.Uint64
}

var (
	trafficMu        sync.RWMutex
	trafficCountries = map[string]*trafficEntry{}

	// trafficSecondState 惰性翻秒 + 当前秒计数的打包原子态：
	// (unixSec<<32)|hits。旧实现 second 与 hits 是
	// 两个独立原子——翻秒路径 Swap(sec) 与并发 Add(1) 之间无配对，跨秒瞬间
	// 的命中会落在被随后 Swap(0) 丢弃的计数里（翻秒丢计）。打包 CAS 把
	// 「读当前秒 + 自增」变成单一线性化操作。
	trafficSecondState atomic.Uint64
	trafficSampleN     atomic.Uint32 // 抽样因子 N（1=全量）
)

// trafficCountryLimit 限定常驻国名桶数量；实际 xdb 国家数远低于此值。
const trafficCountryLimit = 512

// trafficSecondState 的打包布局。
const trafficHitsMask = 0xffffffff

// trafficBumpSecond 在当前秒计数 +1 并返回 (新 hits, 上一秒 hits, 是否翻秒)。
func trafficBumpSecond(nowSec uint64) (hits, prevHits uint32, rolled bool) {
	for {
		old := trafficSecondState.Load()
		oldSec := old >> 32
		oldHits := uint32(old & trafficHitsMask)
		if oldSec == nowSec && oldHits < trafficHitsMask {
			if trafficSecondState.CompareAndSwap(old, (nowSec<<32)|uint64(oldHits+1)) {
				return oldHits + 1, oldHits, false
			}
			continue
		}
		if oldSec != nowSec {
			// 翻秒（含时钟回拨）：新秒从 1 起算，上一秒计数完整交还调用方。
			if trafficSecondState.CompareAndSwap(old, (nowSec<<32)|1) {
				return 1, oldHits, true
			}
			continue
		}
		// hits 饱和（理论不可达：1e9 QPS）：保持当前秒不再自增。
		return oldHits, oldHits, false
	}
}

const (
	fuseQPSPerSecond = 4000 // 单秒请求计数超过此值 → 进入 1/8 抽样
	fuseSampleN      = 8
	// 抽样期单秒计数低于此值 → 回落全量：×8 估计真值 <8000，与进入阈值
	// 4000 构成 4000–8000 的滞回带（旧注释「真值≈×8 < fuseQPS」
	// 与数值不符——1000×8=8000 > 4000）。
	fuseFallbackPerSecond = 1000
)

// trafficCountryKeyValid 判定国名键是否为可展示的国家值：xdb 对私网/保留
// 网段行的国家列常为 "0"/"Reserved"，不可解析行为空串。与事件聚合端点
// （internal/handlers/security_threat_screen.go 的 ""/"0"/"Reserved" 过滤）
// 同口径——大屏只为真实国家画弧/建桶。
func trafficCountryKeyValid(country string) bool {
	switch strings.TrimSpace(country) {
	case "", "0", "Reserved":
		return false
	}
	return true
}

// trafficCountryDropped 记录因满员被丢弃的新国名键累计数（可观测面：
// 大屏少计不再无声——满员时 countries 桶缺该国家而快照无任何信号）。
var trafficCountryDropped atomic.Uint64

func trafficEntryFor(country string) *trafficEntry {
	trafficMu.RLock()
	e := trafficCountries[country]
	trafficMu.RUnlock()
	if e != nil {
		return e
	}
	trafficMu.Lock()
	if e = trafficCountries[country]; e == nil {
		// 硬上限兜底：即使未来新增其他调用源，也不能让国家键无界增长。
		// 满员只丢新键，已有国家继续精确计数。
		if len(trafficCountries) >= trafficCountryLimit {
			trafficMu.Unlock()
			trafficCountryDropped.Add(1)
			// 首报即记 + 窗口抑制（复用快照加载族的节流实现）：满员是持续态，
			// 不节流会按请求速率刷屏；状态变化不需要区分，永久满员只需一条/分钟。
			crawlerSnapshotLogfThrottled("traffic-countries", "full",
				"traffic stats country bucket full (limit %d), new country %q dropped (dropped_total=%d)",
				trafficCountryLimit, country, trafficCountryDropped.Load())
			return nil
		}
		e = &trafficEntry{}
		trafficCountries[country] = e
	}
	trafficMu.Unlock()
	return e
}

// normalizeTrafficCountryKey 归一统计/事件桶的国名键
// TrimSpace 后海外异体（xdb 中文「美国」等）经 geoipnames.NormalizeCountry
// 折叠为规范名——与发射侧 geoipLocFor（handler.go）同表同函数；「中国」
// 保留（NormalizeCountry 对其返回空串，须前置保留）；无效值（空/0/Reserved）
// 折叠为空串，由 trafficCountryKeyValid 过滤。归一在入口完成：app 聚合端点
// 按翻译后中文名重建 map 是覆盖语义，异体分键会丢一桶计数。
func normalizeTrafficCountryKey(country string) string {
	country = strings.TrimSpace(country)
	if country == "中国" {
		return country
	}
	return geoipnames.NormalizeCountry(country)
}

// trafficNowUnix 秒级时钟测试缝——trafficRecord 的翻秒/保险丝判定经本函数
// 取秒，测试冻结墙钟可消除「循环跨秒导致秒计数重累计」的假红。
var trafficNowUnix = func() int64 { return time.Now().Unix() }

// trafficRecord 记一次请求（country 非国家值=未解析/私网保留段——跳过；
// 抽样期按 1/N 计数并 ×N 还原）。
func trafficRecord(country string, attack bool) {
	// 国名键 TrimSpace + 异体归一——否则空白异形
	// （" 中国"）与中文异体（"美国"）各建脏桶，大屏出现重复国桶且 app 侧
	// 覆盖式聚合丢计数。发射侧已归一，此处为纵深防御。
	country = normalizeTrafficCountryKey(country)
	if !trafficCountryKeyValid(country) {
		return
	}
	// 惰性翻秒 + 保险丝状态机（全量→1/8 抽样→全量，滞回防抖动）。
	// 翻秒与自增是单个 CAS（打包秒戳+计数），并发 Add 不会被
	// 随后清零的上一秒计数吞掉。
	hits, prevHits, rolled := trafficBumpSecond(uint64(trafficNowUnix()))
	if rolled && prevHits < fuseFallbackPerSecond {
		trafficSampleN.Store(1)
	}
	trafficSampleN.CompareAndSwap(0, 1)
	if hits == fuseQPSPerSecond+1 {
		trafficSampleN.Store(fuseSampleN)
	}
	n := trafficSampleN.Load()
	if n > 1 && hits%uint32(n) != 0 {
		return // 抽样：仅计每 N 个请求（×N 还原）
	}
	if n == 0 {
		n = 1
	}
	e := trafficEntryFor(country)
	if e == nil {
		return
	}
	if attack {
		e.attack.Add(uint64(n))
	} else {
		e.normal.Add(uint64(n))
	}
}

// trafficSnapshotJSON 序列化当前快照：{"countries":{...},"sample_n":N,"collecting":bool}——
// countries 键=原始国名（app 侧翻译中文），值=累计计数（自进程启动）。
// 计数只在采集租约有效期间推进（无租约时 blocked_counter 热路径直接返回），
// 因此必须发射 collecting：否则「累计不变」与「无流量」不可区分（available
// 只表示 admin 可达）。字段语义=采集租约当前是否有效。
func trafficSnapshotJSON() []byte {
	trafficMu.RLock()
	defer trafficMu.RUnlock()
	b := []byte(`{"countries":{`)
	first := true
	for country, e := range trafficCountries {
		if first {
			first = false
		} else {
			b = append(b, ',')
		}
		b = append(b, '"')
		b = appendJSONString(b, country)
		b = append(b, '"')
		b = append(b, ':')
		b = append(b, '{')
		b = append(b, `"attack":`...)
		b = appendUint(b, e.attack.Load())
		b = append(b, `,"normal":`...)
		b = appendUint(b, e.normal.Load())
		b = append(b, '}')
	}
	b = append(b, `},"sample_n":`...)
	b = appendUint(b, uint64(trafficSampleN.Load()))
	b = append(b, `,"collecting":`...)
	if trafficCollectorActive() {
		b = append(b, "true"...)
	} else {
		b = append(b, "false"...)
	}
	b = append(b, '}')
	return b
}

// appendJSONString 生成 JSON 字符串字面量的转义内容（调用方自行加两侧引号）。
// 国名来自 GeoIP 解析结果，可能含引号/控制字节/非法 UTF-8：逐字节手写转义会
// 把非法 UTF-8 原样写入，使整个快照端点解析失败。改用 encoding/json 统一
// 处理（非法 UTF-8 替换为 U+FFFD，控制字节按 \u 转义）——单次快照至多
// trafficCountryLimit 个键，序列化开销可忽略。
func appendJSONString(dst []byte, s string) []byte {
	// json.Marshal 对 string 类型恒不返回 error，只保留长度防御。
	quoted, _ := json.Marshal(s)
	if len(quoted) < 2 {
		return dst
	}
	return append(dst, quoted[1:len(quoted)-1]...)
}

func appendUint(dst []byte, v uint64) []byte {
	if v == 0 {
		return append(dst, '0')
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return append(dst, buf[i:]...)
}

// serveTrafficStats admin 端点处理器（只读快照；AdminHandler 签名）。
func serveTrafficStats(w http.ResponseWriter, r *http.Request) error {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(trafficSnapshotJSON())
	return nil
}

// TrafficStatsAdmin admin.api 模块：把 /lb/traffic-stats 注册进 Caddy admin
// API（无鉴权面=admin 端点本体，Caddy 自行按 admin 配置限制来源）。admin
// 服务每次（重）启动重建 mux 并实例化全部 admin.api 模块——同路径重复注册
// 不经此模块实例（无实例状态，读全局计数器），无 reload 重复注册问题。
type TrafficStatsAdmin struct{}

// CaddyModule returns the Caddy module information.
func (TrafficStatsAdmin) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "admin.api.lb_traffic_stats",
		New: func() caddy.Module { return new(TrafficStatsAdmin) },
	}
}

// Routes registers the read-only traffic snapshot endpoint.
func (TrafficStatsAdmin) Routes() []caddy.AdminRoute {
	return []caddy.AdminRoute{
		{
			Pattern: "/lb/traffic-stats",
			Handler: caddy.AdminHandlerFunc(serveTrafficStats),
		},
		{
			Pattern: "/lb/traffic-collector",
			Handler: caddy.AdminHandlerFunc(serveTrafficCollector),
		},
		{
			Pattern: "/lb/traffic-events",
			Handler: caddy.AdminHandlerFunc(serveTrafficEvents),
		},
	}
}

// Interface guards(编译期契约)。
var (
	_ caddy.AdminRouter = (*TrafficStatsAdmin)(nil)
)
