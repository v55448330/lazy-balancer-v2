// Package caddygeoip —— 搜索引擎爬虫验证器（v2.3.8 地域拦截爬虫豁免，方案 B：
// UA + PTR 双跳验证，2026-10-17 用户裁定）。
//
// 验证算法（geoipnames.CrawlerEnginePTRMatch 同源语义）：
//  1. UA 命中引擎（geoipnames.MatchCrawlerEngine）
//  2. PTR 反查客户端 IP，域名后缀属该引擎官方域（机房 PTR 如
//     *.bc.googleusercontent.com 不匹配——伪装墙 1）
//  3. 正向回验：PTR 域名解析结果包含客户端 IP（防自配 PTR——伪装墙 2/3）
//
// 性能（2000/s 正常 + 100/s 攻击基准）：非爬虫 UA 不做 DNS/PTR，但需顺序
// 扫描引擎预编译正则表（未命中=全表成本）；验证按 IP 缓存（正 1h/确定性负
// 10min，瞬态失败不缓存）；在途 DNS 信号量 32 非阻塞（满员立即 fail-closed，
// 无 goroutine 堆积）；单查询 500ms 超时。
package caddygeoip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/wafiplist"
)

// crawlerDNSResolver 解析器接口（测试替身注入点）。
type crawlerDNSResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupHost(ctx context.Context, host string) ([]string, error)
}

// crawlerVerifyResolver 可注入解析器（测试替身）；缺省 net 包。
var crawlerVerifyResolver crawlerDNSResolver = &netResolver{}

type netResolver struct{}

func (n *netResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	return net.DefaultResolver.LookupAddr(ctx, addr)
}

func (n *netResolver) LookupHost(ctx context.Context, host string) ([]string, error) {
	return net.DefaultResolver.LookupHost(ctx, host)
}

// crawlerVerifyCache 验证结论缓存条目。
type crawlerVerifyCache struct {
	ok      bool
	expires time.Time
}

const (
	crawlerCachePositiveTTL = time.Hour
	crawlerCacheNegativeTTL = 10 * time.Minute
	crawlerDNSQueryTimeout  = 500 * time.Millisecond
	// crawlerVerifySlots 在途 DNS 并发上限（非阻塞获取：满员 fail-closed）
	crawlerVerifySlots = 32
	// crawlerCachePruneProbeLimit 限制单次新键插入时的回收工作量，避免满员后
	// 对 200k map 做全表扫描。map 遍历顺序不作保证；探针内先回收过期条目，
	// 并至多记住一个**活跃负结论**作为候选（插入前淘汰）——正结论绝不淘汰。
	// 探针未找到可回收条目时新结论不缓存（留痕）。
	crawlerCachePruneProbeLimit = 64
)

var (
	crawlerCacheMu sync.Mutex
	crawlerCache   = map[string]crawlerVerifyCache{}
	// crawlerCachePruneVisitsForTest 记录满员回收实际检查的条目数；由
	// crawlerCacheMu 保护，供容量路径的有界工作量钉测读取。
	crawlerCachePruneVisitsForTest int
	// crawlerVerifySem 非阻塞信号量（cap 32；关账本式释放）
	crawlerVerifySem = make(chan struct{}, crawlerVerifySlots)
	// crawlerCacheMax 容量护栏：到上限时在固定探针内回收过期条目，并至多淘汰
	// 一个**活跃负结论**以接纳新结论（负结论丢弃后 10min 可重验，正结论绝不
	// 淘汰）。探针内无可回收条目时（正结论占满）新结论不缓存并留痕；
	// 已存在键原位更新，不增加条目数。
	crawlerCacheMax = 200_000
)

// CrawlerVerdict 是爬虫验证的三态结论。
//
// 二态（bool）曾把「确定否定」与「无法判定」压成同一个 false，下游一律置
// X-LB-Crawler-Spoof → 真实搜索引擎爬虫在 DNS 抖动/并发饱和时被当成伪装
// 并实际阻断（还产生伪伪装事件）。三态后仅确定否定计伪装：瞬态既不豁免也
// 不判伪装（不误封真爬虫、不伪造安全事件），豁免面保持 fail-closed。
type CrawlerVerdict uint8

const (
	// CrawlerVerdictTransient 本次无法得出结论（信号量饱和/超时/解析错误/
	// 官方段快照不可用）：不置任何验证头。
	CrawlerVerdictTransient CrawlerVerdict = iota
	// CrawlerVerdictVerified 确定性通过（PTR+正向回验 / 官方段命中）。
	CrawlerVerdictVerified
	// CrawlerVerdictSpoof 确定性否定（PTR 不属官方域/正向回验不含原 IP/
	// 官方段内无命中/地址不可解析）。
	CrawlerVerdictSpoof
)

// VerifyCrawler 验证客户端 IP 是否为该引擎官方爬虫出口（带缓存）。
// 只有确定性结论（Verified/Spoof）进入缓存；瞬态结论仅作用于本次请求，
// 不写 10 分钟负缓存。
func VerifyCrawler(ip, engineID string) CrawlerVerdict {
	key := crawlerVerifyCacheKey(ip) + "|" + engineID
	now := time.Now()
	crawlerCacheMu.Lock()
	if entry, hit := crawlerCache[key]; hit && now.Before(entry.expires) {
		crawlerCacheMu.Unlock()
		if entry.ok {
			return CrawlerVerdictVerified
		}
		return CrawlerVerdictSpoof
	}
	crawlerCacheMu.Unlock()

	verdict := CrawlerVerdictTransient
	cacheable := false
	if geoipnames.CrawlerEngineVerifyMethod(engineID) == geoipnames.CrawlerVerifyIPRange {
		// 官方声明不支持 nslookup 的厂商（360）：官方 IP 段验证（名单表=
		// 定时更新任务的快照，更新即生效，无需重载）。O(log n) 查找本身很便宜，
		// 不缓存结论——否则 CIDR 被官方移除后仍可豁免至多 1h（负结论同样不
		// 缓存：快照更新即时生效）。
		verdict = verifyCrawlerIPRangeVerdict(ip, engineID)
	} else {
		if !acquireCrawlerSlot() {
			return CrawlerVerdictTransient // 瞬态资源饱和：本次不形成持久结论。
		}
		verified, dnsCacheable := verifyCrawlerDNS(ip, engineID)
		releaseCrawlerSlot()
		cacheable = dnsCacheable
		if verified {
			verdict = CrawlerVerdictVerified
		} else if cacheable {
			verdict = CrawlerVerdictSpoof
		}
	}
	if !cacheable || verdict == CrawlerVerdictTransient {
		return verdict
	}
	ok := verdict == CrawlerVerdictVerified
	ttl := crawlerCacheNegativeTTL
	if ok {
		ttl = crawlerCachePositiveTTL
	}
	crawlerCacheMu.Lock()
	_, keyExists := crawlerCache[key]
	var negativeCandidate string
	haveNegativeCandidate := false
	if len(crawlerCache) >= crawlerCacheMax {
		// 固定探针数内：回收过期条目，并记住一个**活跃负结论**作为候选。
		// 负结论（10min TTL）与正结论（1h TTL）共用容量池时，攻击者可用
		// 海量自有 IP + 爬虫 UA 把池填满，使合法爬虫的新结论无法缓存
		// （退化为逐请求 DNS）。正结论绝不淘汰（误删会让真爬虫同样退化）；
		// 负结论丢弃后 10min 可重验，代价可控。探针总数仍受
		// crawlerCachePruneProbeLimit 约束，绝不全表扫描。
		probed := 0
		for cachedKey, entry := range crawlerCache {
			probed++
			crawlerCachePruneVisitsForTest++
			if !now.Before(entry.expires) {
				delete(crawlerCache, cachedKey)
			} else if !entry.ok && !haveNegativeCandidate && cachedKey != key {
				negativeCandidate = cachedKey
				haveNegativeCandidate = true
			}
			if probed >= crawlerCachePruneProbeLimit || len(crawlerCache) < crawlerCacheMax {
				break
			}
		}
		if len(crawlerCache) >= crawlerCacheMax && haveNegativeCandidate && !keyExists {
			delete(crawlerCache, negativeCandidate)
		}
	}
	_, keyExists = crawlerCache[key]
	cached := false
	if len(crawlerCache) < crawlerCacheMax || keyExists {
		crawlerCache[key] = crawlerVerifyCache{ok: ok, expires: now.Add(ttl)}
		cached = true
	}
	crawlerCacheMu.Unlock()
	if !cached {
		// 满员且探针内无可回收的负结论：新结论不缓存（正结论占满或探针
		// 未命中）。该降级必须留痕迹，否则表现为「DNS 解析量无故升高」。
		crawlerSnapshotLogfThrottled("crawler-verify-cache", "full",
			"crawler verification cache is full (%d entries): new conclusion for engine %s is not cached; verification falls back to per-request DNS",
			crawlerCacheMax, engineID)
	}
	return verdict
}

// crawlerVerifyCacheKey 归一缓存键：4in6 映射形态（::ffff:a.b.c.d）与 v4 规范串
// 是同一主机，必须共用同一条缓存（验证本体已在 Unmap 后比较，键不归一会让
// 同一地址占两份条目、各跑一次 PTR+正向回验，攻击者还可用两种文本形态额外
// 占用缓存槽与 DNS 配额）。不可解析/带 zone 的输入沿用原串——这类输入在验证
// 侧是确定性否定（fail-closed）或瞬态，键归一与否不影响结论。
func crawlerVerifyCacheKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || addr.Zone() != "" {
		return ip
	}
	return addr.Unmap().String()
}

// verifyCrawlerDNS 双跳验证本体（无缓存、需已持信号量）。第二个返回值表示
// 结论是否可缓存：PTR/正向回验的确定性否定为 true；NXDOMAIN 同样是权威否定，
// 其余解析错误/超时为 false。
func verifyCrawlerDNS(ip, engineID string) (bool, bool) {
	// 地址归一化比较——netip 解析 + Unmap。客户端 IP 可能是
	// 4in6 映射形态（::ffff:a.b.c.d），而 DNS 正向应答恒为 v4 规范串，
	// 字符串比较会恒不命中把真爬虫误杀；带 zone/不可解析输入 fail-closed
	// （确定性否定，可缓存）。
	want, perr := netip.ParseAddr(ip)
	if perr != nil || want.Zone() != "" {
		return false, true
	}
	want = want.Unmap()
	ctx, cancel := context.WithTimeout(context.Background(), crawlerDNSQueryTimeout)
	defer cancel()
	names, err := crawlerVerifyResolver.LookupAddr(ctx, ip)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return false, true
		}
		return false, false
	}
	transientFailure := false
	for _, name := range names {
		// LookupAddr 返回 FQDN 尾点；PTR 后缀锚定前剥除
		host := name
		if n := len(host); n > 0 && host[n-1] == '.' {
			host = host[:n-1]
		}
		if !geoipnames.CrawlerEnginePTRMatch(engineID, host) {
			continue
		}
		// 正向回验：PTR 域名解析须包含原 IP（防伪造 PTR 指向官方域）
		addrs, err := crawlerVerifyResolver.LookupHost(ctx, host)
		if err != nil {
			transientFailure = true
			continue
		}
		for _, a := range addrs {
			got, gerr := netip.ParseAddr(a)
			if gerr != nil || got.Zone() != "" {
				continue // 非法回验地址不计命中（fail-closed）
			}
			if got.Unmap() == want {
				return true, true
			}
		}
	}
	if transientFailure || ctx.Err() != nil {
		return false, false
	}
	return false, true
}

func acquireCrawlerSlot() bool {
	select {
	case crawlerVerifySem <- struct{}{}:
		return true
	default:
		return false // 满员：立即 fail-closed（不排队）
	}
}

func releaseCrawlerSlot() {
	select {
	case <-crawlerVerifySem:
	default:
	}
}

// crawlerIPListFile 厂商 IP 段名单快照文件（root 服务写、插件读——模块边界：
// caddygeoip 独立模块不 import 根模块，快照经共享文件交换）。
// defaultCrawlerIPListFile 与根服务容器默认逐字节一致（插件侧
// 兜底；根服务自定义 data_dir 时渲染侧经 crawler_ip_list_file 配置键下发
// 派生路径，由 GeoIPHandler.Provision 应用）。
const defaultCrawlerIPListFile = "/app/data/crawler-ip-lists.json"

var (
	// crawlerIPListFileMu 保护 crawlerIPListFile：Provision（配置重载）写、
	// 判定热路径经 crawlerIPListFilePath 读，重载窗口内可并发。
	crawlerIPListFileMu sync.Mutex
	crawlerIPListFile   = defaultCrawlerIPListFile
)

// crawlerIPListFilePath 返回当前快照交换文件路径。
func crawlerIPListFilePath() string {
	crawlerIPListFileMu.Lock()
	defer crawlerIPListFileMu.Unlock()
	return crawlerIPListFile
}

// setCrawlerIPListFilePath 应用配置路径（GeoIPHandler.Provision；空值忽略）。
// 路径变化时重置快照缓存——否则旧路径的成功快照在其 TTL（≤10min）内继续
// 服役，把上一部署形态的名单带进新形态。fail-closed 语义与失败重试间隔
// （crawlerIPListRetryInterval，默认 10s）不变。
func setCrawlerIPListFilePath(path string) {
	if path == "" {
		return
	}
	crawlerIPListFileMu.Lock()
	changed := crawlerIPListFile != path
	if changed {
		crawlerIPListFile = path
	}
	crawlerIPListFileMu.Unlock()
	if changed {
		crawlerFileCacheMu.Lock()
		crawlerFileCacheSnap = nil
		crawlerFileCacheMu.Unlock()
	}
}

// crawlerIPRangeSnapshot 预编译快照：引擎 ID → 已解析前缀列表。加载时一次性
// ParsePrefix 并聚合为「升序不相交」集合（判定期二分，零解析/零分配）。
// ok=false 表示读取/解析失败的空快照——只按短重试间隔节流，成功快照按完整
// 重载间隔缓存。
type crawlerIPRangeSnapshot struct {
	prefixes map[string][]netip.Prefix
	// filePath 标识本次读取所属的路径代际；配置切换后在途旧路径读取不得
	// 写入新路径缓存。
	filePath string
	// loadedAt 是本快照开始读取的时刻（TTL 基准）。
	loadedAt time.Time
	ok       bool
	// modTime/size 是读取时打开 inode 的 stat 形态（内容代际）：写侧经
	// rename 换文件，慢读者可能读到 rename 前的旧 inode 并在新快照落定后
	// 才提交——以代际较旧者判定丢弃（与 wafiplist 同型）。
	modTime time.Time
	size    int64
	// committedAt 是落定时刻：失败读取与并发成功快照的先后判定依据。
	committedAt time.Time
}

var (
	crawlerFileCacheMu   sync.Mutex
	crawlerFileCacheSnap *crawlerIPRangeSnapshot
)

const crawlerIPListReloadInterval = 10 * time.Minute

// crawlerIPListMaxBytes 快照文件体积硬上限（4MiB，与 wafiplist 名单文件加载
// 器的 maxFileBytes/maxFastFileBytes 同口径）：正常形态为 360 引擎的官方段
// 列表（实测远小于 1MiB），超限文件按「快照不可用」fail-closed 处理——
// 异常/损坏文件不得整体读入内存放大驻留。
const crawlerIPListMaxBytes = 4 << 20

// crawlerSnapshotLogf 快照加载异常告警（体积门/坏条目/读取期改写）。日志而非
// 静默：豁免段静默缩水会让真爬虫被判伪装、产生误报事件，必须可观测。
var crawlerSnapshotLogf = func(format string, args ...any) {
	crawlerSnapshotLogCallsForTest.Add(1)
	caddy.Log().Named("geoip2region.crawler").Sugar().Warnf(format, args...)
}

// crawlerSnapshotLogInterval 是同路径同原因告警的最小间隔（对齐 wafiplist
// staleServeLogInterval 口径；0=不节流，测试用）。失败快照按
// crawlerIPListRetryInterval（10s）重读，持久异常形态（超限文件、磁盘满、
// 半截快照）不节流时约 8.6k 行/天，会稀释真实告警。原因变化立即上报
// （状态迁移必须可见）；成功快照落定后清除记录——再次故障立即可见。
var crawlerSnapshotLogInterval = time.Minute

var (
	crawlerSnapshotLogMu   sync.Mutex
	crawlerSnapshotLogLast = map[string]time.Time{} // "path|reason" → 上次上报时刻
	// crawlerSnapshotLogCallsForTest 记录实际发射的告警条数（节流后）。
	crawlerSnapshotLogCallsForTest atomic.Int64
)

// crawlerSnapshotLogfThrottled 按「路径+原因」节流告警。
func crawlerSnapshotLogfThrottled(path, reason, format string, args ...any) {
	if crawlerSnapshotLogInterval > 0 {
		key := path + "|" + reason
		now := time.Now()
		crawlerSnapshotLogMu.Lock()
		if last, ok := crawlerSnapshotLogLast[key]; ok && now.Sub(last) < crawlerSnapshotLogInterval {
			crawlerSnapshotLogMu.Unlock()
			return
		}
		crawlerSnapshotLogLast[key] = now
		crawlerSnapshotLogMu.Unlock()
	}
	crawlerSnapshotLogf(format, args...)
}

// clearCrawlerSnapshotLogs 清除该路径的节流记录（成功快照落定后调用）。
func clearCrawlerSnapshotLogs(path string) {
	prefix := path + "|"
	crawlerSnapshotLogMu.Lock()
	for key := range crawlerSnapshotLogLast {
		if strings.HasPrefix(key, prefix) {
			delete(crawlerSnapshotLogLast, key)
		}
	}
	crawlerSnapshotLogMu.Unlock()
}

// crawlerIPListRetryInterval 是失败/坏快照的重试间隔：Caddy 可能先于根服务
// 生成快照文件做首次爬虫校验（首启/冷装窗口）。旧实现把失败也缓存满 10min，
// 360 引擎豁免会 fail-closed 最长 10 分钟（伪装判定）；10s 既避免每次判定
// 读盘，又让文件出现后迅速收敛。var 供测试收窄。
var crawlerIPListRetryInterval = 10 * time.Second

// crawlerReadBoundedFile 是快照读盘唯一入口：有界代际读（体积门 + 定长读 +
// 读后同 inode 复核）与 wafiplist 名单加载器共用同一原语。var 供测试注入
// 「读期间被改写」等形态，生产恒为 wafiplist.ReadBoundedFile。
var crawlerReadBoundedFile = wafiplist.ReadBoundedFile

// loadCrawlerIPRangeSnapshot 返回当前快照（成功快照超过 10min、失败快照超过
// 重试间隔时重读）。读盘与解析在锁外完成（双检 + 原子快照替换 + 内容代际
// 守卫）：文件大/磁盘慢时不再阻塞并发判定，慢读者也不会把 rename 前的旧
// 内容写回新快照（见 commitCrawlerIPRangeSnapshot）。读取/JSON/
// 解析失败同样写入节流时间戳并返回空快照（fail-closed + 失败也节流，旧实现
// 失败路径不写时间戳，缺失文件时每次判定都尝试读盘）。
func loadCrawlerIPRangeSnapshot() *crawlerIPRangeSnapshot {
	now := time.Now()
	crawlerFileCacheMu.Lock()
	snap := crawlerFileCacheSnap
	if snap != nil {
		ttl := crawlerIPListRetryInterval
		if snap.ok {
			ttl = crawlerIPListReloadInterval
		}
		if now.Sub(snap.loadedAt) <= ttl {
			crawlerFileCacheMu.Unlock()
			return snap
		}
	}
	crawlerFileCacheMu.Unlock()

	next := &crawlerIPRangeSnapshot{prefixes: map[string][]netip.Prefix{}, loadedAt: now, filePath: crawlerIPListFilePath()}
	raw, info, readErr := crawlerReadBoundedFile(next.filePath, crawlerIPListMaxBytes)
	switch {
	case errors.Is(readErr, wafiplist.ErrFileSizeLimit):
		// 体积门（与 wafiplist 名单加载器的体积上限同口径）：异常/
		// 损坏文件不得整体读入内存；fail-closed 消费空快照。
		crawlerSnapshotLogfThrottled(next.filePath, "oversized",
			"crawler ip list snapshot %s exceeds %d bytes (size %d); treating as unavailable",
			next.filePath, crawlerIPListMaxBytes, info.Size())
	case errors.Is(readErr, wafiplist.ErrFileRewriteDuringRead):
		// 读期间被原地改写（追加/截断/同尺寸改写）：读到的只是混合字节，
		// 不当作一代内容落定；fail-closed 等下一轮重读。
		crawlerSnapshotLogfThrottled(next.filePath, "rewrite",
			"crawler ip list snapshot %s was rewritten while being read; treating as unavailable",
			next.filePath)
	case errors.Is(readErr, os.ErrNotExist):
		// 缺失：fail-closed 空快照，不告警——首启时 Caddy 先于根服务生成
		// 快照属正常形态，重试间隔内自愈。
	case readErr != nil:
		// 存在但不可读（权限/目录误挂/IO 故障）：与「尚未生成」不同——重试
		// 间隔内的静默形态会让 360 豁免持续失效且零痕迹，必须可见。
		crawlerSnapshotLogfThrottled(next.filePath, "read",
			"crawler ip list snapshot %s is unreadable: %v; treating as unavailable",
			next.filePath, readErr)
	default:
		if next.parsePayload(raw) {
			// 代际元数据取自读取所用的同一 inode（见 ReadBoundedFile）。
			next.ok, next.modTime, next.size = true, info.ModTime(), info.Size()
			clearCrawlerSnapshotLogs(next.filePath)
		} else if len(bytes.TrimSpace(raw)) == 0 {
			// 空文件（写侧崩溃残留/误 truncate）：与内容损坏区分原因，便于
			// 判断是生成链路还是磁盘问题。
			crawlerSnapshotLogfThrottled(next.filePath, "empty",
				"crawler ip list snapshot %s is empty; treating as unavailable",
				next.filePath)
		} else {
			crawlerSnapshotLogfThrottled(next.filePath, "parse",
				"crawler ip list snapshot %s is not valid JSON; treating as unavailable",
				next.filePath)
		}
	}
	return commitCrawlerIPRangeSnapshot(next)
}

// parsePayload 解析 JSON 段集，并按引擎聚合为「升序不相交」前缀集——判定
// 期二分查找的正确性依赖该不变量（与 @ipListFast 共用聚合原语）。坏条目逐条
// 跳过（单条损坏不得放大成整份豁免失效、产生误报事件），但必须可见。
// 返回 false = 内容不可用（fail-closed）：聚合后总前缀数为 0（null/{}/
// 全坏条目）同样是不可用——把空集当 ok 会让判定侧 10 分钟缓存期内恒瞬态
// （空集=瞬态），且诊断被成功路径的 clearCrawlerSnapshotLogs 抹掉。
func (s *crawlerIPRangeSnapshot) parsePayload(raw []byte) bool {
	var all map[string][]string
	if err := json.Unmarshal(raw, &all); err != nil {
		return false
	}
	badCIDRs := 0
	total := 0
	for engine, cidrs := range all {
		prefixes := make([]netip.Prefix, 0, len(cidrs))
		for _, cidr := range cidrs {
			// 与判定侧/名单侧同口径：复用 wafiplist.ParseIPEntry 单源
			// （裸 IP 补 /32、4in6 归一为 v4 前缀、带 zone 拒绝）。裸
			// netip.ParsePrefix 会把 4in6 段装进 v6 集，而查询侧 Unmap 后
			// 恒为 v4 → 该段「加载成功、运行永不命中」（真爬虫被拦 + 伪伪装
			// 事件，快照侧零告警）。
			p, err := wafiplist.ParseIPEntry(cidr)
			if err != nil {
				badCIDRs++
				continue
			}
			prefixes = append(prefixes, p)
		}
		s.prefixes[engine] = wafiplist.AggregateParsedPrefixes(prefixes)
		total += len(prefixes)
	}
	if badCIDRs > 0 {
		crawlerSnapshotLogfThrottled(s.filePath, "bad-cidr",
			"crawler ip list snapshot %s has %d unparsable CIDR entries; those entries are unavailable and grant no crawler exemption; remaining valid entries stay cached",
			s.filePath, badCIDRs)
	}
	return total > 0
}

// commitCrawlerIPRangeSnapshot 在锁内落定快照，并拒绝旧代际/陈旧失败覆盖：
//   - 路径代际不同：配置切换前发起的读取不得写入新路径缓存；若新路径尚无
//     快照，本调用 fail-closed。
//   - 成功 vs 成功：当前快照的内容代际（mtime+size）更新时，旧代际读取结果
//     丢弃（并发慢读者不得把 rename 前的旧内容写回）。
//   - 失败 vs 成功：成功快照在本失败读取开始之后才落定 → 保留成功快照
//     （瞬时读错不得把刚刷新的名单降级成空集 fail-closed）。
//
// 其余形态（TTL 到期后的失败读取、无当前快照、同代际）照常覆盖。
func commitCrawlerIPRangeSnapshot(next *crawlerIPRangeSnapshot) *crawlerIPRangeSnapshot {
	crawlerFileCacheMu.Lock()
	defer crawlerFileCacheMu.Unlock()
	currentPath := crawlerIPListFilePath()
	current := crawlerFileCacheSnap
	if next.filePath != "" && next.filePath != currentPath {
		if current != nil {
			return current
		}
		// 路径切换已清空缓存时，旧路径在途读只对本调用 fail-closed，
		// 不落定任何缓存；下一次读取会按新路径重新加载。
		return &crawlerIPRangeSnapshot{prefixes: map[string][]netip.Prefix{}, loadedAt: next.loadedAt, filePath: currentPath}
	}
	if current != nil {
		// 代际/失败守卫与名单文件加载器共用单源判定（wafiplist.SnapshotGeneration）。
		currentGen := wafiplist.SnapshotGeneration{ModTime: current.modTime, Size: current.size, CommittedAt: current.committedAt}
		nextGen := wafiplist.SnapshotGeneration{ModTime: next.modTime, Size: next.size}
		if current.ok && next.ok && wafiplist.StaleSnapshotGeneration(nextGen, currentGen) {
			return current
		}
		if current.ok && !next.ok && wafiplist.StaleFailureDowngrade(currentGen, next.loadedAt) {
			return current
		}
	}
	next.committedAt = time.Now()
	crawlerFileCacheSnap = next
	return next
}

// verifyCrawlerIPRangeVerdict 官方 IP 段验证三态：快照不可用（缺失/损坏/
// 无该引擎段）=瞬态（无法判定，不得据此判伪装）；地址不可解析（含带 zone
// 形态）与段外 = 确定否定。
func verifyCrawlerIPRangeVerdict(ipStr, engineID string) CrawlerVerdict {
	snap := loadCrawlerIPRangeSnapshot()
	entries := snap.prefixes[engineID]
	if !snap.ok || len(entries) == 0 {
		return CrawlerVerdictTransient
	}
	// 畸形地址不得 panic（MustParseAddr 旧实现可直接崩进程）——
	// 解析失败即确定为非该引擎出口。
	// 带 zone 拒绝 + 4in6 映射形态 Unmap 归一——netip 的 v4 前缀不含 4in6
	// 地址，不归一则映射形态的真爬虫恒不命中（误判为伪装）。
	ip, err := netip.ParseAddr(ipStr)
	if err != nil || ip.Zone() != "" {
		return CrawlerVerdictSpoof
	}
	ip = ip.Unmap()
	// 加载期已聚合为升序不相交集合：含目标的前缀必为最后一个 start <= 目标
	// 的前缀（与 @ipListFast 同构，O(log n)）。
	i := sort.Search(len(entries), func(i int) bool { return entries[i].Addr().Compare(ip) > 0 }) - 1
	if i >= 0 && entries[i].Contains(ip) {
		return CrawlerVerdictVerified
	}
	return CrawlerVerdictSpoof
}
