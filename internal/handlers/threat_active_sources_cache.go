package handlers

// 威胁大屏「活跃攻击源」计数缓存：近 10 分钟原始事件表按 client_ip 去重
// （GROUP BY 全窗口扫描 + 逐行私网排除），大屏 30s 轮询下是重复的重查询。
// 键取窗口起点的分钟锚点 + TTL 45s（比 30s 轮询留一轮余量）：同一分钟锚点内
// 的重复请求复用结果，窗口跨分钟即换键。TTL 与轮询同值时第二轮落在到期边界上
// （±jitter 即 miss），缓存退化为「每轮必 miss」。秒级入参在键上截到分钟——
// 分钟内的窗口前移不换键（由 TTL 兜住陈旧上界）。失败不缓存（错误显式上抛由
// 大屏整卡 500）。

import (
	"database/sql"
	"sync"
	"time"

	"lazy-balancer-v2/internal/services"
)

// threatActiveSourcesCacheTTL 缓存有效期（45s = 大屏 30s 轮询周期的 1.5 倍）：
// 同一分钟锚点内的第二次请求必须确定性命中，热路径的 10 分钟窗口全扫才真的
// 不再每轮发生。取「轮询周期 + 一整轮余量」而不是等值——等值时第二轮恰在
// 到期边界（±调度 jitter 即 miss），缓存收益归零且没有任何用例能发现。
// 跨栈对表见 web/tests/threatFullscreenUi.spec.ts 与
// threat_screen_cache_rollup_test.go（两侧都按 1.5 倍下限判）。var 供测试缩短/关闭。
var threatActiveSourcesCacheTTL = 45 * time.Second

// threatMinuteAnchor 把秒级/任意形态的窗口起点截到分钟锚点（缓存键口径）。
// 小于 16 字符的异形值（带外写库/异形导入的 event_time）按原样返回，不得
// 直接切片（[:16] 会 panic）。仅供活跃源缓存键使用（渲染侧另有自己的锚点
// 口径，不经本 helper）。
func threatMinuteAnchor(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

type threatActiveSourcesKey struct {
	metrics *sql.DB
	since   string // 活跃窗口起点锚点（分钟串）
}

// —— 进程内 TTL 缓存单源 ——

// ttlCacheEntry 是一条缓存条目：值与到期时刻。
type ttlCacheEntry[V any] struct {
	value     V
	expiresAt time.Time
}

// ttlCache 是「键 → 值 + 到期时刻」进程内缓存的单一实现：威胁大屏活跃源/
// 被攻击目标 Top3/rollup 维度聚合/规则阶段统计/安全总览聚合五处共用同一份
// TTL 判定与淘汰逻辑（此前五处各写一遍，淘汰语义分叉且没有单点声明）。
//
// 两种淘汰策略由 maxEntries 选择：
//   - maxEntries > 0：写入时条目数已超上限即整体重建（有界增长优先于精确
//     逐出，洪峰下内存封顶）；
//   - maxEntries == 0：写入时逐键清扫过期项——分钟锚定键族每分钟产生新键，
//     整体重置会打掉同屏其它维度仍在有效期内的条目（轮询抖动）。
//
// TTL 不作为结构体字段：各缓存的 TTL 是测试可调的包级 var（构造期快照会让
// 缩短 TTL 的测试缝失效），由调用方在 Get/Set 时按自身口径传入；「TTL<=0
// 即整体关闭缓存」与「cacheable=false 不读不写」等门槛也留在调用方。
//
// 不在本结构内的两处进程内缓存属不同语义：enrichLocationCache 键含 GeoIP
// 代际（代际变更整体失效、无到期时刻），threatTrafficCache 由 singleflight
// 持有且以 admin URL 为键、无淘汰需求。
type ttlCache[K comparable, V any] struct {
	sync.Mutex
	entries    map[K]ttlCacheEntry[V]
	maxEntries int
}

// newTTLCache 构造一个进程内 TTL 缓存；maxEntries>0 走「超限整体重置」，
// 0 走「写入清扫过期」。
func newTTLCache[K comparable, V any](maxEntries int) *ttlCache[K, V] {
	return &ttlCache[K, V]{entries: make(map[K]ttlCacheEntry[V]), maxEntries: maxEntries}
}

// Get 返回未过期条目；过期条目按 miss 处理（不在此删除，交由写入侧清扫）。
func (c *ttlCache[K, V]) Get(key K, now time.Time) (V, bool) {
	c.Lock()
	defer c.Unlock()
	if entry, ok := c.entries[key]; ok && now.Before(entry.expiresAt) {
		return entry.value, true
	}
	var zero V
	return zero, false
}

// Set 写入条目并按淘汰策略腾挪（先腾挪后写入，与既有各处的判定顺序一致）。
func (c *ttlCache[K, V]) Set(key K, value V, now time.Time, ttl time.Duration) {
	c.Lock()
	defer c.Unlock()
	if c.maxEntries > 0 {
		if len(c.entries) > c.maxEntries {
			c.entries = make(map[K]ttlCacheEntry[V])
		}
	} else {
		for k, entry := range c.entries {
			if !now.Before(entry.expiresAt) {
				delete(c.entries, k)
			}
		}
	}
	c.entries[key] = ttlCacheEntry[V]{value: value, expiresAt: now.Add(ttl)}
}

// Reset 清空缓存（测试缝与失效钩子共用）。
func (c *ttlCache[K, V]) Reset() {
	c.Lock()
	c.entries = make(map[K]ttlCacheEntry[V])
	c.Unlock()
}

// —— 测试缝（生产路径一律走 Get/Set/Reset）——

// Seed 写入一条指定到期时刻的条目：测试构造「已过期/即将过期/有效」三种形状，
// 避免 wall-clock sleep。
func (c *ttlCache[K, V]) Seed(key K, value V, expiresAt time.Time) {
	c.Lock()
	c.entries[key] = ttlCacheEntry[V]{value: value, expiresAt: expiresAt}
	c.Unlock()
}

// Has 键是否存在（不判到期——用于断言「未缓存」与「已失效」两种形状）。
func (c *ttlCache[K, V]) Has(key K) bool {
	c.Lock()
	defer c.Unlock()
	_, ok := c.entries[key]
	return ok
}

// Len 当前条目数（含已过期未清扫项）。
func (c *ttlCache[K, V]) Len() int {
	c.Lock()
	defer c.Unlock()
	return len(c.entries)
}

// ExpireMatching 把匹配键的到期时刻置为零（立即过期）。
func (c *ttlCache[K, V]) ExpireMatching(match func(K) bool) {
	c.Lock()
	defer c.Unlock()
	for k, entry := range c.entries {
		if match(k) {
			entry.expiresAt = time.Time{}
			c.entries[k] = entry
		}
	}
}

// threatActiveSourcesCache 键含窗口锚点（每分钟新键），条目数上限 4：同屏
// 多维度并行取数时会短暂产生多个键，超限整体重建（有界增长优先于精确逐出）。
var threatActiveSourcesCache = newTTLCache[threatActiveSourcesKey, int](4)

// threatActiveSourcesCount 返回窗口内非保留地址的去重源 IP 数（命中缓存时
// 零查询）。activeSince 为窗口起点（UTC 墙钟串）。
func threatActiveSourcesCount(metricsDB *sql.DB, activeSince string, now time.Time) (int, error) {
	anchor := threatMinuteAnchor(activeSince)
	key := threatActiveSourcesKey{metrics: metricsDB, since: anchor}
	if threatActiveSourcesCacheTTL > 0 {
		if count, ok := threatActiveSourcesCache.Get(key, now); ok {
			return count, nil
		}
	}

	rows, err := metricsDB.Query(`SELECT COALESCE(client_ip,'') FROM security_events WHERE event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip`, activeSince)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return 0, err
		}
		if !isMissingOrReservedIP(ip) {
			count++
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}

	if threatActiveSourcesCacheTTL > 0 {
		threatActiveSourcesCache.Set(key, count, now, threatActiveSourcesCacheTTL)
	}
	return count, nil
}

// —— 归属地富化缓存（事件列表/大屏 feed/toast/光流逐行富化共用）——

// enrichIPLocationLookup 归属地查询缝（services.LookupRegion）——var 供
// 测试观测调用次数（富化缓存钉测）。
var enrichIPLocationLookup = services.LookupRegion

// enrichLocationCacheMax 归属地富化缓存条目上限（超限整体重置——有界
// 增长优先于精确 LRU 逐出，攻击源 IP 集洪峰下内存封顶）。
const enrichLocationCacheMax = 8192

type enrichLocationCacheEntry struct {
	location   string
	generation int64
}

var enrichLocationCache = struct {
	sync.Mutex
	entries map[string]enrichLocationCacheEntry
}{entries: make(map[string]enrichLocationCacheEntry)}

// enrichIPLocation 返回 IP 的归属地展示文本；xdb 未安装或查询失败返回 ""（前端
// 隐藏归属地标签），永不报错。
//
// 大屏 feed/toast/光流逐行富化同一批攻击源 IP——xdb 查询 O(log n) 便宜，
// 成本在字符串分配与格式化（200 行/30s、1200 行/toast 量级）。进程内缓存
// 键含 xdb 代际（GeoIPDataGeneration），库热换后旧值自然失效；容量有界
// （超限整体重置，与本文件活跃源缓存同形态）。
func enrichIPLocation(ip string) string {
	if ip == "" {
		return ""
	}
	// 保留地址前置拦截:xdb 仅 IPv4(NewV4Config),IPv6 回环/链路本地等
	// 查库返回空串会裸显示 IP;私网/回环/链路本地/未指定一律「保留地址」。
	if isReservedIP(ip) {
		return "保留地址"
	}
	return enrichIPLocationCached(ip)
}

// enrichIPLocationCached 缓存版实现：键含 GeoIP 数据代际，代际变更整体失效。
func enrichIPLocationCached(ip string) string {
	gen := services.GeoIPDataGeneration()
	enrichLocationCache.Lock()
	if e, ok := enrichLocationCache.entries[ip]; ok && e.generation == gen {
		location := e.location
		enrichLocationCache.Unlock()
		return location
	}
	enrichLocationCache.Unlock()
	location := formatIP2RegionLocation(enrichIPLocationLookup(ip))
	enrichLocationCache.Lock()
	if len(enrichLocationCache.entries) >= enrichLocationCacheMax {
		enrichLocationCache.entries = make(map[string]enrichLocationCacheEntry)
	}
	enrichLocationCache.entries[ip] = enrichLocationCacheEntry{location: location, generation: gen}
	enrichLocationCache.Unlock()
	return location
}
