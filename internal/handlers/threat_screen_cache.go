package handlers

import (
	"database/sql"
	"errors"
	"maps"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/services"
)

// 威胁大屏进程内缓存与请求合并——大屏 30s（聚合）/1-2s（流量）轮询下的
// 原始表扫描与 admin 代理出口收敛。所有缓存带 TTL 且失败不缓存（降级响应
// 下一轮重试自愈）。

// ---- top_targets（被攻击目标 Top3）缓存：TTL 与大屏维度聚合同源（30s） ----

// threatTopTarget 大屏「被攻击目标 Top3」条目（JSON 契约：name/domain/value）。
type threatTopTarget struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Value  int    `json:"value"`
}

// topTargetsCacheTTL top_targets 进程内缓存有效期——同一窗口锚点内（1 分钟）
// 合并重复查询；锚点（sinceMinute）变化即换键，卡片窗口与同屏其余维度一致
// （旧键只有 hours，命中时会把 5 分钟前的旧窗口结果当当前窗口）。
// TTL 与同屏其余维度聚合缓存（threatRollupDimAggregateTTL=30s，即前端轮询
// 周期）单源对齐：此前 60s/30s 分叉会让同一响应里 Top3 与总量最多差 30s
// 新鲜度（warmer 每 60s 推进 rollup 时）。
const topTargetsCacheTTL = threatRollupDimAggregateTTL

// topTargetsCacheKey 缓存键含 *sql.DB 指针与窗口锚点 sinceMinute——
// 测试换库/换窗口即失效，不串库不串窗口；窗口每分钟前移即新键，不会返回
// 含窗口外事件的过期聚合。窗口粒度只由 sinceMinute 编码
// 此前键上还带无消费方的 hours，形成第二事实源——查询只按 sinceMinute 过滤，
// 键上的 hours 会让后续改动窗口语义时误判已有隔离）。
type topTargetsCacheKey struct {
	metrics     *sql.DB // security_event_target_rollup 所在库
	main        *sql.DB // lb_rules 所在库
	generation  string  // metrics 库代际（损坏隔离重建即失效）
	sinceMinute string
}

// topTargetsCache 键含窗口锚点（每分钟产生新键）：写入时顺带清扫过期项防
// map 无限增长（旧键 TTL 到期后不再被命中）；不得整体重置——会打掉同屏其它
// 维度仍在有效期的条目。
var topTargetsCache = newTTLCache[topTargetsCacheKey, []threatTopTarget](0)

// threatTopTargets 窗口内目标维度 rollup（security_event_target_rollup，
// rule_caddy_id 分组）计数前 3 → 主库 lb_rules 取 name/domain。
//
//	读分钟 rollup 而非原始事件表——原始表受保留期/行帽
//	  裁剪，旁路会让「TOP 被攻击站点」与同屏其余卡片窗口分裂；
//	保留/私网地址在固化期已排除（与其余维度同口径）；
//	先批量解析现存规则，再按计数顺序取前 3 条**现存**目标——已
//	  删除规则不得挤掉后续真实站点；
//	- 查询失败不缓存、错误上抛（调用方整卡 500，与现有错误口径一致）；
//	- cacheable=false（宽窗口回填未完成）时既不读也不写缓存：部分窗口的
//	  Top3 一旦落缓存，回填完成后的下一轮轮询（coverageReaches=true、
//	  stale=false，不再失效）仍会命中部分结果 ≤60s，而同响应 total/国家
//	  已是完整窗口——与 threatRollupDimAggregateQuery 的 cacheable 门同口径。
func threatTopTargets(sinceMinute string, cacheable bool) ([]threatTopTarget, error) {
	if db.MetricsDB == nil || db.DB == nil {
		return nil, errors.New("database unavailable")
	}
	key := topTargetsCacheKey{metrics: db.MetricsDB, main: db.DB, generation: db.MetricsDBGeneration(), sinceMinute: sinceMinute}
	now := time.Now()
	if cacheable {
		if targets, ok := topTargetsCache.Get(key, now); ok {
			// 拷贝返回：缓存条目不得与响应共享底层数组（消费者就地改动会污染
			// 其他请求的缓存，同型事故见安全总览聚合缓存）。
			return slices.Clone(targets), nil
		}
	}

	rows, err := db.MetricsDB.Query(`SELECT rule_caddy_id, SUM(count) FROM security_event_target_rollup WHERE minute >= ? GROUP BY rule_caddy_id`, sinceMinute)
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			rows.Close()
			return nil, err
		}
		if id == "" {
			continue
		}
		counts[id] = n
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	ids := make([]string, 0, len(counts))
	for id := range counts {
		ids = append(ids, id)
	}
	// 计数降序；同计数按 id 升序（确定性输出，大屏轮询重渲染名次不抖动）
	sort.Slice(ids, func(i, j int) bool {
		if counts[ids[i]] != counts[ids[j]] {
			return counts[ids[i]] > counts[ids[j]]
		}
		return ids[i] < ids[j]
	})

	// 按计数降序分批解析现存规则（分块 IN，避免逐目标查询的主库往返），
	// 凑满前 3 条**现存**目标即停：已删除规则的历史 caddy_id 仍留在 rollup
	// 分钟行里，全量解析会为 3 条结果做 O(distinct) 次主库往返（宽窗口/大量
	// 删除规则时被轮询放大）；分批早停把往返收敛到「命中率 × 3」量级，
	// 且顺序不变（计数降序、同计数 id 升序），结果与全量解析一致。
	type ruleInfo struct{ name, domain string }
	const chunk = 500
	const topTargetCount = 3
	existing := make(map[string]ruleInfo, chunk)
	targets := make([]threatTopTarget, 0, topTargetCount)
	for start := 0; start < len(ids) && len(targets) < topTargetCount; start += chunk {
		end := start + chunk
		if end > len(ids) {
			end = len(ids)
		}
		chunkIDs := ids[start:end]
		placeholders := ""
		args := make([]any, 0, len(chunkIDs))
		for i, id := range chunkIDs {
			if i > 0 {
				placeholders += ","
			}
			placeholders += "?"
			args = append(args, id)
		}
		rrows, rerr := db.DB.Query(`SELECT caddy_id, name, COALESCE(domain,'') FROM lb_rules WHERE caddy_id IN (`+placeholders+`)`, args...)
		if rerr != nil {
			return nil, rerr
		}
		for rrows.Next() {
			var id string
			var info ruleInfo
			if err := rrows.Scan(&id, &info.name, &info.domain); err != nil {
				rrows.Close()
				return nil, err
			}
			existing[id] = info
		}
		if err := rrows.Err(); err != nil {
			rrows.Close()
			return nil, err
		}
		rrows.Close()
		// 本批结果按全局降序逐个补足
		for _, id := range chunkIDs {
			if len(targets) == topTargetCount {
				break
			}
			info, ok := existing[id]
			if !ok {
				continue // 规则已删除：跳过，继续补足现存前 3
			}
			targets = append(targets, threatTopTarget{Name: info.name, Domain: info.domain, Value: counts[id]})
		}
	}

	if cacheable {
		topTargetsCache.Set(key, targets, now, topTargetsCacheTTL)
	}
	return targets, nil
}

// ---- traffic 代理缓存：TTL 1s + singleflight（key=admin URL）----

// threatTrafficCacheTTL traffic 快照缓存有效期（测试缝：可缩短验证过期重抓）。
var threatTrafficCacheTTL = time.Second

// threatTrafficGroup 同 admin URL 并发请求合并为一趟上游抓取（大屏多客户端
// 同开时不对 Caddy admin 放大请求）。
var threatTrafficGroup singleflight.Group

type threatTrafficCacheEntry struct {
	// data 是缓存载荷：traffic 主体为 gin.H，L4 原始快照为
	// l4TrafficRawSnapshot（键前缀区分）；取值处按键身份断言。
	data      any
	expiresAt time.Time
}

var threatTrafficCache sync.Map // key: admin URL（去尾斜杠）

var errThreatTrafficFetch = errors.New("threat traffic fetch failed")

// threatTrafficSnapshot 带缓存地取流量快照：TTL 命中直返；miss 经 singleflight
// 合并并发后抓取；抓取失败不缓存（ok=false，调用方走降级响应）。命中后并入
// L4 连接计数差分（l4 键，契约 C5；l4 抓取失败静默跳过，主体不受影响）。
func threatTrafficSnapshot(adminURL string) (gin.H, bool) {
	data, ok := threatTrafficSnapshotCached(adminURL)
	if !ok {
		return nil, false
	}
	attachL4TrafficDelta(adminURL, data)
	return data, true
}

func threatTrafficSnapshotCached(adminURL string) (gin.H, bool) {
	if v, ok := threatTrafficCache.Load(adminURL); ok {
		if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
			data, _ := entry.data.(gin.H)
			return data, true
		}
	}
	result, err, _ := threatTrafficGroup.Do(adminURL, func() (any, error) {
		// 航班内二次检查：合并进来的并发请求直接复用首个成功结果。
		if v, ok := threatTrafficCache.Load(adminURL); ok {
			if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
				return entry.data, nil
			}
		}
		data, ok := fetchThreatTrafficSnapshot(adminURL)
		if !ok {
			return nil, errThreatTrafficFetch
		}
		threatTrafficCache.Store(adminURL, threatTrafficCacheEntry{data: data, expiresAt: time.Now().Add(threatTrafficCacheTTL)})
		return data, nil
	})
	if err != nil {
		return nil, false
	}
	data, ok := result.(gin.H)
	return data, ok
}

// invalidateThreatScreenRollupCaches 清空「读 rollup 分钟行」的两份缓存。请求
// 路径刚完成同步固化后必须调用：固化会改写窗口内分钟行（最新分钟/重固窗口），
// 而聚合缓存键只含 sinceMinute/槽界/coverage、top_targets 键只含 sinceMinute
// ——任一未清都会让本次响应返回固化前的数据，直到 TTL 过期（同一屏总量/国家
// 已重算而 Top3 仍旧，展示口径分叉）。
func invalidateThreatScreenRollupCaches() {
	threatRollupDimAggregateCache.Reset()
	topTargetsCache.Reset()
}

// ---- L4（TCP）连接计数差分（契约 C3/C5）----
//
// caddy admin /lb/l4-conn-stats 的计数器随 /load 重建归零（Caddy 既有行为，
// 与 HTTP traffic-stats 同口径）。端点在 serve 时输出**差分值**：上次已消费
// 快照（按 admin URL）与本次快照逐字段相减；计数器重置（任意字段 cur<prev）
// 视为整体重置，差分取 cur（不出负数）。countries 为模块侧采样口径（默认每
// 16 连接取 1），响应以 sampled:true 披露；allowed/denied 全量差分。
//
// 抓取与差分单源在 services（FetchL4ConnStats/DeltaUint64）：指标采集任务
// （lb_l4_conn_history 30s 伴生落库）与大屏 serve 差分共用同一实现与钳制
// 语义，各自维护独立基线（l4TrafficLastServe 只是大屏 serve 侧的消费进度）。

type l4TrafficRuleCounters = services.L4TrafficRuleCounters
type l4TrafficRawSnapshot = services.L4TrafficRawSnapshot

// deltaUint64 重置钳制单源（services.DeltaUint64）。
var deltaUint64 = services.DeltaUint64

var (
	// l4TrafficDeltaMu 守护按 admin URL 的「上次已消费」状态；同一 URL 的
	// 每次 serve 各自消费增量（缓存命中同样推进）——单客户端大屏轮询语义
	// 精确，多客户端并存时各自看到子序列增量（与累计口径的既有行为同界）。
	l4TrafficDeltaMu   sync.Mutex
	l4TrafficLastServe = map[string]l4TrafficRawSnapshot{}
)

// fetchL4ConnStats 抓取一次 L4 连接计数原始快照；任何失败（不可达/非
// 200/解码失败）ok=false 并告警——超时 2s，不阻塞大屏轮询协程（与
// traffic-stats 抓取同容错：旧 Caddy 二进制无该端点=静默跳过）。
func fetchL4ConnStats(adminURL string) (l4TrafficRawSnapshot, bool) {
	snap, err := services.FetchL4ConnStats(adminURL)
	if err != nil {
		services.Logf("warn", "threat-screen l4 traffic: %v", err)
		return l4TrafficRawSnapshot{}, false
	}
	return snap, true
}

// threatL4Snapshot 带缓存地取 L4 原始快照：复用 traffic 的 1s TTL 缓存与
// singleflight（键前缀 l4|，与主体抓取同组不对 admin 放大并发）。
func threatL4Snapshot(adminURL string) (l4TrafficRawSnapshot, bool) {
	key := "l4|" + adminURL
	if v, ok := threatTrafficCache.Load(key); ok {
		if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
			snap, _ := entry.data.(l4TrafficRawSnapshot)
			return snap, true
		}
	}
	result, err, _ := threatTrafficGroup.Do(key, func() (any, error) {
		if v, ok := threatTrafficCache.Load(key); ok {
			if entry, ok := v.(threatTrafficCacheEntry); ok && time.Now().Before(entry.expiresAt) {
				return entry.data, nil
			}
		}
		snap, ok := fetchL4ConnStats(adminURL)
		if !ok {
			return nil, errThreatTrafficFetch
		}
		threatTrafficCache.Store(key, threatTrafficCacheEntry{data: snap, expiresAt: time.Now().Add(threatTrafficCacheTTL)})
		return snap, nil
	})
	if err != nil {
		return l4TrafficRawSnapshot{}, false
	}
	snap, ok := result.(l4TrafficRawSnapshot)
	return snap, ok
}

// attachL4TrafficDelta 把 L4 差分并入 traffic 响应（l4 键，契约 C5）：
//   - rules.<cid>.{allowed,denied} 全量差分（未采样）；
//   - countries.<中文名> 放行连接按国家差分（采样口径，键与主体 countries
//     同口径翻译/过滤），由前端并入 normal 弧通道；
//   - sampled:true 披露 countries 未经还原。
//
// l4 端点缺失/不可达（旧二进制）→ 空对象，traffic 主体不受影响。
func attachL4TrafficDelta(adminURL string, data gin.H) {
	snap, ok := threatL4Snapshot(adminURL)
	rulesOut := make(map[string]map[string]uint64)
	countriesOut := make(map[string]uint64)
	if ok {
		for cid, counters := range snap.Rules {
			prev := l4TrafficLastServe[adminURL].Rules[cid]
			allowed := deltaUint64(counters.AllowedTotal, prev.AllowedTotal)
			denied := deltaUint64(counters.DeniedTotal, prev.DeniedTotal)
			rulesOut[cid] = map[string]uint64{"allowed": allowed, "denied": denied}
			for country, sampled := range counters.Countries {
				if country == "" || country == "Reserved" || country == "0" {
					continue
				}
				key := geoipnames.CountryChinese(country)
				countriesOut[key] += deltaUint64(sampled, prev.Countries[country])
			}
		}
	}
	l4TrafficDeltaMu.Lock()
	l4TrafficLastServe[adminURL] = snap
	l4TrafficDeltaMu.Unlock()
	data["l4"] = gin.H{
		"rules":     rulesOut,
		"countries": countriesOut,
		"sampled":   true,
	}
}

// ---- rollup 维度聚合（大屏同屏全部维度）：SQL 侧聚合 + 30s 缓存 ----

// threatRollupDimAggregateTTL 与安全总览/规则阶段统计同族（30s）：大屏 30s
// 轮询在同一窗口锚点内复用一次聚合，宽窗口（hours 上限 720）不再每请求全量
// 拉行。
const threatRollupDimAggregateTTL = 30 * time.Second

// threatRollupDimAggregate 是 rollup 窗口的聚合结果（总量/拦截/国家/省/攻击族/
// 规则/按槽分钟总量）。map 只读共享给同屏各卡片（topN 与 JSON 序列化均只读）。
type threatRollupDimAggregate struct {
	total, blocked                                      int
	countries, chinaProvinces, familyCounts, ruleCounts map[string]int
	// bucketTotals 与查询键里的槽界一一对应（长度=槽数）。
	bucketTotals []int
}

type threatRollupDimAggregateKey struct {
	metrics    *sql.DB
	generation string // metrics 库代际（损坏隔离重建即失效）
	// sinceMinute 是窗口下界（分钟锚点）：每分钟前移即换键。
	sinceMinute string
	// bucketLayout 是槽界签名（首槽 UnixNano + 槽数），槽界在入库前已按分钟
	// 锚定（threatRollupMinuteAnchoredBuckets）——同分钟内两次请求同键，跨
	// 分钟/槽数变化即失效，保证落桶与缓存内容一一对应。
	bucketLayout string
	// coverage 是固化覆盖水位（coveredFrom）：宽窗口头部回填推进会使同一
	// 窗口的聚合内容变化——不参与键会把回填中的空/少计结果锁在 30s 缓存里
	// （大屏看板与回填进度自相矛盾）。
	coverage string
}

// threatRollupDimAggregateCache 键含分钟锚点/槽界/覆盖水位——写入时顺带清扫
// 过期项防 map 无限增长；不得整体重置（同屏其它维度条目仍在有效期）。
var threatRollupDimAggregateCache = newTTLCache[threatRollupDimAggregateKey, threatRollupDimAggregate](0)

// cloneThreatRollupDimAggregate 返回聚合的深拷贝（4 个 map 与 bucketTotals
// 切片各自独立）——缓存命中路径的返回值契约：调用方改写不得污染缓存条目。
func cloneThreatRollupDimAggregate(in threatRollupDimAggregate) threatRollupDimAggregate {
	out := in
	out.countries = maps.Clone(in.countries)
	out.chinaProvinces = maps.Clone(in.chinaProvinces)
	out.familyCounts = maps.Clone(in.familyCounts)
	out.ruleCounts = maps.Clone(in.ruleCounts)
	out.bucketTotals = slices.Clone(in.bucketTotals)
	return out
}

// threatRollupBucketLayout 槽界签名（空槽集=空串）。
func threatRollupBucketLayout(bucketStarts []time.Time) string {
	if len(bucketStarts) == 0 {
		return ""
	}
	return strconv.FormatInt(bucketStarts[0].UnixNano(), 10) + "|" + strconv.Itoa(len(bucketStarts))
}

// threatRollupMinuteAnchoredBuckets 把槽界归一化到分钟（保留长度与顺序）：
// 槽界由纳秒精度时钟推导，不归一则缓存键逐请求不同（永不命中）且同一分钟
// 内两次请求的落桶边界漂移。分钟锚定后查询分桶与缓存键同源。
func threatRollupMinuteAnchoredBuckets(bucketStarts []time.Time) []time.Time {
	if len(bucketStarts) == 0 {
		return bucketStarts
	}
	anchored := make([]time.Time, len(bucketStarts))
	for i, start := range bucketStarts {
		anchored[i] = start.Truncate(time.Minute)
	}
	return anchored
}

// threatRollupDimAggregateQuery 聚合窗口内 rollup：
//   - 维度聚合走 SQL GROUP BY——传输行数从「分钟数 × 维度基数」压到「维度
//     组合数」（30 天 × 每分钟数十~数百行 → 数百~数千行），Go 侧不再逐行 Scan；
//   - 按槽分钟总量另用 GROUP BY minute（≤43,200 行，与维度无关），槽界归属
//     仍在 Go 侧按真实时刻二分（槽界携带配置时区，DST 两侧各自正确）；
//   - 失败不缓存、错误上抛（调用方整卡 500，与现有错误口径一致）。
//
// cacheable=false（窗口头部回填未完成）时既不读也不写缓存：不完整的聚合
// 被缓存会让同一窗口在 30s 内锁死少计结果，与回填进度自相矛盾。
func threatRollupDimAggregateQuery(database *sql.DB, sinceMinute string, bucketStarts []time.Time, coverage string, cacheable bool) (threatRollupDimAggregate, error) {
	agg := threatRollupDimAggregate{
		countries:      map[string]int{},
		chinaProvinces: map[string]int{},
		familyCounts:   map[string]int{},
		ruleCounts:     map[string]int{},
		bucketTotals:   make([]int, len(bucketStarts)),
	}
	if database == nil {
		return agg, errors.New("database unavailable")
	}
	// 槽界归一化到分钟——槽界由纳秒精度请求时刻推导，逐请求的秒级差异会同时
	// 漂移聚合分桶与缓存键（键含纳秒级槽界 → 30s 缓存永不命中，与「同屏
	// 轮询复用一次聚合」的设计承诺相反）。按分钟锚定后同一分钟内两次轮询
	// 命中同一键且分桶与键同源；槽标签为 HH:MM/MM-DD，分钟锚定不改变可见语义。
	bucketStarts = threatRollupMinuteAnchoredBuckets(bucketStarts)
	key := threatRollupDimAggregateKey{
		metrics:      database,
		generation:   db.MetricsDBGeneration(),
		sinceMinute:  sinceMinute,
		bucketLayout: threatRollupBucketLayout(bucketStarts),
		coverage:     coverage,
	}
	now := time.Now()
	if cacheable {
		if cached, ok := threatRollupDimAggregateCache.Get(key, now); ok {
			// 命中路径返回深拷贝：4 个 map 与 bucketTotals 切片若与缓存条目
			// 共享底层数据，调用方就地改写会污染同窗后续命中（同型事故见
			// 安全总览聚合缓存）；与同文件 threatTopTargets 的 slices.Clone
			// 防护同口径。
			return cloneThreatRollupDimAggregate(cached), nil
		}
	}

	rows, err := database.Query(`SELECT COALESCE(country,''), COALESCE(province,''), COALESCE(family,''), COALESCE(rule,''), COALESCE(action,''), SUM(count)
		FROM security_event_rollup WHERE minute >= ? AND `+services.AttackEventSQLPredicate("rule", "action")+` GROUP BY 1,2,3,4,5`, sinceMinute)
	if err != nil {
		return agg, err
	}
	for rows.Next() {
		var country, province, family, rule, action string
		var count int
		if err := rows.Scan(&country, &province, &family, &rule, &action, &count); err != nil {
			rows.Close()
			return agg, err
		}
		agg.total += count
		// action 取值与 queryThreatRecentBlocked 同单一事实源
		// （threatRollupBlockedAction），两侧口径漂移由同一钉测捕获。
		if action == threatRollupBlockedAction {
			agg.blocked += count
		}
		if country != "" {
			agg.countries[country] += count
		}
		if province != "" {
			agg.chinaProvinces[province] += count
		}
		agg.familyCounts[family] += count
		if rule != "" {
			agg.ruleCounts[rule] += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return agg, err
	}
	rows.Close()

	if len(bucketStarts) > 0 {
		minuteRows, merr := database.Query(`SELECT minute, SUM(count) FROM security_event_rollup WHERE minute >= ? AND `+services.AttackEventSQLPredicate("rule", "action")+` GROUP BY minute`, sinceMinute)
		if merr != nil {
			return agg, merr
		}
		for minuteRows.Next() {
			var minute string
			var count int
			if serr := minuteRows.Scan(&minute, &count); serr != nil {
				minuteRows.Close()
				return agg, serr
			}
			// 滑动窗口落桶：rollup 分钟串为 UTC，按槽界真实时刻二分定位。
			if mt, perr := time.ParseInLocation("2006-01-02 15:04", minute, time.UTC); perr == nil {
				agg.bucketTotals[threatBucketIndex(mt, bucketStarts)] += count
			}
		}
		if err := minuteRows.Err(); err != nil {
			minuteRows.Close()
			return agg, err
		}
		minuteRows.Close()
	}

	if !cacheable {
		return agg, nil
	}
	threatRollupDimAggregateCache.Set(key, agg, now, threatRollupDimAggregateTTL)
	return agg, nil
}
