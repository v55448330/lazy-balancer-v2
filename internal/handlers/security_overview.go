package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetSecurityRateLimitBlocks 返回各站点被限流（HTTP 429）拦截的累计次数，数据
// 来自 Caddy admin /metrics。注意口径：仅按 code=429 过滤、含上游自返 429；
// 计数自最近一次 Caddy 配置重载以来累计（实证：/load
// 重建 metrics registry 即归零；进程重启同），非进程启动口径（前端按"累计拦截"标注）。
// 抓取失败返回 500：降级为空列表会让「Caddy 指标不可达」与「暂无限流拦截」
// 不可区分，面板错误态需可达。
func (h *Handlers) GetSecurityRateLimitBlocks(c *gin.Context) {
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	if err != nil {
		services.Logf("error", "Scrape rate-limit blocks failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
		return
	}
	var total float64
	for _, block := range blocks {
		total += block.Count
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"total": total,
		"hosts": blocks,
	}})
}

// securityRuleHostMatches 判断指标 host 是否属于规则域名：精确匹配，或规则为
// *.example.com 通配时匹配其**一级**子域（Caddy 通配域不覆盖裸域，与渲染语义
// 一致；不展开通配会让泛域名规则的限流 chip 恒 0）。
//
// 单段语义以 Caddy host matcher 为准（modules/caddyhttp/matchers.go
// MatchHost.MatchWithError：通配模式按 "." 切分后要求 len(patternParts) ==
// len(incomingParts)，即 *.example.com 不匹配 a.b.example.com）。复用
// tlsWildcardMatch 保持单一实现——此前用 HasSuffix 会把多级子域的 429 计数
// 并入通配规则（chip 偏高，展示口径失真）。
func securityRuleHostMatches(ruleHost, metricHost string) bool {
	if ruleHost == "" || metricHost == "" {
		return false
	}
	// host matcher 比较大小写不敏感；metrics 标签恒小写，规则域按输入保留。
	return tlsWildcardMatch(strings.ToLower(ruleHost), strings.ToLower(metricHost))
}

// GetRuleStageStats 返回单规则的三阶段计数（流程抽屉计数 chip）：
//   - stage1_blocked_24h / stage3_blocked_24h：近 24h 该规则 blocked 安全事件
//     按 rule_triggered id 形状分桶——阶段 1（IP 访问控制+威胁情报库+地域拦截预检）=
//     {2,4,7,8,14} ∪ [800000,900000)，其余（CRS 9xxxxx/自定义/合成 id）归阶段 3；
//   - ratelimit_blocks_reload：Caddy /metrics 429 计数（重载口径，自最近一次
//     配置重载以来累计）按规则 domain + 监听端口映射回规则求和。端口维度不可
//     省：同域多端口部署下按 host 求和会把各端口规则的计数累加到每条规则上。
//     域名匹配支持 *.example.com 通配（匹配其子域）；CNAME 等不可见的 host
//     映射仍显示 0 而非报错（已声明口径，不新造时序）。
//
// 429 抓取失败返回 500（与 GetSecurityRateLimitBlocks 同口径：指标不可达与
// 暂无限流拦截必须可区分，前端 chip 显示「暂无计数」）。
func (h *Handlers) GetRuleStageStats(c *gin.Context) {
	ruleCaddyID := c.Param("caddy_id")
	// 规则存在性判定先于 MetricsDB 分支——零值面板与成功路径同口径
	// （未知规则一律 404，不得因 metrics 未装配而对任意 caddy_id 返回 200）。
	var domain string
	var listenPort int
	if err := db.DB.QueryRow(`SELECT COALESCE(domain,''), COALESCE(listen_port,0) FROM lb_rules WHERE caddy_id=?`, ruleCaddyID).Scan(&domain, &listenPort); err != nil {
		// ErrNoRows（规则不存在）与真实 DB 故障分判——前者归 404
		// not_found，后者保持 500 且 message 归位查询失败（不再借「规则不存在」
		// 文案）。前端对非 200 一律 stats=null，404 化不改变前端表现。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		services.Logf("error", "stage-stats read rule domain failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：与成功路径同键的零统计而非 panic。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
			"stage1_blocked_24h":      0,
			"stage3_blocked_24h":      0,
			"stage_unattributed_24h":  0,
			"ratelimit_blocks_reload": 0.0,
			"precheck_avg_us":         0.0,
			"precheck_samples":        0,
			"waf_avg_us":              0.0,
			"waf_samples":             0,
		}})
		return
	}
	// 24h 分桶 + 分段耗时经 30s 缓存（规则流程抽屉按秒级轮询/多页签并存，
	// 单规则 24h 全窗口两次聚合在高事件量下达数百 ms）——与策略 24h 计数
	// 缓存（security_policy_counts_cache.go）同范式；失败不缓存。
	stats, err := loadRuleStageStats(db.MetricsDB, ruleCaddyID, time.Now())
	if err != nil {
		services.Logf("error", "stage-stats query failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "阶段统计查询失败"})
		return
	}

	var ratelimit float64
	if domain != "" {
		// 端口维度：规则只认自己监听端口的 server 分组（http_<listen_port>）。
		// 同域多端口部署下按 host 求和会把 80/443 两条规则的计数累加到每条
		// 规则上（chip 被放大成两条之和）。
		blocks, err := services.ScrapeRateLimitBlocksByHostServer(h.cfg.CaddyMetricsURL)
		if err != nil {
			services.Logf("error", "stage-stats scrape rate-limit blocks failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "限流拦截数据不可用"})
			return
		}
		serverName := fmt.Sprintf("http_%d", listenPort)
		ruleHosts := make([]string, 0, 2)
		for _, host := range strings.Split(domain, ",") {
			if trimmed := services.NormalizeMetricsHost(host); trimmed != "" {
				ruleHosts = append(ruleHosts, trimmed)
			}
		}
		for _, block := range blocks {
			if block.Server != serverName {
				continue
			}
			host := services.NormalizeMetricsHost(block.Host)
			for _, ruleHost := range ruleHosts {
				if securityRuleHostMatches(ruleHost, host) {
					ratelimit += block.Count
					break
				}
			}
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stage1_blocked_24h":      stats.stage1,
		"stage3_blocked_24h":      stats.stage3,
		"stage_unattributed_24h":  stats.unattributed,
		"ratelimit_blocks_reload": ratelimit,
		"precheck_avg_us":         stats.preAvg,
		"precheck_samples":        stats.preCnt,
		"waf_avg_us":              stats.wafAvg,
		"waf_samples":             stats.wafCnt,
	}})
}

// ruleStageStatsSnapshot 是单规则 24h 阶段计数 + 分段耗时的缓存单元。
type ruleStageStatsSnapshot struct {
	stage1, stage3, unattributed int
	preAvg, wafAvg               float64
	preCnt, wafCnt               int
}

// ruleStageStatsCacheTTL 缓存有效期（测试可缩短）。
var ruleStageStatsCacheTTL = 30 * time.Second

type ruleStageStatsCacheKey struct {
	metrics *sql.DB
	rule    string
	anchor  string // 24h 窗口锚点（UTC 分钟串）
}

type ruleStageStatsCacheEntry struct {
	snapshot  ruleStageStatsSnapshot
	expiresAt time.Time
}

var (
	ruleStageStatsMu    sync.Mutex
	ruleStageStatsCache = map[ruleStageStatsCacheKey]ruleStageStatsCacheEntry{}
)

// resetRuleStageStatsCacheForTest 测试缝：清空缓存（生产不调用）。
func resetRuleStageStatsCacheForTest() {
	ruleStageStatsMu.Lock()
	ruleStageStatsCache = map[ruleStageStatsCacheKey]ruleStageStatsCacheEntry{}
	ruleStageStatsMu.Unlock()
}

// loadRuleStageStats 返回单规则近 24h 的阶段分桶计数与分段耗时（命中缓存时
// 零查询）。分桶口径：阶段 1={2,4,7,8,14}∪[800000,900000) 预检段（
// IsStage1PrecheckID 单一事实源），429 由 ratelimit_blocks_reload 单独供给
// 阶段 2 chip（不计入阶段 3），非数字 triggered 归「未归因」独立桶（与
// categorizeAttack 的「其他/未归因」口径一致），其余归阶段 3。
// 分桶查询失败显式上抛（不缓存）；耗时为增强信息——失败留 warn 按零值并入
// 快照（响应仍返回其余已取数据，与缓存前口径一致）。
func loadRuleStageStats(metricsDB *sql.DB, ruleCaddyID string, now time.Time) (ruleStageStatsSnapshot, error) {
	key := ruleStageStatsCacheKey{metrics: metricsDB, rule: ruleCaddyID, anchor: now.UTC().Format("2006-01-02 15:04")}
	if ruleStageStatsCacheTTL > 0 {
		ruleStageStatsMu.Lock()
		if entry, ok := ruleStageStatsCache[key]; ok && now.Before(entry.expiresAt) {
			snapshot := entry.snapshot
			ruleStageStatsMu.Unlock()
			return snapshot, nil
		}
		ruleStageStatsMu.Unlock()
	}

	var snapshot ruleStageStatsSnapshot
	// rule_triggered 列可空（schema 无 NOT NULL，带外/旧快照/集群写入可留 NULL）：
	// 裸列 Scan 到 string 会让整个端点 500，而事件列表/feed/rollup 同列均已
	// COALESCE——此处分组与投影同口径收敛 NULL 为空串（归「未归因」桶）。
	rows, err := metricsDB.Query(`SELECT COALESCE(rule_triggered,''), COUNT(*) FROM security_events WHERE rule_caddy_id=? AND action='blocked' AND event_time >= datetime('now','-1 day') GROUP BY COALESCE(rule_triggered,'')`, ruleCaddyID)
	if err != nil {
		return snapshot, err
	}
	for rows.Next() {
		var triggered string
		var count int
		if err := rows.Scan(&triggered, &count); err != nil {
			rows.Close()
			return snapshot, err
		}
		n, convErr := strconv.Atoi(triggered)
		switch {
		case triggered == "429":
			continue
		case convErr == nil && services.IsStage1PrecheckID(n):
			snapshot.stage1 += count
		case convErr != nil:
			snapshot.unattributed += count
		default:
			snapshot.stage3 += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return snapshot, err
	}
	rows.Close()

	preAvg, preCnt, wafAvg, wafCnt, terr := queryRuleStageTimings(metricsDB, ruleCaddyID)
	if terr != nil {
		services.Logf("warn", "stage-stats timing query failed for %s: %v", ruleCaddyID, terr)
	} else {
		snapshot.preAvg, snapshot.preCnt, snapshot.wafAvg, snapshot.wafCnt = preAvg, preCnt, wafAvg, wafCnt
	}

	if ruleStageStatsCacheTTL > 0 {
		ruleStageStatsMu.Lock()
		// 键含分钟锚点+规则身份：条目数受 TTL 与活跃规则数约束；超界重建
		// 防长尾规则集膨胀（与策略计数缓存同范式）。
		if len(ruleStageStatsCache) > 256 {
			ruleStageStatsCache = map[ruleStageStatsCacheKey]ruleStageStatsCacheEntry{}
		}
		ruleStageStatsCache[key] = ruleStageStatsCacheEntry{snapshot: snapshot, expiresAt: now.Add(ruleStageStatsCacheTTL)}
		ruleStageStatsMu.Unlock()
	}
	return snapshot, nil
}

// queryRuleStageTimings 分段平均处理耗时聚合（预检段 / WAF 段）。
// SUM 在空窗口上返回 SQL NULL——计数列必须 COALESCE，否则正常空窗口
// 会被扫描失败误报成「查询故障」（安静规则每次轮询刷一条 warn）。
// AVG 在空窗口本就是 NULL，扫进 sql.NullFloat64 后归零。
// 句柄必须由调用方传入（与分桶查询同源）：此前用包级 db.MetricsDB，缓存键
// 却含入参句柄——换库/测试注入时会出现「分桶来自 A、耗时来自 B」，且错误内容
// 以 A 为键缓存 30s（缓存键与数据源不对称）。
func queryRuleStageTimings(metricsDB *sql.DB, ruleCaddyID string) (preAvg float64, preCnt int, wafAvg float64, wafCnt int, err error) {
	stageTimingSQL := fmt.Sprintf(`SELECT
		AVG(CASE WHEN precheck_us > 0 THEN precheck_us END),
		COALESCE(SUM(CASE WHEN precheck_us > 0 THEN 1 ELSE 0 END),0),
		AVG(CASE WHEN duration_us > 0 THEN CASE WHEN %s THEN NULL ELSE duration_us END END),
		COALESCE(SUM(CASE WHEN duration_us > 0 THEN CASE WHEN %s THEN 0 ELSE 1 END ELSE 0 END),0)
		FROM security_events
		WHERE rule_caddy_id=? AND event_time >= datetime('now','-1 day')`, services.Stage1PrecheckSegmentSQL, services.Stage1PrecheckSegmentSQL)
	var preAverage, wafAverage sql.NullFloat64
	if err = metricsDB.QueryRow(stageTimingSQL, ruleCaddyID).Scan(&preAverage, &preCnt, &wafAverage, &wafCnt); err != nil {
		return 0, 0, 0, 0, err
	}
	if preAverage.Valid {
		preAvg = preAverage.Float64
	}
	if wafAverage.Valid {
		wafAvg = wafAverage.Float64
	}
	return preAvg, preCnt, wafAvg, wafCnt, nil
}

// 安全总览的近 7 天聚合（趋势/Top10 IP/攻击族）此前
// 每请求执行 4 条无缓存的大范围扫描（趋势、Top IP、Top IP 攻击族、攻击类型），
// 100/s 攻击态 7 天可达数千万行时每 30s 轮询多趟全窗口聚合。改为 30s 进程内
// 缓存（键含指标库句柄/日界/时区偏移——换库/跨日/改时区即失效；失败不缓存）。
const securityOverviewAggCacheTTL = 30 * time.Second

type securityOverviewAggregates struct {
	trend            []models.SecurityTrendPoint
	topIPs           []models.SecurityTopIP
	attackTypes      []models.SecurityAttackType
	attackTypesStage []models.SecurityAttackType
}

type securityOverviewAggCacheKey struct {
	metrics    *sql.DB
	todayStart string
	// tzName 是时区身份（loc.String()），不是瞬时 UTC 偏移：数据按 today 的
	// location 逐日构造日桶，仅用偏移做键会让「同偏移不同 DST 规则」的两个
	// 时区（或切换后偏移恰好相同的时区）在 TTL 内共用另一时区的日桶。
	tzName string
}

type securityOverviewAggCacheEntry struct {
	data      securityOverviewAggregates
	expiresAt time.Time
}

var (
	securityOverviewAggCacheMu sync.Mutex
	securityOverviewAggCache   = map[securityOverviewAggCacheKey]securityOverviewAggCacheEntry{}
)

// resetSecurityOverviewAggCacheForTest 测试缝：清空总览聚合缓存（生产不调用）。
func resetSecurityOverviewAggCacheForTest() {
	securityOverviewAggCacheMu.Lock()
	securityOverviewAggCache = map[securityOverviewAggCacheKey]securityOverviewAggCacheEntry{}
	securityOverviewAggCacheMu.Unlock()
}

// securityOverviewTodayCounts 今日拦截/检测计数单源：优先读分钟 rollup
// （与威胁大屏同源，与原始表规模解耦——行帽触顶时原始表只剩最近若干
// 分钟，直算会静默少计且面板照常渲染）。rollup 覆盖水位未回推到今日
// 起点（启动回填中）或固化陈旧（warmer 停转）时回退原始表直算。
// fromRollup 披露口径分叉：rollup 固化时排除私网/保留地址（大屏口径），
// 原始表回退含私网（旧口径）。
// 时间口径（勿再按「部分分钟」重报）：warmer 每轮恒固化 currentMinute 的
// 部分分钟，本查询因此包含「当前分钟截至最近一次固化」的事件（滞后 ≤60s，
// 随轮询增量变化）；事件列表/总览/大屏三面同一口径。recent_rate 例外——
// 它用固定 5 分钟除数，必须只取完整分钟（上界排除当前分钟），否则速率随
// 秒数漂移。UI 文案按「含当前分钟（截至最近固化）」描述，不要再声称
// 「当前未满分钟不计入」。
func securityOverviewTodayCounts(database *sql.DB, todayStart time.Time, now time.Time) (blocked, detected int, fromRollup bool, err error) {
	todayStartUTC := todayStart.UTC()
	lastComplete := now.UTC().Add(-time.Minute).Truncate(time.Minute)
	coveredFrom, okCovered, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil {
		return 0, 0, false, err
	}
	watermark, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil {
		return 0, 0, false, err
	}
	usable := okCovered && okFixed && !coveredFrom.After(todayStartUTC) &&
		lastComplete.Sub(watermark) <= threatRollupStaleAfter
	if usable {
		rows, qerr := database.Query(`SELECT action, COALESCE(SUM(count),0) FROM security_event_rollup
			WHERE minute >= ? AND action IN ('blocked','logged') AND `+services.AttackEventSQLPredicate("rule", "action")+` GROUP BY action`, todayStartUTC.Format("2006-01-02 15:04"))
		if qerr != nil {
			return 0, 0, false, qerr
		}
		defer rows.Close()
		for rows.Next() {
			var action string
			var count int
			if err := rows.Scan(&action, &count); err != nil {
				return 0, 0, false, err
			}
			if action == "blocked" {
				blocked = count
			} else {
				detected = count
			}
		}
		if err := rows.Err(); err != nil {
			return 0, 0, false, err
		}
		return blocked, detected, true, nil
	}
	// 回退：原始表直算（含私网/保留地址，includes_reserved 披露）。
	// 两条语句与 rollup 分支同口径套攻击面谓词——当前谓词只排除
	// 「logged 且爬虫放行族」，对 blocked 恒真故无行为差异；两分支一旦分叉，
	// 同一卡片会在 rollup/回退切换点（覆盖水位决定）给出不同数字且极难复现。
	todayStartText := todayStartUTC.Format("2006-01-02 15:04:05")
	if err := database.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='blocked' AND event_time >= ? AND "+services.AttackEventSQLPredicate("rule_triggered", "action"), todayStartText).Scan(&blocked); err != nil {
		return 0, 0, false, err
	}
	if err := database.QueryRow("SELECT COUNT(*) FROM security_events WHERE action='logged' AND event_time >= ? AND "+services.AttackEventSQLPredicate("rule_triggered", "action"), todayStartText).Scan(&detected); err != nil {
		return 0, 0, false, err
	}
	return blocked, detected, false, nil
}

// threatRawCoverageStart 返回原始事件表最早事件时间（空表=""）。总览与
// 威胁大屏共用同一覆盖事实，避免保留期/行帽裁剪后的披露口径分叉。
func threatRawCoverageStart(database *sql.DB) (string, error) {
	var earliest string
	err := database.QueryRow(`SELECT COALESCE(MIN(event_time),'') FROM security_events`).Scan(&earliest)
	return earliest, err
}

// securityOverviewResponse 在不改变公共 SecurityOverview 模型的前提下，为
// 原始表直读的近 7 天卡片附带覆盖披露；nil metrics 的零面板也保持同键。
// IncludesReserved 口径披露：trend/top_ips/attack_types 总量不排除私网/保留
// 地址事件；today_blocked/today_detected 走 rollup 时与大屏同口径排除私网
// （includes_reserved=false），回退原始表直算时含私网（=true）——前端
// tooltip 按该字段切换两种口径文案消歧。
type securityOverviewResponse struct {
	models.SecurityOverview
	RawCoverageFrom string `json:"raw_coverage_from"`
	// BackfillIncomplete 是历史字段名，语义 =「原始表最早事件晚于 7 天窗口
	// 起点 → 更早区间不可重建」。与威胁大屏的同名字段（rollup 覆盖未完成）
	// 同名异义——保留仅为前端兼容，新消费者一律读 RawCoverageLimited。
	BackfillIncomplete bool `json:"backfill_incomplete"`
	// RawCoverageLimited 与威胁大屏同名同义（原始表保留期限制导致明细不全，
	// 与 rollup 回填状态无关），总览/大屏跨端点口径统一。
	RawCoverageLimited bool `json:"raw_coverage_limited"`
	IncludesReserved   bool `json:"includes_reserved"`
	// Ingestion 与事件列表同源（services 快照）：总览/事件页必须看到同一
	// 采集健康位（任务已停/连续失败/审计写侧降级），不得各自推断。
	Ingestion services.SecurityEventsIngestionStatus `json:"ingestion"`
}

// loadSecurityOverviewAggregates 计算（或命中缓存）近 7 天聚合。错误不缓存、
// 由调用方聚合成 500（与既有「任一查询失败显式报错」口径一致）。
// tzName 仅用于缓存键区分时区身份（loc.String()）；窗口/日桶一律由 today
// 携带的时区逐日构造（DST 正确），不把单一偏移套到整周 SQL date() 上。
func loadSecurityOverviewAggregates(metricsDB *sql.DB, today time.Time, todayStartUTC, tzName string) (securityOverviewAggregates, error) {
	key := securityOverviewAggCacheKey{metrics: metricsDB, todayStart: todayStartUTC, tzName: tzName}
	now := time.Now()
	securityOverviewAggCacheMu.Lock()
	if entry, ok := securityOverviewAggCache[key]; ok && now.Before(entry.expiresAt) {
		// 深拷贝：四个切片若与缓存条目共享底层数组，任一消费者就地变更
		// （sort/截断/改元素）都会污染其他请求的 30s 缓存（同型事故：健康
		// 缓存的「共享同一克隆」）。
		data := cloneSecurityOverviewAggregates(entry.data)
		securityOverviewAggCacheMu.Unlock()
		return data, nil
	}
	securityOverviewAggCacheMu.Unlock()

	var firstErr error
	track := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// 趋势日桶必须用**逐日本地边界**，不得用单一当前时区偏移——
	// DST 周界（如 America/New_York 3 月/11 月切换）单偏移会让切换前一日的
	// 边界错 1h，事件跨到相邻日桶（默认 Asia/Shanghai 无 DST，故此前未暴露）。
	// 边界按 today 携带的配置时区逐日构造（today 由调用方 time.Now().In(loc)
	// 传入），窗口下界同步用 dayStarts[0]，其余 7 天聚合与趋势同窗口。
	const eventTimeLayout = "2006-01-02 15:04:05"
	dayStarts := make([]time.Time, 8)
	for i := range dayStarts {
		d := today.AddDate(0, 0, i-6)
		dayStarts[i] = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, today.Location())
	}
	windowStartUTC := dayStarts[0].UTC().Format(eventTimeLayout)
	trend := make([]models.SecurityTrendPoint, 0, 7)
	for i := range 7 {
		point := models.SecurityTrendPoint{Date: dayStarts[i].In(today.Location()).Format("2006-01-02")}
		err := metricsDB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END),0)
			FROM security_events WHERE event_time >= ? AND event_time < ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action"),
			dayStarts[i].UTC().Format(eventTimeLayout), dayStarts[i+1].UTC().Format(eventTimeLayout)).
			Scan(&point.Blocked, &point.Detected)
		track(err)
		trend = append(trend, point)
	}

	type topIPRow struct {
		ip                  string
		blocked, detected   int
		recent10m, recent1h int
		lastTime            string
	}
	var topRows []topIPRow
	nowUTC := time.Now().UTC()
	recent10m := nowUTC.Add(-10 * time.Minute).Format(eventTimeLayout)
	recent1h := nowUTC.Add(-time.Hour).Format(eventTimeLayout)
	ipRows, err := metricsDB.Query(`SELECT client_ip,
		SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b,
		SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l,
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END) as recent_10m,
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END) as recent_1h,
		MAX(event_time) as last_time
		FROM security_events WHERE event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip ORDER BY b + l DESC LIMIT 10`, recent10m, recent1h, windowStartUTC)
	track(err)
	for ipRows != nil && ipRows.Next() {
		var row topIPRow
		track(ipRows.Scan(&row.ip, &row.blocked, &row.detected, &row.recent10m, &row.recent1h, &row.lastTime))
		topRows = append(topRows, row)
	}
	if ipRows != nil {
		track(ipRows.Err())
		ipRows.Close()
	}
	familyCountsByIP := map[string]map[string]int{}
	stageFamilyCountsByIP := map[string]map[string]int{}
	if len(topRows) > 0 {
		placeholders := make([]string, len(topRows))
		famArgs := make([]interface{}, 0, len(topRows)+1)
		famArgs = append(famArgs, windowStartUTC)
		for i, row := range topRows {
			placeholders[i] = "?"
			famArgs = append(famArgs, row.ip)
		}
		famRows, ferr := metricsDB.Query(fmt.Sprintf(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= ? AND client_ip IN (%s) AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip, rule_triggered, rule_msg`, strings.Join(placeholders, ",")), famArgs...)
		track(ferr)
		for famRows != nil && famRows.Next() {
			var ip, ruleTriggered, ruleMsg string
			var cnt int
			track(famRows.Scan(&ip, &ruleTriggered, &ruleMsg, &cnt))
			counts := familyCountsByIP[ip]
			if counts == nil {
				counts = map[string]int{}
				familyCountsByIP[ip] = counts
			}
			counts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
			stageCounts := stageFamilyCountsByIP[ip]
			if stageCounts == nil {
				stageCounts = map[string]int{}
				stageFamilyCountsByIP[ip] = stageCounts
			}
			stageCounts[stageCategorizeAttack(ruleTriggered, ruleMsg)] += cnt
		}
		if famRows != nil {
			track(famRows.Err())
			famRows.Close()
		}
	}
	topIPs := make([]models.SecurityTopIP, 0, len(topRows))
	for _, row := range topRows {
		topIPs = append(topIPs, models.SecurityTopIP{
			IP:              row.ip,
			IPLocation:      enrichIPLocation(row.ip),
			Blocked:         row.blocked,
			Detected:        row.detected,
			Recent10m:       row.recent10m,
			Recent1h:        row.recent1h,
			LastTime:        row.lastTime,
			AttackType:      joinDistinctFamilies(familyCountsByIP[row.ip]),
			AttackTypeStage: joinDistinctFamilies(stageFamilyCountsByIP[row.ip]),
		})
	}

	typeRows, err := metricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY rule_triggered, rule_msg`, windowStartUTC)
	track(err)
	familyCounts := map[string]int{}
	stageCounts := map[string]int{}
	for typeRows != nil && typeRows.Next() {
		var ruleTriggered, ruleMsg string
		var cnt int
		track(typeRows.Scan(&ruleTriggered, &ruleMsg, &cnt))
		familyCounts[categorizeAttack(ruleTriggered, ruleMsg)] += cnt
		stageCounts[stageCategorizeAttack(ruleTriggered, ruleMsg)] += cnt
	}
	if typeRows != nil {
		track(typeRows.Err())
		typeRows.Close()
	}
	attackTypesStage := make([]models.SecurityAttackType, 0, len(stageCounts))
	for name, value := range stageCounts {
		attackTypesStage = append(attackTypesStage, models.SecurityAttackType{Name: name, Value: value})
	}
	// 值相等时按名称升序 tiebreak（map 迭代序随机，防轮询抖动）。
	sort.Slice(attackTypesStage, func(i, j int) bool {
		if attackTypesStage[i].Value != attackTypesStage[j].Value {
			return attackTypesStage[i].Value > attackTypesStage[j].Value
		}
		return attackTypesStage[i].Name < attackTypesStage[j].Name
	})

	attackTypes := make([]models.SecurityAttackType, 0, len(familyCounts))
	for name, value := range familyCounts {
		attackTypes = append(attackTypes, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(attackTypes, func(i, j int) bool {
		if attackTypes[i].Value != attackTypes[j].Value {
			return attackTypes[i].Value > attackTypes[j].Value
		}
		return attackTypes[i].Name < attackTypes[j].Name
	})
	if len(attackTypes) > 10 {
		attackTypes = attackTypes[:10]
	}

	data := securityOverviewAggregates{trend: trend, topIPs: topIPs, attackTypes: attackTypes, attackTypesStage: attackTypesStage}
	if firstErr != nil {
		return data, firstErr
	}
	securityOverviewAggCacheMu.Lock()
	// 过期项顺带清理（键空间随时区/日界变化，且测试换库会产生旧键）。
	for k, entry := range securityOverviewAggCache {
		if !now.Before(entry.expiresAt) {
			delete(securityOverviewAggCache, k)
		}
	}
	securityOverviewAggCache[key] = securityOverviewAggCacheEntry{data: cloneSecurityOverviewAggregates(data), expiresAt: now.Add(securityOverviewAggCacheTTL)}
	securityOverviewAggCacheMu.Unlock()
	return data, nil
}

// cloneSecurityOverviewAggregates 复制四组切片（元素为值类型，浅复制切片即
// 深拷贝）——缓存读写两侧都必须用副本，缓存条目与响应构造不得共享底层数组。
func cloneSecurityOverviewAggregates(in securityOverviewAggregates) securityOverviewAggregates {
	return securityOverviewAggregates{
		trend:            slices.Clone(in.trend),
		topIPs:           slices.Clone(in.topIPs),
		attackTypes:      slices.Clone(in.attackTypes),
		attackTypesStage: slices.Clone(in.attackTypesStage),
	}
}
