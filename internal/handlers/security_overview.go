package handlers

import (
	"database/sql"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/sync/singleflight"

	"lazy-balancer-v2/internal/apimsg"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// GetRuleStageStats 返回单规则的三阶段计数（流程抽屉计数 chip）：
//   - stage1_blocked_24h / stage3_blocked_24h：近 24h 该规则 blocked 安全事件
//     按 rule_triggered id 形状分桶——阶段 1（IP 访问控制+威胁情报库+地域拦截预检）=
//     {2,4,7,8,14} ∪ [800000,900000) ∪ [1500000,1520000)（逐策略 ACL/黑名单预检段，
//     IsStage1PrecheckID 单一事实源），其余（CRS 9xxxxx/自定义/合成 id）归阶段 3；
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
	if err := db.DB.QueryRow(`SELECT 1 FROM lb_rules WHERE caddy_id=?`, ruleCaddyID).Scan(new(int)); err != nil {
		// ErrNoRows（规则不存在）与真实 DB 故障分判——前者归 404
		// not_found，后者保持 500 且 message 归位查询失败（不再借「规则不存在」
		// 文案）。前端对非 200 一律 stats=null，404 化不改变前端表现。
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: apimsg.T(c, "k_814ff4da"), MessageKey: "k_814ff4da"})
			return
		}
		services.Logf("error", "stage-stats read rule domain failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: apimsg.T(c, "k_50531a0d"), MessageKey: "k_50531a0d"})
		return
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：与成功路径同键的零统计而非 panic。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
			"stage1_blocked_24h":     0,
			"stage3_blocked_24h":     0,
			"stage_unattributed_24h": 0,
			"precheck_avg_us":        0.0,
			"precheck_samples":       0,
			"waf_avg_us":             0.0,
			"waf_samples":            0,
		}})
		return
	}
	// 24h 分桶 + 分段耗时经 30s 缓存（规则流程抽屉按秒级轮询/多页签并存，
	// 单规则 24h 全窗口两次聚合在高事件量下达数百 ms）——与策略 24h 计数
	// 缓存（security_policy_counts_cache.go）同范式；失败不缓存。
	stats, err := loadRuleStageStats(db.MetricsDB, ruleCaddyID, time.Now())
	if err != nil {
		services.Logf("error", "stage-stats query failed for %s: %v", ruleCaddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: apimsg.T(c, "k_50531a0d"), MessageKey: "k_50531a0d"})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"stage1_blocked_24h":     stats.stage1,
		"stage3_blocked_24h":     stats.stage3,
		"stage_unattributed_24h": stats.unattributed,
		"precheck_avg_us":        stats.preAvg,
		"precheck_samples":       stats.preCnt,
		"waf_avg_us":             stats.wafAvg,
		"waf_samples":            stats.wafCnt,
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

// ruleStageStatsCache 键含分钟锚点 + 规则身份：条目数受 TTL 与活跃规则数
// 约束，上限 256 超限整体重建（长尾规则集膨胀下内存封顶）。
var ruleStageStatsCache = newTTLCache[ruleStageStatsCacheKey, ruleStageStatsSnapshot](256)

// loadRuleStageStats 返回单规则近 24h 的阶段分桶计数与分段耗时（命中缓存时
// 零查询）。分桶口径：阶段 1={2,4,7,8,14}∪[800000,900000)∪[1500000,1520000)
// 预检段（IsStage1PrecheckID 单一事实源），429 由 ratelimit_blocks_reload 单独供给
// 阶段 2 chip（不计入阶段 3），非数字 triggered 归「未归因」独立桶（与
// categorizeAttack 的「其他/未归因」口径一致），其余归阶段 3。
// 分桶查询失败显式上抛（不缓存）；耗时为增强信息——失败留 warn 按零值并入
// 快照（响应仍返回其余已取数据，与缓存前口径一致）。
func loadRuleStageStats(metricsDB *sql.DB, ruleCaddyID string, now time.Time) (ruleStageStatsSnapshot, error) {
	key := ruleStageStatsCacheKey{metrics: metricsDB, rule: ruleCaddyID, anchor: now.UTC().Format("2006-01-02 15:04")}
	if ruleStageStatsCacheTTL > 0 {
		if snapshot, ok := ruleStageStatsCache.Get(key, now); ok {
			return snapshot, nil
		}
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
		ruleStageStatsCache.Set(key, snapshot, now, ruleStageStatsCacheTTL)
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

// 安全总览的近 7 天聚合（趋势/Top10 IP/攻击族）的读取形态演进：
//  1. 30s 全量重算缓存（键含指标库句柄/日界/时区）——消除每轮询 4 趟全窗口
//     扫描，但冷路径仍是原始表/rollup 的整窗聚合（45 万行生产库 ~1.9s）；
//  2. SWR + 水位线增量（现状）：请求命中未过期条目零查询返回；条目过期后
//     **立即返回旧快照**并触发后台 singleflight 刷新（数据滞后 ≤ 刷新周期），
//     刷新优先走增量（`WHERE id > 水位` 只扫新行、top-IP 候选有界重查 recency），
//     删除/换库/固化模式切换等情形回退全量重算。精度由对账钉测钉死：
//     增量结果必须与全量重算逐字段相等（security_overview_incremental_test.go）。
//
// 失败口径偏离声明：全量时代「任一查询失败显式 500」；SWR 下刷新失败改为
// **保留旧快照 + 限频 warn 日志**——同步报错面已消失（请求不等待刷新），
// 故障经日志与 Ingestion 健康快照披露，面板显示旧数据好于 500。冷启动
// （无任何快照可保，首请求同步全量建）失败仍按原口径上抛 500。
const securityOverviewAggCacheTTL = 5 * time.Second

type securityOverviewAggregates struct {
	trend            []models.SecurityTrendPoint
	topIPs           []models.SecurityTopIP
	attackTypes      []models.SecurityAttackType
	attackTypesStage []models.SecurityAttackType
	// 日界窗口计数与正常请求差分（同缓存体：键含日界/时区/库句柄，
	// 与趋势聚合同缓存生命周期）。todayBlockedTCP 自 handler 逐请求直算
	// 下沉进缓存（同款原始表窗口，口径不变）。
	todayBlockedTCP      int
	todayDetectedTCP     int
	yesterdayBlocked     int
	yesterdayBlockedTCP  int
	yesterdayDetectedTCP int
	yesterdayDetected    int
	normalTodayHTTP      int
	normalTodayTCP       int
	normalYesterdayHTTP  int
	normalYesterdayTCP   int
}

type securityOverviewAggCacheKey struct {
	metrics    *sql.DB
	todayStart string
	// tzName 是时区身份（loc.String()），不是瞬时 UTC 偏移：数据按 today 的
	// location 逐日构造日桶，仅用偏移做键会让「同偏移不同 DST 规则」的两个
	// 时区（或切换后偏移恰好相同的时区）在 TTL 内共用另一时区的日桶。
	tzName string
}

// securityOverviewAggCache 键含时区/日界/库句柄（键空间随时区与日界变化）：
// 写入时顺带清扫过期项防 map 无限增长。值为展示快照 + 增量状态双体
// （securityOverviewAggEntry）：请求路径只读 data，后台刷新读写 state。
var securityOverviewAggCache = newTTLCache[securityOverviewAggCacheKey, securityOverviewAggEntry](0)

// securityOverviewAggMutated 摄取侧行改判标志（检测→拦截原地 UPDATE）：置位
// 后下一次后台刷新强制全量重建（增量轨道无法回溯已消费行的旧结论）。由
// services.SecurityEventsRowMutatedHook 在改判事务提交后触发。
var securityOverviewAggMutated atomic.Bool

func init() {
	services.SecurityEventsRowMutatedHook = func() { securityOverviewAggMutated.Store(true) }
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

// ---- 昨日窗口计数与正常请求差分（30s 聚合缓存体；口径披露见
// models.SecurityOverview 对应字段注释与 apidocs）----

// securityOverviewDayWindowCounts 原始表单日窗口 [from,to) 的拦截/检测计数
// （攻击面谓词同今日直算分支；窗口两端由调用方按本地日界换 UTC 文本）。
func securityOverviewDayWindowCounts(database *sql.DB, from, to time.Time) (blocked, detected int, err error) {
	err = database.QueryRow(`SELECT COALESCE(SUM(action='blocked'),0), COALESCE(SUM(action='logged'),0)
		FROM security_events
		WHERE event_time >= ? AND event_time < ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action"),
		from.UTC().Format(securityOverviewEventTimeLayout), to.UTC().Format(securityOverviewEventTimeLayout)).
		Scan(&blocked, &detected)
	return blocked, detected, err
}

// securityOverviewDayWindowTCPAction 原始表窗口 TCP 动作拆分
// （event_type='tcp' AND action=?——blocked/logged 由参数给定，与今日 TCP
// 直算同款，仅换窗口；to 为零值表示无上界——今日口径与切换前逐字一致）。
func securityOverviewDayWindowTCPAction(database *sql.DB, from, to time.Time, action string) (int, error) {
	query := `SELECT COUNT(*) FROM security_events
		WHERE event_type='tcp' AND action=? AND event_time >= ?`
	args := []any{action, from.UTC().Format(securityOverviewEventTimeLayout)}
	if !to.IsZero() {
		query += ` AND event_time < ?`
		args = append(args, to.UTC().Format(securityOverviewEventTimeLayout))
	}
	var blocked int
	err := database.QueryRow(query, args...).Scan(&blocked)
	return blocked, err
}

// securityOverviewEventTimeLayout metrics 库时间文本统一格式（与采集写侧
// datetime('now') 同形状，UTC 文本比较）。
const securityOverviewEventTimeLayout = "2006-01-02 15:04:05"

// clampedDelta int64 单调差分：cur<prev（计数器随 /load/重启归零）取 cur，
// 否则 cur−prev（与 services.DeltaUint64 同一钳制语义的带符号变体——
// metrics_history 列为 INTEGER，语义同源不得各写各的钳制方向）。
func clampedDelta(cur, prev int64) int64 {
	if cur < prev {
		return cur
	}
	return cur - prev
}

// securityOverviewRuleMetricAnchorAt 取各规则在 at 时刻前（含 at；零值=不限时）
// 末样本的 column（requests_blocked / requests_logged）累计 map（无样本的规则
// 不在 map 中=0 基线）。「每规则末样本」经 MAX(id) 子查询连接取行（同时间戳
// 双行时按写入序取末行，不依赖 SQLite bare-column 行为）。column 是包内常量
// 白名单，非外部输入。
func securityOverviewRuleMetricAnchorAt(database *sql.DB, at time.Time, column string) (map[string]int64, error) {
	inner := `SELECT rule_id, MAX(id) AS id FROM metrics_history WHERE rule_id IS NOT NULL`
	args := []any{}
	if !at.IsZero() {
		inner += ` AND timestamp <= ?`
		args = append(args, at.UTC().Format(securityOverviewEventTimeLayout))
	}
	inner += ` GROUP BY rule_id`
	rows, err := database.Query(`SELECT m.rule_id, m.`+column+` FROM metrics_history m
		JOIN (`+inner+`) t ON m.id = t.id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	anchor := map[string]int64{}
	for rows.Next() {
		var ruleID string
		var value int64
		if err := rows.Scan(&ruleID, &value); err != nil {
			return nil, err
		}
		anchor[ruleID] = value
	}
	return anchor, rows.Err()
}

// 总览差分消费的 metrics_history 计数列白名单（包内常量，非外部输入）。
const (
	securityOverviewColTotal   = "requests_total"
	securityOverviewColBlocked = "requests_blocked"
	securityOverviewColLogged  = "requests_logged"
)

// securityOverviewNormalHTTPDiff 正常请求（HTTP）差分：规则级真实转发计数口径——
// 逐规则 requests_total − requests_blocked − requests_logged（三列同源自
// lazybalancer_* 计数族，每规则独立钳制 /load 重置，逐规则钳零后求和）。
// 不再使用 server 全局 caddy_http_requests_total：v2.11 起该指标按 handler
// 逐位计数（同一请求在链上多个 handler 各计一次），求和口径成倍虚高且与
// per-rule 被拦/检测减项不可对齐；规则未匹配的直连流量（面板/探活等）不
// 计入本 KPI（口径披露见 models/apidocs）。
//
// 读路径双通道（日聚合持久化，2026-11）：
//   - 聚合通道：窗口内 metrics_daily_agg 有行（功能已激活）→ 直读日聚合
//     SUM。采集侧每轮把钳制差分增量按本地日历日入账 + apply 链重载前快照
//     轮，重载零丢失；聚合表独立保留，不受 metrics_history 行帽/7 天清理
//     裁剪影响；
//   - 锚点通道（回退）：窗口内无聚合行（历史日/功能上线前/新装）→ 回落
//     securityOverviewNormalRuleSumRange 累计锚点差分（切换点前后口径断裂
//     由既有披露承载）。回退判定按窗口独立（升级当日激活：今日读聚合、
//     昨日回落锚点）。
//
// 两通道同公式语义：每规则 max(0, totalΔ − blockedΔ − loggedΔ) 后求和；
// 无重置数据集上逐字段相等（对账钉测）。
func securityOverviewNormalHTTPDiff(database *sql.DB, ydayStart, todayStart time.Time) (today, yesterday int, err error) {
	todayDate := securityOverviewLocalDate(todayStart)
	ydayDate := securityOverviewLocalDate(ydayStart)
	// 今日窗口：[今日 0 点, 最新样本)——聚合行 local_date >= 今日日期。
	todayActive, err := securityOverviewDailyAggWindowHasRows(database, todayDate, "")
	if err != nil {
		return 0, 0, err
	}
	if todayActive {
		if today, err = securityOverviewDailyAggNormalSum(database, todayDate, ""); err != nil {
			return 0, 0, err
		}
	} else if today, err = securityOverviewNormalRuleSumRange(database, todayStart, time.Time{}); err != nil {
		return 0, 0, err
	}
	// 昨日窗口：[昨日 0 点, 今日 0 点)——聚合行 local_date ∈ [昨日, 今日)。
	yesterdayActive, err := securityOverviewDailyAggWindowHasRows(database, ydayDate, todayDate)
	if err != nil {
		return 0, 0, err
	}
	if yesterdayActive {
		if yesterday, err = securityOverviewDailyAggNormalSum(database, ydayDate, todayDate); err != nil {
			return 0, 0, err
		}
	} else if yesterday, err = securityOverviewNormalRuleSumRange(database, ydayStart, todayStart); err != nil {
		return 0, 0, err
	}
	return today, yesterday, nil
}

// securityOverviewLocalDate 窗口起点的本地日历日文本（与采集侧写入
// local_date 同源：日界按配置时区，两侧一致）。
func securityOverviewLocalDate(t time.Time) string {
	return t.Format("2006-01-02")
}

// securityOverviewDailyAggWindowHasRows 回退判定：metrics_daily_agg 在窗口
// [fromDate, toDate) 内是否有行（toDate 空=开右端，今日窗口到最新）。有行=
// 该窗口聚合通道已激活；聚合表按日粒度独立保留，历史日行在位即代表该窗口
// 走聚合（无行=功能上线前/新装，回落锚点差分）。
func securityOverviewDailyAggWindowHasRows(database *sql.DB, fromDate, toDate string) (bool, error) {
	query := `SELECT EXISTS(SELECT 1 FROM metrics_daily_agg WHERE local_date >= ?`
	args := []any{fromDate}
	if toDate != "" {
		query += ` AND local_date < ?`
		args = append(args, toDate)
	}
	query += `)`
	var exists bool
	err := database.QueryRow(query, args...).Scan(&exists)
	return exists, err
}

// securityOverviewDailyAggNormalSum 聚合通道窗口 [fromDate, toDate)（toDate
// 空=开右端）内逐规则正常请求求和：每规则窗口级 SUM(totalΔ−blockedΔ−loggedΔ)
// 钳零后求和——与锚点差分的「每规则窗口内钳零」同构（无重置数据集对账恒
// 等）。聚合行的差分增量在写侧已按采样点结算并含 /load 归零钳制。
func securityOverviewDailyAggNormalSum(database *sql.DB, fromDate, toDate string) (int, error) {
	query := `SELECT rule_id, SUM(requests_delta), SUM(blocked_delta), SUM(logged_delta)
		FROM metrics_daily_agg WHERE local_date >= ?`
	args := []any{fromDate}
	if toDate != "" {
		query += ` AND local_date < ?`
		args = append(args, toDate)
	}
	query += ` GROUP BY rule_id`
	rows, err := database.Query(query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	sum := 0
	for rows.Next() {
		var ruleID string
		var total, blocked, logged int64
		if err := rows.Scan(&ruleID, &total, &blocked, &logged); err != nil {
			return 0, err
		}
		if d := total - blocked - logged; d > 0 {
			sum += int(d)
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	return sum, nil
}

// securityOverviewNormalRuleSum 窗口 [from,to]（to 零值=最新样本）内逐规则
// 正常请求求和：每规则 max(0, totalΔ − blockedΔ − loggedΔ)——三列同源自
// lazybalancer_* 计数族，每规则独立钳制 /load 重置，逐规则钳零后求和。
func securityOverviewNormalRuleSumRange(database *sql.DB, from, to time.Time) (int, error) {
	totalAnchor, err := securityOverviewRuleMetricAnchorAt(database, to, securityOverviewColTotal)
	if err != nil {
		return 0, err
	}
	blockedAnchor, err := securityOverviewRuleMetricAnchorAt(database, to, securityOverviewColBlocked)
	if err != nil {
		return 0, err
	}
	loggedAnchor, err := securityOverviewRuleMetricAnchorAt(database, to, securityOverviewColLogged)
	if err != nil {
		return 0, err
	}
	totalFrom, err := securityOverviewRuleMetricAnchorAt(database, from, securityOverviewColTotal)
	if err != nil {
		return 0, err
	}
	blockedFrom, err := securityOverviewRuleMetricAnchorAt(database, from, securityOverviewColBlocked)
	if err != nil {
		return 0, err
	}
	loggedFrom, err := securityOverviewRuleMetricAnchorAt(database, from, securityOverviewColLogged)
	if err != nil {
		return 0, err
	}
	sum := 0
	for ruleID, curTotal := range totalAnchor {
		d := clampedDelta(curTotal, totalFrom[ruleID]) -
			clampedDelta(blockedAnchor[ruleID], blockedFrom[ruleID]) -
			clampedDelta(loggedAnchor[ruleID], loggedFrom[ruleID])
		if d > 0 {
			sum += int(d)
		}
	}
	return sum, nil
}

// securityOverviewNormalTCPDiff 正常 TCP 连接差分：lb_l4_conn_history 全局
// 行（rule_id=”）allowed 的日窗口求和。2026-11-08 用户裁定：信任检测连接
// （logged 键形态，trust_detect 专属）是成功代理流量，计入正常列——不再
// 从 allowed 扣减；logged 列保留为归因明细（检测放行拆分可见性），写侧
// 语义不变。写侧差分落库时已含重置钳制，读侧直接求和；per-rule 行只做
// 归因明细，不参与全局求和。
func securityOverviewNormalTCPDiff(database *sql.DB, ydayStart, todayStart time.Time) (today, yesterday int, err error) {
	layout := securityOverviewEventTimeLayout
	if err := database.QueryRow(`SELECT COALESCE(SUM(allowed),0) FROM lb_l4_conn_history
		WHERE rule_id='' AND timestamp >= ?`, todayStart.UTC().Format(layout)).Scan(&today); err != nil {
		return 0, 0, err
	}
	if err := database.QueryRow(`SELECT COALESCE(SUM(allowed),0) FROM lb_l4_conn_history
		WHERE rule_id='' AND timestamp >= ? AND timestamp < ?`,
		ydayStart.UTC().Format(layout), todayStart.UTC().Format(layout)).Scan(&yesterday); err != nil {
		return 0, 0, err
	}
	return today, yesterday, nil
}

// securityOverviewResponse 在不改变公共 SecurityOverview 模型的前提下，为
// 近 7 天卡片附带覆盖披露；nil metrics 的零面板也保持同键。
// IncludesReserved 口径披露：仅描述 today_blocked/today_detected 的路径
// 分叉（走 rollup=与大屏同口径排除私网 false / 回退原始表直算=含私网 true）。
// trend/top_ips/attack_types **恒含**私网/保留地址——读路径下沉后新维度表
// 写入侧（aggregateOverviewEvents）同口径含保留地址，性能优化不改变统计
// 口径——前端 tooltip 按该字段为今日两项切换两种口径文案消歧。
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

// securityEventIPRollupTable / securityEventRuleRollupTable 安全总览读路径
// 消费的 IP/规则维度分钟预聚合表（写入侧与 security_event_rollup 同事务同
// 生命周期固化：PK 前缀=minute，UTC 分钟文本；固化时已按攻击面谓词与保留
// 地址排除过滤——读侧 ip 表无规则列、rule 表无 IP 列，不再重复套用谓词）。
const (
	securityEventIPRollupTable   = "security_event_ip_rollup"
	securityEventRuleRollupTable = "security_event_rule_rollup"
)

// topIPRow Top10 IP 中间行（raw/rollup 双路径共形，装配段单源）。
type topIPRow struct {
	ip                  string
	blocked, detected   int
	recent10m, recent1h int
	recent24h           int
	lastTime            string
}

// securityOverviewSourceAgg 单次聚合的来源数据（趋势/Top10 行/攻击族计数），
// 由 rollup 或原始表路径产出，共用同一装配段（topIPs/attackTypes 排序截断）。
type securityOverviewSourceAgg struct {
	trend        []models.SecurityTrendPoint
	topRows      []topIPRow
	familyCounts map[string]int
	stageCounts  map[string]int
}

// securityOverviewAggRollupUsable 近 7 天聚合可否切换预聚合读路径：
//   - 覆盖水位已回推到窗口起点（分钟）且固化新鲜（≤ threatRollupStaleAfter
//     ——与 securityOverviewTodayCounts 同款状态键/常量/判定形状）；
//   - 写入侧总览维度就绪标记（overview_rollup_ready，threatFixMinuteWithMode
//     升级回填完成后置位）存在——缺失=升级回填未完成/状态恢复异常，覆盖
//     水位可能宣称完整而维度表为空（静默少计），必须回退原始表。
//
// 状态读取失败按不可用处理（宁可多扫描一次，不得把覆盖缺口伪装成完整
// 聚合）。维度表缺失不属于本门职责：门只看状态键，水位/就绪齐备而表缺失
// 属异常，由查询错误显式暴露成 500（「任一查询失败显式报错」），不静默换路。
func securityOverviewAggRollupUsable(database *sql.DB, windowStartUTC time.Time, now time.Time) bool {
	coveredFrom, okCovered, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil || !okCovered {
		return false
	}
	watermark, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil || !okFixed {
		return false
	}
	ready, okReady, err := loadThreatRollupRawState(database, threatRollupOverviewReadyKey)
	if err != nil || !okReady || ready != "1" {
		return false
	}
	windowMinute := windowStartUTC.Truncate(time.Minute)
	lastComplete := now.UTC().Add(-time.Minute).Truncate(time.Minute)
	return !coveredFrom.After(windowMinute) && lastComplete.Sub(watermark) <= threatRollupStaleAfter
}

// loadOverviewAggregatesFromRollup 预聚合读路径（趋势/Top10 IP/攻击族）。
// 口径（与写入侧 aggregateOverviewEvents 契约一致）：新维度表**含保留/私网
// 地址**（总览历史口径，includes_reserved 披露不变）——读路径切换为纯性能
// 下沉、零口径变化。趋势源因此用 security_event_rule_rollup（按日界区间对
// action 求和），**不用** security_event_rollup：那是大屏固化口径（写入侧
// 排除保留地址），会让趋势与 Top10/攻击族在同一面板内总量分叉。爬虫放行
// 族 logged 在写入侧已按攻击面谓词排除，读侧不再重复套用。
// 时间口径：minute 为 UTC 分钟文本，逐日本地边界换 UTC 分钟文本（分钟粒度，
// 与原始表 event_time 秒级窗口同一日桶构造）；趋势与今日计数一样含「当前
// 分钟截至最近一次固化」的事件。空 rule_triggered 事件写入侧照常聚进
// rule 维度键（COALESCE ”），趋势求和不受影响。
func loadOverviewAggregatesFromRollup(metricsDB *sql.DB, dayStarts []time.Time, today time.Time, now time.Time) (securityOverviewSourceAgg, error) {
	const minuteLayout = "2006-01-02 15:04"
	var firstErr error
	track := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	windowStartMinute := dayStarts[0].UTC().Format(minuteLayout)
	trend := make([]models.SecurityTrendPoint, 0, 7)
	for i := range 7 {
		point := models.SecurityTrendPoint{Date: dayStarts[i].In(today.Location()).Format("2006-01-02")}
		err := metricsDB.QueryRow(`SELECT COALESCE(SUM(CASE WHEN action='blocked' THEN count ELSE 0 END),0),
			COALESCE(SUM(CASE WHEN action='logged' THEN count ELSE 0 END),0)
			FROM `+securityEventRuleRollupTable+` WHERE minute >= ? AND minute < ?`,
			dayStarts[i].UTC().Format(minuteLayout), dayStarts[i+1].UTC().Format(minuteLayout)).
			Scan(&point.Blocked, &point.Detected)
		track(err)
		trend = append(trend, point)
	}

	// 近窗 recency：minute 文本经 Format 取整到分钟——同一分钟内的秒级边缘
	// 与原始表秒级窗口可差 <1 分钟（rollup 无秒级分辨率，与今日计数
	// 「含当前分钟截至最近固化」同类口径）。
	nowUTC := now.UTC()
	recent10m := nowUTC.Add(-10 * time.Minute).Format(minuteLayout)
	recent1h := nowUTC.Add(-time.Hour).Format(minuteLayout)
	recent24h := nowUTC.Add(-24 * time.Hour).Format(minuteLayout)
	type ipRecency struct {
		recent10m, recent1h, recent24h int
	}
	recencyByIP := map[string]ipRecency{}
	recencyRows, err := metricsDB.Query(`SELECT COALESCE(client_ip,''),
		COALESCE(SUM(CASE WHEN minute >= ? THEN count ELSE 0 END),0) as recent_10m,
		COALESCE(SUM(CASE WHEN minute >= ? THEN count ELSE 0 END),0) as recent_1h,
		COALESCE(SUM(count),0) as recent_24h
		FROM `+securityEventIPRollupTable+` WHERE minute >= ? GROUP BY client_ip`, recent10m, recent1h, recent24h)
	track(err)
	for recencyRows != nil && recencyRows.Next() {
		var ip string
		var rec ipRecency
		track(recencyRows.Scan(&ip, &rec.recent10m, &rec.recent1h, &rec.recent24h))
		recencyByIP[ip] = rec
	}
	if recencyRows != nil {
		track(recencyRows.Err())
		recencyRows.Close()
	}

	// 7 天总量 Top10：blocked+logged 降序截前 10；recency 由 24h 全量查询
	// 按 IP 合并（缺省 0——只出现在 24h 窗口之外的 IP）。
	topRows := make([]topIPRow, 0, 10)
	ipRows, err := metricsDB.Query(`SELECT COALESCE(client_ip,''),
		COALESCE(SUM(CASE WHEN action='blocked' THEN count ELSE 0 END),0) as b,
		COALESCE(SUM(CASE WHEN action='logged' THEN count ELSE 0 END),0) as l,
		MAX(minute) as last_minute
		FROM `+securityEventIPRollupTable+` WHERE minute >= ? AND TRIM(COALESCE(client_ip,'')) <> ''
		GROUP BY client_ip ORDER BY b + l DESC, COALESCE(client_ip,'') ASC LIMIT 10`, windowStartMinute)
	track(err)
	for ipRows != nil && ipRows.Next() {
		var ip string
		var blocked, detected int
		var lastMinute string
		track(ipRows.Scan(&ip, &blocked, &detected, &lastMinute))
		rec := recencyByIP[ip]
		topRows = append(topRows, topIPRow{
			ip:        ip,
			blocked:   blocked,
			detected:  detected,
			recent10m: rec.recent10m,
			recent1h:  rec.recent1h,
			recent24h: rec.recent24h,
			// MAX(minute) 为 UTC 分钟文本（无秒位），补 ":00" 与原始表
			// last_time 同形（UTC 文本透传，前端 formatDate 同一解析路径）。
			lastTime: lastMinute + ":00",
		})
	}
	if ipRows != nil {
		track(ipRows.Err())
		ipRows.Close()
	}

	// 攻击族总量：规则维度 rollup GROUP BY rule_triggered, rule_msg——排序/
	// 截断/阶段分类与原始表路径共用同一装配段（分类逻辑单源）。
	familyCounts := map[string]int{}
	stageCounts := map[string]int{}
	typeRows, err := metricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COALESCE(SUM(count),0) as cnt
		FROM `+securityEventRuleRollupTable+` WHERE minute >= ? GROUP BY rule_triggered, rule_msg`, windowStartMinute)
	track(err)
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
	return securityOverviewSourceAgg{trend: trend, topRows: topRows, familyCounts: familyCounts, stageCounts: stageCounts}, firstErr
}

// loadOverviewAggregatesFromRaw 原始表直读回退路径：rollup 覆盖未达窗口起点
// （升级回填/fresh install）、固化陈旧、就绪标记缺失或状态读取失败时使用。
// 行为与切换点之前的既有实现完全同口径（含保留/私网地址，与新维度表写入
// 侧一致，无跨路径口径分叉）。查询形状随总览 SWR 改造有两处显式化：趋势
// 7 条逐日 COUNT 合并为单条窗口扫描（语义逐字保持，逐日边界 UTC 文本传参，
// 等价性由现有趋势钉测钉住）；top-IP 排序补 client_ip 升序 tiebreak（并列
// IP 展示顺序确定化，与增量重排的 Go 排序逐字对齐——严格对账的前提）。
func loadOverviewAggregatesFromRaw(metricsDB *sql.DB, dayStarts []time.Time) (securityOverviewSourceAgg, error) {
	const eventTimeLayout = "2006-01-02 15:04:05"
	var firstErr error
	track := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	windowStartUTC := dayStarts[0].UTC().Format(eventTimeLayout)
	// 趋势单扫描：原实现逐日 7 条 COUNT（7 趟窗口扫描）；合并为单条 [d0,d7)
	// 窗口扫描 + 7 组逐桶 SUM(CASE)。语义逐字保持：[d0,d7) 被 7 个逐日本地
	// 边界日桶精确划分（无缝无叠），逐桶求和与逐日查询逐字段相等；边界仍按
	// 逐日本地边界换 UTC 文本传参（文本比较走 idx_security_events_time 前缀），
	// 不改用 substr 日期截断。语义等价钉测沿用现有趋势测试（窗口边界/时区）。
	trendColumns := make([]string, 0, 14)
	trendArgs := make([]any, 0, 30)
	for i := range 7 {
		dayFrom := dayStarts[i].UTC().Format(eventTimeLayout)
		dayTo := dayStarts[i+1].UTC().Format(eventTimeLayout)
		trendColumns = append(trendColumns,
			"COALESCE(SUM(CASE WHEN event_time >= ? AND event_time < ? THEN CASE WHEN action='blocked' THEN 1 ELSE 0 END ELSE 0 END),0)",
			"COALESCE(SUM(CASE WHEN event_time >= ? AND event_time < ? THEN CASE WHEN action='logged' THEN 1 ELSE 0 END ELSE 0 END),0)")
		trendArgs = append(trendArgs, dayFrom, dayTo, dayFrom, dayTo)
	}
	trendArgs = append(trendArgs, dayStarts[0].UTC().Format(eventTimeLayout), dayStarts[7].UTC().Format(eventTimeLayout))
	var trendCells [14]int
	scanInto := make([]any, 14)
	for i := range scanInto {
		scanInto[i] = &trendCells[i]
	}
	if err := metricsDB.QueryRow("SELECT "+strings.Join(trendColumns, ",")+"\n"+
		"FROM security_events WHERE event_time >= ? AND event_time < ? AND "+services.AttackEventSQLPredicate("rule_triggered", "action"),
		trendArgs...).Scan(scanInto...); err != nil {
		track(err)
	}
	trend := make([]models.SecurityTrendPoint, 0, 7)
	for i := range 7 {
		trend = append(trend, models.SecurityTrendPoint{
			Date:     dayStarts[i].In(dayStarts[0].Location()).Format("2006-01-02"),
			Blocked:  trendCells[i*2],
			Detected: trendCells[i*2+1],
		})
	}

	var topRows []topIPRow
	nowUTC := time.Now().UTC()
	recent10m := nowUTC.Add(-10 * time.Minute).Format(eventTimeLayout)
	recent1h := nowUTC.Add(-time.Hour).Format(eventTimeLayout)
	recent24h := nowUTC.Add(-24 * time.Hour).Format(eventTimeLayout)
	ipRows, err := metricsDB.Query(`SELECT COALESCE(client_ip,''),
		SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b,
		SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l,
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END) as recent_10m,
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END) as recent_1h,
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END) as recent_24h,
		MAX(event_time) as last_time
		FROM security_events WHERE event_time >= ? AND TRIM(COALESCE(client_ip,'')) <> '' AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip ORDER BY b + l DESC, COALESCE(client_ip,'') ASC LIMIT 10`, recent10m, recent1h, recent24h, windowStartUTC)
	track(err)
	for ipRows != nil && ipRows.Next() {
		var row topIPRow
		track(ipRows.Scan(&row.ip, &row.blocked, &row.detected, &row.recent10m, &row.recent1h, &row.recent24h, &row.lastTime))
		topRows = append(topRows, row)
	}
	if ipRows != nil {
		track(ipRows.Err())
		ipRows.Close()
	}

	familyCounts := map[string]int{}
	stageCounts := map[string]int{}
	typeRows, err := metricsDB.Query(`SELECT COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY rule_triggered, rule_msg`, windowStartUTC)
	track(err)
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
	return securityOverviewSourceAgg{trend: trend, topRows: topRows, familyCounts: familyCounts, stageCounts: stageCounts}, firstErr
}

// loadTopIPFamilySubdivision top10 逐 IP 攻击族细分（rollup/raw 双路径共用，
// 一律走原始表）：有 idx_security_events_ip_time(client_ip, event_time DESC)
// 覆盖、按 ≤10 个 IP 有界毫秒级；ip 维度 rollup 无规则维度、rule 维度
// rollup 无 IP 维度，预聚合无法承载该细分（保留 raw 是结构与索引论证后的
// 选择，非遗漏）。
func loadTopIPFamilySubdivision(metricsDB *sql.DB, windowStartUTC string, topRows []topIPRow) (map[string]map[string]int, map[string]map[string]int, error) {
	familyCountsByIP := map[string]map[string]int{}
	stageFamilyCountsByIP := map[string]map[string]int{}
	if len(topRows) == 0 {
		return familyCountsByIP, stageFamilyCountsByIP, nil
	}
	var firstErr error
	placeholders := make([]string, len(topRows))
	famArgs := make([]interface{}, 0, len(topRows)+1)
	famArgs = append(famArgs, windowStartUTC)
	for i, row := range topRows {
		placeholders[i] = "?"
		famArgs = append(famArgs, row.ip)
	}
	famRows, ferr := metricsDB.Query(fmt.Sprintf(`SELECT client_ip, COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COUNT(*) as cnt FROM security_events WHERE event_time >= ? AND client_ip IN (%s) AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip, rule_triggered, rule_msg`, strings.Join(placeholders, ",")), famArgs...)
	if ferr != nil {
		return familyCountsByIP, stageFamilyCountsByIP, ferr
	}
	for famRows.Next() {
		var ip, ruleTriggered, ruleMsg string
		var cnt int
		if err := famRows.Scan(&ip, &ruleTriggered, &ruleMsg, &cnt); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
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
	if err := famRows.Err(); err != nil && firstErr == nil {
		firstErr = err
	}
	famRows.Close()
	return familyCountsByIP, stageFamilyCountsByIP, firstErr
}

// loadSecurityOverviewAggregates 计算（或命中缓存）近 7 天聚合——SWR 读路径：
//   - 未过期条目：零查询返回（深拷贝出入）；
//   - 过期条目：立即返回旧快照，同时触发后台 singleflight 刷新（数据滞后
//     ≤ securityOverviewAggCacheTTL；刷新失败保留旧快照 + 限频 warn，偏离
//     声明见缓存头注释）；
//   - 无条目（首请求/换库/跨日界/改时区）：同步全量建一次，错误照旧上抛
//     （调用方聚合成 500，与既有「任一查询失败显式报错」口径一致——无旧
//     快照可保，静默零面板与「无攻击」不可区分）。
//
// tzName 仅用于缓存键区分时区身份（loc.String()）；窗口/日桶一律由 today
// 携带的时区逐日构造（DST 正确），不把单一偏移套到整周 SQL date() 上。
//
// 双路径语义（rollup 优先 + raw 回退）：覆盖水位已回推到窗口起点、固化
// 新鲜且写入侧就绪标记齐备时，趋势/Top10 IP/攻击族读分钟预聚合
// （loadOverviewAggregatesFromRollup，与原始表规模解耦——保留期/行帽裁剪
// 后不再静默少计）；其余情形（升级回填未完成、fresh install、固化陈旧、
// 状态读取失败）走原始表直读回退（loadOverviewAggregatesFromRaw，查询与
// 切换前实现逐字一致）。新维度表写入侧含保留/私网地址（总览历史口径），
// 读路径切换为纯性能下沉、零口径变化。
func loadSecurityOverviewAggregates(metricsDB *sql.DB, today time.Time, todayStartUTC, tzName string) (securityOverviewAggregates, error) {
	key := securityOverviewAggCacheKey{metrics: metricsDB, todayStart: todayStartUTC, tzName: tzName}
	now := time.Now()
	if entry, ok := securityOverviewAggCache.Get(key, now); ok {
		// 深拷贝：四个切片若与缓存条目共享底层数组，任一消费者就地变更
		// （sort/截断/改元素）都会污染其他请求的缓存（同型事故：健康
		// 缓存的「共享同一克隆」）。
		return cloneSecurityOverviewAggregates(entry.data), nil
	}
	if stale, ok := securityOverviewAggCache.GetStale(key); ok {
		// SWR：过期条目立即让位——先返回旧快照，后台刷新就绪后由 Set 原子
		// 覆盖。singleflight 合并过期瞬间的并发触发为一次刷新（与
		// threatTrafficGroup 同款模式）。
		go func() {
			_, _, _ = securityOverviewAggRefreshGroup.Do(fmt.Sprint(key), func() (any, error) {
				_, err := refreshSecurityOverviewAggregates(metricsDB, key, today)
				return nil, err
			})
		}()
		return cloneSecurityOverviewAggregates(stale.data), nil
	}
	// 冷启动：同步全量建一次（首请求慢一次可接受，与全量缓存时代同）。
	dayStarts := securityOverviewDayStarts(today)
	fromRollup := securityOverviewAggRollupUsable(metricsDB, dayStarts[0], now)
	data, state, err := computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, fromRollup)
	if err != nil {
		return data, err
	}
	securityOverviewAggCache.Set(key, securityOverviewAggEntry{data: cloneSecurityOverviewAggregates(data), state: state}, now, securityOverviewAggCacheTTL)
	return data, nil
}

// securityOverviewDayStarts 近 7 天日桶边界（[0..6]=今日−6..今日、[7]=明日
// 0 点趋势排他上界）。趋势日桶必须用**逐日本地边界**，不得用单一当前时区
// 偏移——DST 周界（如 America/New_York 3 月/11 月切换）单偏移会让切换前
// 一日的边界错 1h，事件跨到相邻日桶（默认 Asia/Shanghai 无 DST，故此前
// 未暴露）。边界按 today 携带的配置时区逐日构造（today 由调用方
// time.Now().In(loc) 传入）。
func securityOverviewDayStarts(today time.Time) []time.Time {
	dayStarts := make([]time.Time, 8)
	for i := range dayStarts {
		d := today.AddDate(0, 0, i-6)
		dayStarts[i] = time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, today.Location())
	}
	return dayStarts
}

// topIPAccum top-IP 可累加结构（7 天窗口内的拦截/检测累计与末次事件时间；
// lastTime 为 UTC 文本，取字典序最大与 SQL MAX(event_time) 同语义——
// event_time 恒为定宽 'YYYY-MM-DD HH:MM:SS' 文本）。
type topIPAccum struct {
	blocked, detected int
	lastTime          string
}

// securityOverviewAggState 增量聚合的缓存状态体：水位 + 可累加结构 + 键生命
// 周期内不可变的窗口值。刷新轨道（refreshSecurityOverviewAggIncremental）
// 对其副本逐行归桶累加；请求路径只读 entry.data，两者经缓存条目各取所需。
//
// 精度不变式（对账钉测钉死）：builtFromRollup=false 的 state 恒等于
// 「对 id ≤ maxEventID 且 event_time ≥ 窗口起点的行做全量重算」的结果——
// 增量扫描只补 id > 水位的新行；任何破坏该不变式的形态（删除/换库/模式
// 切换）都触发全量重建。
type securityOverviewAggState struct {
	// maxEventID 已聚合的最大事件 id（水位）；seenTotal 「id ≤ 水位且
	// event_time ≥ 窗口起点」的存活行数账本（删除检测：存活数变少 → 全量
	// 重建。账本只数窗口内行——窗口外的保留期/行帽裁剪不改变 7 天聚合
	// 结果，不触发无谓重建；行帽触顶删除窗口内旧行属于聚合必须反映的
	// 真实删除，正常触发）。
	maxEventID int64
	seenTotal  int64
	// builtFromRollup 上一轮聚合来源路径：rollup 读路径与 raw 增量计数同一
	// 宇宙（同谓词同窗口），但 rollup 基线存在「固化未覆盖尾部」（≤1 分钟，
	// 与既有 rollup 读路径滞后同口径）——切回 raw 增量前必须先做一次全量
	// raw 重建补齐固化停滞期事件，否则该尾部永远缺计（id ≤ 水位不被增量扫描）。
	builtFromRollup bool
	// 日桶边界（UTC 文本，与 SQL 文本窗口同语义比较）与展示标签。
	dayBounds [8]string
	dayLabels [7]string
	// 可累加聚合（增量逐行归桶）。topIPs 账本有界：播种=窗口内 b+l 前 500 名
	// （loadOverviewTopIPSeed LIMIT 500，封顶播种查询规模），增量轨道此后对
	// 「账本外新出现 IP」补账（仅其新增事件，无历史累计）；跨日界换键后整体
	// 重建。窗口内去重攻击 IP >500 的分布攻击形态下，基线 501 名外的 IP 靠
	// 新增事件冲榜时历史累计缺账本，Top10 漏列/计数缩水，以日界重建自愈
	// （≤1 天）；rank-11 冲榜回归钉测
	// TestSecurityOverviewIncremental_rankElevenIPRushesIntoTop10 钉 500 内
	// 形状，>500 尾部无覆盖（披露于本注释，勿再宣称「有意不设上限」）。
	trendBlocked  [7]int
	trendDetected [7]int
	familyCounts  map[string]int
	stageCounts   map[string]int
	topIPs        map[string]topIPAccum
	// 不可变窗口值：键含 todayStart → 键生命周期内窗口恒定，刷新直接携带
	// （昨日窗口与昨日差分不随时间变化；跨日界换键全量重建一次）。
	yesterdayBlocked     int
	yesterdayDetected    int
	yesterdayBlockedTCP  int
	yesterdayDetectedTCP int
	normalYesterdayHTTP  int
	normalYesterdayTCP   int
}

// securityOverviewAggEntry 缓存条目：展示快照 + 增量状态。
type securityOverviewAggEntry struct {
	data  securityOverviewAggregates
	state securityOverviewAggState
}

// securityOverviewAggRefreshGroup 过期刷新合并组：过期瞬间的并发请求只跑
// 一趟刷新（SWR 读路径不等待，合并的是后台触发本身）。
var securityOverviewAggRefreshGroup singleflight.Group

// securityOverviewAggRefreshWarnLast 刷新失败限频 warn 的上次发射时刻
// （unix 纳秒；CAS 抢占，并发刷新下至多每窗口一条——5s 刷新周期 + 停转
// 的 metrics 库不该刷屏日志）。
var securityOverviewAggRefreshWarnLast atomic.Int64

func warnSecurityOverviewAggRefresh(err error) {
	now := time.Now().UnixNano()
	last := securityOverviewAggRefreshWarnLast.Load()
	if now-last < int64(time.Minute) || !securityOverviewAggRefreshWarnLast.CompareAndSwap(last, now) {
		return
	}
	services.Logf("warn", "security overview aggregate refresh failed (serving stale snapshot): %v", err)
}

// refreshSecurityOverviewAggregates 同步刷新缓存条目（SWR 后台航班的执行体，
// 也是测试缝）：按当前路径可用性分派——rollup 可用走 rollup 全量（与原始表
// 规模解耦）；raw 轨道走水位增量；模式切换/删除检测命中时回退全量 raw 重建。
// 成功后原子覆盖缓存条目；失败保留旧快照并返回错误（无旧快照时返回错误由
// 后台航班吞掉——请求路径从未等待本次刷新）。
func refreshSecurityOverviewAggregates(metricsDB *sql.DB, key securityOverviewAggCacheKey, today time.Time) (securityOverviewAggregates, error) {
	now := time.Now()
	stale, hasStale := securityOverviewAggCache.GetStale(key)
	dayStarts := securityOverviewDayStarts(today)
	fromRollup := securityOverviewAggRollupUsable(metricsDB, dayStarts[0], now)
	var (
		data  securityOverviewAggregates
		state securityOverviewAggState
		err   error
	)
	switch {
	case securityOverviewAggMutated.CompareAndSwap(true, false):
		// 摄取侧行改判（检测→拦截原地 UPDATE）已发生：该行的旧结论已被上一
		// 轮增量消费，增量轨道无法回溯——强制全量重建一次（重铸水位），此后
		// 恢复增量轨道。stale 快照在重建期间照常服务（SWR）。
		data, state, err = computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, fromRollup)
	case !hasStale:
		// 条目已被清（换库/测试 Reset）：退回全量建。
		data, state, err = computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, fromRollup)
	case fromRollup:
		// rollup 读路径可用：全量走预聚合（毫秒-十毫秒级）。逐轮全量而非增量：
		// rollup 固化逐分钟推进，全量重读自动补齐固化尾部，与既有 rollup 读
		// 路径滞后口径完全一致，无需水位簿记。
		data, state, err = computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, true)
	case stale.state.builtFromRollup:
		// rollup→raw 模式切换（固化停滞/状态缺失）：先全量 raw 重建补齐
		// rollup 基线未覆盖的固化停滞期事件，再进入 raw 增量轨道。
		data, state, err = computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, false)
	default:
		data, state, err = refreshSecurityOverviewAggIncremental(metricsDB, stale.state, dayStarts, today, now)
	}
	if err != nil {
		warnSecurityOverviewAggRefresh(err)
		if hasStale {
			return cloneSecurityOverviewAggregates(stale.data), err
		}
		return data, err
	}
	securityOverviewAggCache.Set(key, securityOverviewAggEntry{data: cloneSecurityOverviewAggregates(data), state: state}, now, securityOverviewAggCacheTTL)
	return data, nil
}

// refreshSecurityOverviewAggIncremental raw 轨道水位增量刷新：
//  1. 删除检测双检——MAX(id) 收缩（水位之上行被删，自愈型重建触发）与存活
//     账本核对（COUNT(id ≤ 水位 AND 窗口内) < seenTotal → 有已聚合行被删，
//     全量重建；并发新插入不影响账本，新行 id 恒大于水位）；
//  2. 增量扫描 `WHERE id > 水位 AND event_time ≥ 窗口起点 AND 攻击谓词`，
//     逐行归桶累加（日桶按既有逐日本地边界判定；top-IP 累计 b/l/lastTime）；
//  3. recent 窗口（10m/1h/24h）与 top-IP 排序不做增量——对候选集（按 b+l
//     排序的 topIPAccum 有界前缀，天然包含全部新增 IP）做一次有界 IN 查询
//     重查 recency 后重排取 10；
//  4. 今日 TCP 计数走 (event_type,action,event_time) 索引保留现查询；今日
//     正常请求差分重算（随时间增长）；昨日窗口值直接携带。
//
// 任一步失败显式上抛（调用方保留旧快照）。
func refreshSecurityOverviewAggIncremental(metricsDB *sql.DB, prev securityOverviewAggState, dayStarts []time.Time, today time.Time, now time.Time) (securityOverviewAggregates, securityOverviewAggState, error) {
	state := cloneSecurityOverviewAggState(prev)
	var maxID, alive int64
	err := metricsDB.QueryRow(`SELECT (SELECT COALESCE(MAX(id),0) FROM security_events),
		(SELECT COUNT(*) FROM security_events WHERE id <= ? AND event_time >= ?)`,
		state.maxEventID, state.dayBounds[0]).Scan(&maxID, &alive)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	if maxID < state.maxEventID || alive < state.seenTotal {
		// 删除/收缩检测命中：全量重建（走既有全路径，水位在重建内重铸）。
		return computeSecurityOverviewAggregatesFull(metricsDB, dayStarts, today, now, false)
	}
	scanned, err := scanSecurityOverviewIncrementalRows(metricsDB, &state)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	state.seenTotal = alive + scanned

	topRows, err := rerankSecurityOverviewTopIPs(metricsDB, &state, now)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	familyCountsByIP, stageFamilyCountsByIP, err := loadTopIPFamilySubdivision(metricsDB, state.dayBounds[0], topRows)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	todayDayStart := dayStarts[6]
	var dayCounts securityOverviewAggregates
	dayCounts.todayBlockedTCP, err = securityOverviewDayWindowTCPAction(metricsDB, todayDayStart, time.Time{}, "blocked")
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	dayCounts.todayDetectedTCP, err = securityOverviewDayWindowTCPAction(metricsDB, todayDayStart, time.Time{}, "logged")
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	dayCounts.normalTodayHTTP, _, err = securityOverviewNormalHTTPDiff(metricsDB, dayStarts[5], todayDayStart)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	_, dayCounts.normalTodayTCP, err = securityOverviewNormalTCPDiff(metricsDB, dayStarts[5], todayDayStart)
	if err != nil {
		return securityOverviewAggregates{}, state, err
	}
	dayCounts.yesterdayBlocked = state.yesterdayBlocked
	dayCounts.yesterdayDetected = state.yesterdayDetected
	dayCounts.yesterdayBlockedTCP = state.yesterdayBlockedTCP
	dayCounts.yesterdayDetectedTCP = state.yesterdayDetectedTCP
	dayCounts.normalYesterdayHTTP = state.normalYesterdayHTTP
	dayCounts.normalYesterdayTCP = state.normalYesterdayTCP

	src := securityOverviewSourceAgg{
		trend:        state.trendPoints(),
		topRows:      topRows,
		familyCounts: state.familyCounts,
		stageCounts:  state.stageCounts,
	}
	data := assembleSecurityOverviewAggregates(dayStarts, src, familyCountsByIP, stageFamilyCountsByIP, dayCounts)
	return data, state, nil
}

// scanSecurityOverviewIncrementalRows 水位增量扫描：只取 id > 水位且落在聚合
// 窗口（event_time ≥ 窗口起点，无上界——与全量路径的 top-IP/攻击族查询同
// 窗口形状）且命中攻击面谓词的行，逐行归桶累加进 state。返回消费行数。
// 日桶判定用 UTC 文本比较（与 SQL 文本窗口同语义）；落在 [明日零点,∞) 的
// 时钟偏斜行不进趋势桶（全量路径逐日查询均不含该行），但仍计入攻击族与
// top-IP（这两个聚合只有窗口下界）。水位推进到本趟扫描内最大 id（按 id 升
// 序扫描——语句级快照保证消费行与水位自洽，元数据查询的 MAX(id) 不用于
// 推进水位）。
//
// event_time 恒为定宽 UTC 文本（SQL 文本窗口/字典序比较的前提）。裸列
// SELECT 时驱动会把声明为 DATETIME 的列转成 time.Time，再扫进 string 时被
// database/sql 按 RFC3339Nano 重排（全量路径的 MAX(event_time) 聚合无声明
// 类型、保持原文本）——增量扫描必须 CAST 成 TEXT 保持与全量路径同形。
func scanSecurityOverviewIncrementalRows(metricsDB *sql.DB, state *securityOverviewAggState) (int64, error) {
	rows, err := metricsDB.Query(`SELECT id, CAST(event_time AS TEXT) AS event_time, COALESCE(client_ip,''), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action
		FROM security_events WHERE id > ? AND event_time >= ? AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+`
		ORDER BY id ASC`, state.maxEventID, state.dayBounds[0])
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	var scanned, maxScanned int64
	for rows.Next() {
		var id int64
		var eventTime, ip, triggered, msg, action string
		if err := rows.Scan(&id, &eventTime, &ip, &triggered, &msg, &action); err != nil {
			return 0, err
		}
		scanned++
		if id > maxScanned {
			maxScanned = id
		}
		for i := range 7 {
			if eventTime >= state.dayBounds[i] && eventTime < state.dayBounds[i+1] {
				if action == "blocked" {
					state.trendBlocked[i]++
				} else if action == "logged" {
					state.trendDetected[i]++
				}
				break
			}
		}
		state.familyCounts[categorizeAttack(triggered, msg)]++
		state.stageCounts[stageCategorizeAttack(triggered, msg)]++
		if strings.TrimSpace(ip) != "" {
			acc := state.topIPs[ip]
			if action == "blocked" {
				acc.blocked++
			} else if action == "logged" {
				acc.detected++
			}
			if eventTime > acc.lastTime {
				acc.lastTime = eventTime
			}
			state.topIPs[ip] = acc
		}
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if maxScanned > state.maxEventID {
		state.maxEventID = maxScanned
	}
	return scanned, nil
}

// securityOverviewTopIPCandidateCap top-IP 候选重排的有界上限：候选集=
// topIPAccum 按 b+l 降序的前缀（天然包含本轮全部新增 IP——新增行在扫描时
// 已入账）。排名对累计单调：任何冲进 b+l top-10 的 IP 必然产生过新行并被
// 计入账本，故有界前缀外的 IP 不可能属于 top-10（严格相等不变式不受截断
// 影响）。上限只为封顶洪峰下单趟 IN 查询的参数量。
const securityOverviewTopIPCandidateCap = 500

// rerankSecurityOverviewTopIPs top-IP 重排：候选（b+l 降序、ip 升序
// tiebreak——与全量路径 SQL 的 ORDER BY 逐字对齐，并列 IP 展示顺序跨刷新
// 路径稳定）经单条有界 IN 查询重查 24h 内 recency（10m/1h/24h 三窗），
// 取前 10。idx_security_events_ip_time(client_ip, event_time DESC) 支撑
// 逐 IP 命中，24h 窗口量级可控；24h 内无行的候选 recency 归零（与全量
// 路径 GROUP BY 求和的零值形状一致）。
func rerankSecurityOverviewTopIPs(metricsDB *sql.DB, state *securityOverviewAggState, now time.Time) ([]topIPRow, error) {
	type candidate struct {
		ip                string
		blocked, detected int
		lastTime          string
	}
	candidates := make([]candidate, 0, len(state.topIPs))
	for ip, acc := range state.topIPs {
		candidates = append(candidates, candidate{ip: ip, blocked: acc.blocked, detected: acc.detected, lastTime: acc.lastTime})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].blocked+candidates[i].detected != candidates[j].blocked+candidates[j].detected {
			return candidates[i].blocked+candidates[i].detected > candidates[j].blocked+candidates[j].detected
		}
		return candidates[i].ip < candidates[j].ip
	})
	if len(candidates) > securityOverviewTopIPCandidateCap {
		candidates = candidates[:securityOverviewTopIPCandidateCap]
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	recent10m := now.UTC().Add(-10 * time.Minute).Format(securityOverviewEventTimeLayout)
	recent1h := now.UTC().Add(-time.Hour).Format(securityOverviewEventTimeLayout)
	recent24h := now.UTC().Add(-24 * time.Hour).Format(securityOverviewEventTimeLayout)
	placeholders := make([]string, len(candidates))
	args := make([]any, 0, len(candidates)+4)
	args = append(args, recent10m, recent1h, recent24h, recent24h)
	for i, cand := range candidates {
		placeholders[i] = "?"
		args = append(args, cand.ip)
	}
	rows, err := metricsDB.Query(fmt.Sprintf(`SELECT COALESCE(client_ip,''),
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END),
		SUM(CASE WHEN event_time >= ? THEN 1 ELSE 0 END)
		FROM security_events WHERE event_time >= ? AND client_ip IN (%s) AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+`
		GROUP BY client_ip`, strings.Join(placeholders, ",")), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type ipRecency struct {
		r10m, r1h, r24h int
	}
	recencyByIP := map[string]ipRecency{}
	for rows.Next() {
		var ip string
		var rec ipRecency
		if err := rows.Scan(&ip, &rec.r10m, &rec.r1h, &rec.r24h); err != nil {
			return nil, err
		}
		recencyByIP[ip] = rec
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	topRows := make([]topIPRow, 0, 10)
	for _, cand := range candidates {
		rec := recencyByIP[cand.ip]
		topRows = append(topRows, topIPRow{
			ip:        cand.ip,
			blocked:   cand.blocked,
			detected:  cand.detected,
			recent10m: rec.r10m,
			recent1h:  rec.r1h,
			recent24h: rec.r24h,
			lastTime:  cand.lastTime,
		})
		if len(topRows) == 10 {
			break
		}
	}
	return topRows, nil
}

// trendPoints 由可累加日桶装配趋势点（增量与全量共用同形状输出）。
func (s *securityOverviewAggState) trendPoints() []models.SecurityTrendPoint {
	points := make([]models.SecurityTrendPoint, 7)
	for i := range 7 {
		points[i] = models.SecurityTrendPoint{Date: s.dayLabels[i], Blocked: s.trendBlocked[i], Detected: s.trendDetected[i]}
	}
	return points
}

// cloneSecurityOverviewAggState 增量状态的独立副本：刷新轨道在副本上累加，
// 与缓存条目内状态及并发读路径零共享（map 必须逐个克隆）。
func cloneSecurityOverviewAggState(in securityOverviewAggState) securityOverviewAggState {
	out := in
	out.familyCounts = maps.Clone(in.familyCounts)
	out.stageCounts = maps.Clone(in.stageCounts)
	out.topIPs = maps.Clone(in.topIPs)
	return out
}

// computeSecurityOverviewAggregatesFull 全量重算：双路径取数（rollup/raw）+
// top-IP 攻击族细分 + 日界窗口计数与正常请求差分 + 装配，并以本次数据状态
// 铸造增量状态（水位=当时 MAX(id)、存活账本=当时全表行数）。fromRollup 由
// 调用方传入（冷启动经可用性门判定；SWR 刷新按当前模式/切换语义强制）。
// 水位元数据查询失败必须使整个构建失败——缺失水位的增量轨道会重复计数，
// 不得带病入缓存。
func computeSecurityOverviewAggregatesFull(metricsDB *sql.DB, dayStarts []time.Time, today time.Time, now time.Time, fromRollup bool) (securityOverviewAggregates, securityOverviewAggState, error) {
	// 水位元数据**先于**聚合读取：先取 MAX(id)=M，再跑聚合查询——id ≤ M 的
	// 行必然已提交、必然被聚合查询看到；M 之后插入的行 id > M，交给首次增量
	// 扫描。逆序（先聚合后取水位）会让「聚合快照后、取水位前」插入的行既
	// 不在基线又落在水位之下，永远缺计（破坏对账不变式）。
	// 存活账本必须与核对侧（refreshSecurityOverviewAggIncremental 的窗口内
	// COUNT）同口径：只数 event_time ≥ 窗口起点的行——全表 COUNT 会把窗口外
	// 旧行（90 天保留 × 7 天窗口的常态）计入账本，使删除检测每轮误命中、
	// 增量分支永不生效（回归钉测：窗口外行在场时增量必须真实生效）。
	var watermarkMaxID, watermarkTotal int64
	if err := metricsDB.QueryRow(`SELECT (SELECT COALESCE(MAX(id),0) FROM security_events), (SELECT COUNT(*) FROM security_events WHERE event_time >= ?)`, dayStarts[0].UTC().Format(securityOverviewEventTimeLayout)).Scan(&watermarkMaxID, &watermarkTotal); err != nil {
		return securityOverviewAggregates{}, securityOverviewAggState{}, err
	}
	var (
		src    securityOverviewSourceAgg
		srcErr error
	)
	if fromRollup {
		src, srcErr = loadOverviewAggregatesFromRollup(metricsDB, dayStarts, today, now)
	} else {
		src, srcErr = loadOverviewAggregatesFromRaw(metricsDB, dayStarts)
	}

	// top10 逐 IP 攻击族细分：双路径都走原始表（理由见
	// loadTopIPFamilySubdivision——有索引、有界、rollup 无对应维度）。
	familyCountsByIP, stageFamilyCountsByIP, famErr := loadTopIPFamilySubdivision(metricsDB, dayStarts[0].UTC().Format(securityOverviewEventTimeLayout), src.topRows)
	if famErr != nil && srcErr == nil {
		srcErr = famErr
	}

	// 日界窗口计数与正常请求差分（同缓存体同失效语义）：昨日窗口/正常请求
	// 查询失败与趋势聚合失败同口径上抛（不缓存失败轮，调用方聚合成 500）。
	var dayCounts securityOverviewAggregates
	ydayStart := dayStarts[5]
	todayDayStart := dayStarts[6]
	var dayErr error
	dayCounts.yesterdayBlocked, dayCounts.yesterdayDetected, dayErr = securityOverviewDayWindowCounts(metricsDB, ydayStart, todayDayStart)
	if dayErr == nil {
		// 昨日 TCP 检测：L4 信任检测（trust_detect）产 tcp+logged 形态（与
		// HTTP stage0 DetectionOnly 对齐）；无该形态时为 0。
		dayCounts.yesterdayDetectedTCP, dayErr = securityOverviewDayWindowTCPAction(metricsDB, ydayStart, todayDayStart, "logged")
	}
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}
	dayCounts.yesterdayBlockedTCP, dayErr = securityOverviewDayWindowTCPAction(metricsDB, ydayStart, todayDayStart, "blocked")
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}
	dayCounts.todayBlockedTCP, dayErr = securityOverviewDayWindowTCPAction(metricsDB, todayDayStart, time.Time{}, "blocked")
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}
	dayCounts.todayDetectedTCP, dayErr = securityOverviewDayWindowTCPAction(metricsDB, todayDayStart, time.Time{}, "logged")
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}
	dayCounts.normalTodayHTTP, dayCounts.normalYesterdayHTTP, dayErr = securityOverviewNormalHTTPDiff(metricsDB, ydayStart, todayDayStart)
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}
	dayCounts.normalTodayTCP, dayCounts.normalYesterdayTCP, dayErr = securityOverviewNormalTCPDiff(metricsDB, ydayStart, todayDayStart)
	if dayErr != nil && srcErr == nil {
		srcErr = dayErr
	}

	data := assembleSecurityOverviewAggregates(dayStarts, src, familyCountsByIP, stageFamilyCountsByIP, dayCounts)
	if srcErr != nil {
		return data, securityOverviewAggState{}, srcErr
	}
	state := newSecurityOverviewAggState(dayStarts, fromRollup, src, dayCounts)
	state.maxEventID, state.seenTotal = watermarkMaxID, watermarkTotal
	if !fromRollup {
		// raw 轨道：top-IP 账本必须播种**窗口内全量 per-IP 聚合**（有界 500），
		// 不得只灌展示用 top-10——基线 11 名外的 IP 靠新增事件冲榜时，账本里
		// 没有它的历史累计会使增量 top-10 漏列或计数缩水（回归钉测：冲榜形态）。
		// rollup 轨道增量不启用（rollup 读路径与原始表规模解耦），top-10 播种
		// 仅作状态对齐，无增量消费面。
		seedRows, seedErr := loadOverviewTopIPSeed(metricsDB, dayStarts[0].UTC().Format(securityOverviewEventTimeLayout))
		if seedErr != nil {
			return data, securityOverviewAggState{}, seedErr
		}
		for _, row := range seedRows {
			state.topIPs[row.ip] = topIPAccum{blocked: row.blocked, detected: row.detected, lastTime: row.lastTime}
		}
	}
	return data, state, nil
}

// loadOverviewTopIPSeed 窗口内全量 per-IP 聚合（增量账本播种源，有界 500）：
// 谓词/形状与 loadOverviewAggregatesFromRaw 的 top-IP 查询同口径，仅去展示
// 截断（LIMIT 10）——账本必须覆盖「当前排名之外、靠新增事件冲榜」的候选。
func loadOverviewTopIPSeed(metricsDB *sql.DB, windowStartUTC string) ([]topIPRow, error) {
	rows, err := metricsDB.Query(`SELECT COALESCE(client_ip,''),
		SUM(CASE WHEN action='blocked' THEN 1 ELSE 0 END) as b,
		SUM(CASE WHEN action='logged' THEN 1 ELSE 0 END) as l,
		MAX(event_time) as last_time
		FROM security_events WHERE event_time >= ? AND TRIM(COALESCE(client_ip,'')) <> '' AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+` GROUP BY client_ip ORDER BY b + l DESC, client_ip ASC LIMIT 500`, windowStartUTC)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seed := make([]topIPRow, 0, 64)
	for rows.Next() {
		var row topIPRow
		if err := rows.Scan(&row.ip, &row.blocked, &row.detected, &row.lastTime); err != nil {
			return nil, err
		}
		seed = append(seed, row)
	}
	return seed, rows.Err()
}

// newSecurityOverviewAggState 由全量聚合结果铸造增量状态初值：日桶边界/标签、
// 可累加结构（趋势桶/攻击族/top-IP 账本）与不可变窗口值。水位与存活账本由
// 调用方回填（必须取自聚合读取之前的同一元数据查询）。
func newSecurityOverviewAggState(dayStarts []time.Time, fromRollup bool, src securityOverviewSourceAgg, dayCounts securityOverviewAggregates) securityOverviewAggState {
	state := securityOverviewAggState{
		builtFromRollup:      fromRollup,
		familyCounts:         make(map[string]int, len(src.familyCounts)),
		stageCounts:          make(map[string]int, len(src.stageCounts)),
		topIPs:               make(map[string]topIPAccum, len(src.topRows)),
		yesterdayBlocked:     dayCounts.yesterdayBlocked,
		yesterdayDetected:    dayCounts.yesterdayDetected,
		yesterdayBlockedTCP:  dayCounts.yesterdayBlockedTCP,
		yesterdayDetectedTCP: dayCounts.yesterdayDetectedTCP,
		normalYesterdayHTTP:  dayCounts.normalYesterdayHTTP,
		normalYesterdayTCP:   dayCounts.normalYesterdayTCP,
	}
	for i := range 8 {
		state.dayBounds[i] = dayStarts[i].UTC().Format(securityOverviewEventTimeLayout)
	}
	for i := range 7 {
		state.dayLabels[i] = dayStarts[i].In(dayStarts[0].Location()).Format("2006-01-02")
		state.trendBlocked[i] = src.trend[i].Blocked
		state.trendDetected[i] = src.trend[i].Detected
	}
	maps.Copy(state.familyCounts, src.familyCounts)
	maps.Copy(state.stageCounts, src.stageCounts)
	for _, row := range src.topRows {
		state.topIPs[row.ip] = topIPAccum{blocked: row.blocked, detected: row.detected, lastTime: row.lastTime}
	}
	return state
}

// assembleSecurityOverviewAggregates 单源装配段：趋势/Top-IP/攻击族中间数据
// + 攻击族细分 + 日界窗口计数 → 展示快照。全量重算与增量刷新共用（排序/
// 截断/富化逻辑单源，两条轨道逐字段同形——对账钉测的相等性由此保证）。
func assembleSecurityOverviewAggregates(dayStarts []time.Time, src securityOverviewSourceAgg, familyCountsByIP, stageFamilyCountsByIP map[string]map[string]int, dayCounts securityOverviewAggregates) securityOverviewAggregates {
	topIPs := make([]models.SecurityTopIP, 0, len(src.topRows))
	for _, row := range src.topRows {
		topIPs = append(topIPs, models.SecurityTopIP{
			IP:              row.ip,
			IPLocation:      enrichIPLocation(row.ip),
			Blocked:         row.blocked,
			Detected:        row.detected,
			Recent10m:       row.recent10m,
			Recent1h:        row.recent1h,
			Recent24h:       row.recent24h,
			LastTime:        row.lastTime,
			AttackType:      joinDistinctFamilies(familyCountsByIP[row.ip]),
			AttackTypeStage: joinDistinctFamilies(stageFamilyCountsByIP[row.ip]),
		})
	}

	attackTypesStage := make([]models.SecurityAttackType, 0, len(src.stageCounts))
	for name, value := range src.stageCounts {
		attackTypesStage = append(attackTypesStage, models.SecurityAttackType{Name: name, Value: value})
	}
	// 值相等时按名称升序 tiebreak（map 迭代序随机，防轮询抖动）。
	sort.Slice(attackTypesStage, func(i, j int) bool {
		if attackTypesStage[i].Value != attackTypesStage[j].Value {
			return attackTypesStage[i].Value > attackTypesStage[j].Value
		}
		return attackTypesStage[i].Name < attackTypesStage[j].Name
	})

	attackTypes := make([]models.SecurityAttackType, 0, len(src.familyCounts))
	for name, value := range src.familyCounts {
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

	return securityOverviewAggregates{
		trend:                src.trend,
		topIPs:               topIPs,
		attackTypes:          attackTypes,
		attackTypesStage:     attackTypesStage,
		todayBlockedTCP:      dayCounts.todayBlockedTCP,
		todayDetectedTCP:     dayCounts.todayDetectedTCP,
		yesterdayBlocked:     dayCounts.yesterdayBlocked,
		yesterdayBlockedTCP:  dayCounts.yesterdayBlockedTCP,
		yesterdayDetected:    dayCounts.yesterdayDetected,
		yesterdayDetectedTCP: dayCounts.yesterdayDetectedTCP,
		normalTodayHTTP:      dayCounts.normalTodayHTTP,
		normalTodayTCP:       dayCounts.normalTodayTCP,
		normalYesterdayHTTP:  dayCounts.normalYesterdayHTTP,
		normalYesterdayTCP:   dayCounts.normalYesterdayTCP,
	}
}

// cloneSecurityOverviewAggregates 复制四组切片（元素为值类型，浅复制切片即
// 深拷贝）——缓存读写两侧都必须用副本，缓存条目与响应构造不得共享底层数组。
// 日界窗口/差分字段为值类型，随结构体赋值自然复制（不得遗漏——漏带会让
// 缓存命中路径返回零值计数）。
func cloneSecurityOverviewAggregates(in securityOverviewAggregates) securityOverviewAggregates {
	out := securityOverviewAggregates{
		trend:                slices.Clone(in.trend),
		topIPs:               slices.Clone(in.topIPs),
		attackTypes:          slices.Clone(in.attackTypes),
		attackTypesStage:     slices.Clone(in.attackTypesStage),
		todayBlockedTCP:      in.todayBlockedTCP,
		todayDetectedTCP:     in.todayDetectedTCP,
		yesterdayBlocked:     in.yesterdayBlocked,
		yesterdayBlockedTCP:  in.yesterdayBlockedTCP,
		yesterdayDetected:    in.yesterdayDetected,
		yesterdayDetectedTCP: in.yesterdayDetectedTCP,
		normalTodayHTTP:      in.normalTodayHTTP,
		normalTodayTCP:       in.normalTodayTCP,
		normalYesterdayHTTP:  in.normalYesterdayHTTP,
		normalYesterdayTCP:   in.normalYesterdayTCP,
	}
	return out
}

// securityOverviewTodayHumanCounts 今日人机挑战三态计数（原始表直算）：
// 挑战是独立结果（action=challenged），不计入拦截/检测；规则 id 区分通过/失败。
// 人机事件在插件侧按 IP 每分钟至多 1 条，量级可控，不参与 rollup。
func securityOverviewTodayHumanCounts(database *sql.DB, todayStart time.Time) (challenged, passed, failed int, err error) {
	rows, qerr := database.Query(`SELECT rule_triggered, COUNT(*) FROM security_events
		WHERE action='challenged' AND event_time >= ? AND rule_triggered IN ('human_challenge','human_pass','human_failed')
		GROUP BY rule_triggered`, todayStart.UTC().Format("2006-01-02 15:04:05"))
	if qerr != nil {
		return 0, 0, 0, qerr
	}
	defer rows.Close()
	for rows.Next() {
		var rule string
		var n int
		if err := rows.Scan(&rule, &n); err != nil {
			return 0, 0, 0, err
		}
		switch rule {
		case "human_challenge":
			challenged = n
		case "human_pass":
			passed = n
		case "human_failed":
			failed = n
		}
	}
	if err := rows.Err(); err != nil {
		return 0, 0, 0, err
	}
	return challenged, passed, failed, nil
}
