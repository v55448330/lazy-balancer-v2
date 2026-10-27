package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/geoipnames"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

// 威胁大屏（ThreatScreen）数据端点——只读聚合，复用安全总览查询核心
// （security_events 单表 + categorizeAttack 家族单源 + enrichIPLocation 归属
// 地单源），从节点可读（不挂 requireMaster）。

// threatScreenMaxHours hours 参数上限（30 天）——超出回退默认 24h，与非法
// 值同口径（大屏固定 24h 消费，参数仅为后续扩展保留）。
const threatScreenMaxHours = 24 * 30

// threatRollupRewindWindowHours 回退水位默认窗口 = warmer 预热窗口 = 大屏
// 7d 展示窗口：重启后 requestedHours=0 时，48h+ 积压回放仍须触发重算，
// 否则覆盖水位推进后 7d 永久少计。
const threatRollupRewindWindowHours = 24 * 7

// threatActiveSourceWindow 活跃攻击源窗口（设计定稿）：近 10 分钟去重 client_ip。
const threatActiveSourceWindow = 10 * time.Minute

// threatRuleNamePointQueriesForTest 仅测试观测「自定义规则名单键点查主库」
// 的次数：大屏标签解析必须走批量预取（生产零消费，仅原子自增）。
var threatRuleNamePointQueriesForTest atomic.Int64

// describeThreatRuleNameWithNames 把「命中规则」维度的原始 SecRule id 翻译为可读
// 标签；customNames 非 nil 时自定义规则名一律取预取结果（不再逐键点查主库）
// ——nil 键表示该 id 在 security_custom_rules 中不存在（回退
// 「自定义规则（#id）」）。大屏直接展示本标签：事件里的 rule_triggered 是
// coraza SecRule id，裸数字对用户无意义（阶段 1 预检为合成 id、CRS 为 9xxxxx、
// 自定义规则为 DB id+10000 或可回解的 OR 分支、限流固定 429）。解析失败时回退「可读类别 + 原始
// id」，绝不静默丢 id——排障需要 id 才能对回规则文件。
func describeThreatRuleNameWithNames(key string, customNames map[int]string) string {
	if key == "" {
		return ""
	}
	n, err := strconv.Atoi(key)
	if err != nil {
		// 非数字（历史事件回退的是负载规则名）原样展示。
		return key
	}
	switch n {
	case 2:
		return "IP 访问控制拦截（#2）"
	case 4:
		return "IP 黑名单（#4）"
	case 7:
		return "IP 白名单拒绝（#7）"
	case 429:
		return "限流触发（#429）"
	}
	// 其余固定 id 的族标签由 legacyRuleFamilies 派生（与 triggerTypeForRule/
	// attackFamilyClassOf/筛选表同源）：id:5 是「绕过模式占位」的信任名单
	// DetectionOnly 规则（id:3 的同族变体）；威胁情报库的历史段是 id:14，
	// 二者不得共用一个标签。IP 族三个 id 的细标签差异较大（拦截/黑名单/白名单），
	// 已在上面单独给出。id:11（请求体解析失败）必须与事件列表
	// triggerTypeForRule 的「请求体异常」同词——漏掉该类会让大屏显示裸数字。
	switch legacyRuleFamilyOf(n).class {
	case attackFamilyTrust:
		return "信任名单检测（#" + key + "）"
	case attackFamilyThreatIntel:
		return "威胁情报库（#" + key + "）"
	case attackFamilyGeoIP:
		return "地域拦截（#" + key + "）"
	case attackFamilyBodyAnomaly:
		return "请求体异常（#" + key + "）"
	}
	// 阶段 1 预检段经 services.DecodePrecheckRuleID 单一事实源解码
	// （段界字面量禁止复写——段基址调整时 handlers 不得静默分叉）。
	if family, policyID, _, ok := services.DecodePrecheckRuleID(key); ok {
		switch family {
		case services.PrecheckRuleFamilyGeoIP:
			if policyID > 0 {
				return fmt.Sprintf("地域拦截（策略 #%d）", policyID)
			}
		case services.PrecheckRuleFamilyCrawlerExempt:
			return "爬虫校验（#" + key + "）"
		case services.PrecheckRuleFamilyCrawlerSpoof:
			return "爬虫伪装拦截（#" + key + "）"
		}
	}
	// 属主不可解码的段内边界形态（p=0，发射侧已拒绝、生产不可达）：
	// 按段归类展示，不猜属主（归因侧禁令同口径）。
	switch services.PrecheckRuleFamilyOf(n) {
	case services.PrecheckRuleFamilyCrawlerExempt:
		return "爬虫校验（#" + key + "）"
	case services.PrecheckRuleFamilyCrawlerSpoof:
		return "爬虫伪装拦截（#" + key + "）"
	}
	if parentID, ok := services.DecodeCustomRuleEmitID(n); ok {
		if customNames != nil {
			if name, ok := customNames[parentID]; ok && strings.TrimSpace(name) != "" {
				return fmt.Sprintf("%s（#%s）", strings.TrimSpace(name), key)
			}
			return "自定义规则（#" + key + "）"
		}
		if db.DB != nil {
			threatRuleNamePointQueriesForTest.Add(1)
			var name string
			if err := db.DB.QueryRow(`SELECT name FROM security_custom_rules WHERE id=?`, parentID).Scan(&name); err == nil && strings.TrimSpace(name) != "" {
				return fmt.Sprintf("%s（#%s）", strings.TrimSpace(name), key)
			}
		}
		return "自定义规则（#" + key + "）"
	}
	switch {
	case n >= services.SyntheticCustomRuleIDBase:
		// 无 id 的内嵌自定义规则（v2.1.0 前遗留）按合成 emit id 发射：
		// security_custom_rules 无对应行可查，但语义仍属自定义规则族——
		// 直接回裸数字会与事件列表 trigger_type 的「WAF·自定义」分叉。
		return "自定义规则（#" + key + "）"
	case n >= services.GeoIPPrecheckSegmentLimit && n < services.SyntheticCustomRuleIDBase:
		if idx := services.GetCRSRuleIndex(); idx != nil {
			if entry := idx.Find(key); entry != nil && strings.TrimSpace(entry.Msg) != "" {
				return fmt.Sprintf("%s（#%s）", strings.TrimSpace(entry.Msg), key)
			}
		}
		return "CRS 规则（#" + key + "）"
	}
	return key
}

// labeledThreatRuleCounts 把规则 id 维度计数换成可读标签维度（同标签合并计数），
// 供大屏 Top 榜直接展示。自定义规则名一次分块 IN 预取（宽窗口下 distinct 规则
// 键可达自定义规则总量 200，逐键点查会在缓存 miss 时引入 ~200 次串行主库查询）。
func labeledThreatRuleCounts(counts map[string]int) map[string]int {
	customNames := loadThreatCustomRuleNames(counts)
	labeled := make(map[string]int, len(counts))
	for key, value := range counts {
		labeled[describeThreatRuleNameWithNames(key, customNames)] += value
	}
	return labeled
}

// loadThreatCustomRuleNames 预取计数键里普通/ OR 分支自定义规则 id 对应的父规则名：
// 一次分块 IN（≤500/批，与 validateIPListRefsExistence 同口径）。
// 无自定义规则键返回 nil（describe 走单键路径，行为与旧实现一致）。
func loadThreatCustomRuleNames(counts map[string]int) map[int]string {
	if db.DB == nil || len(counts) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(counts))
	for key := range counts {
		n, err := strconv.Atoi(key)
		if err != nil {
			continue
		}
		parentID, ok := services.DecodeCustomRuleEmitID(n)
		if !ok {
			continue
		}
		ids = append(ids, int64(parentID))
	}
	if len(ids) == 0 {
		return nil
	}
	names := make(map[int]string, len(ids))
	for _, chunk := range chunkIDs(ids, 500) {
		rows, err := db.DB.Query("SELECT id, name FROM security_custom_rules WHERE id IN ("+chunk.placeholders+")", chunk.args...)
		if err != nil {
			// 预取失败回退逐键路径（DB 故障时同样返回不可读标签，不扩大影响面）。
			services.Logf("warn", "大屏规则名批量预取失败，回退逐键解析: %v", err)
			return nil
		}
		for rows.Next() {
			var id int
			var name string
			if err := rows.Scan(&id, &name); err != nil {
				rows.Close()
				services.Logf("warn", "大屏规则名批量预取扫描失败，回退逐键解析: %v", err)
				return nil
			}
			names[id] = name
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			services.Logf("warn", "大屏规则名批量预取迭代失败，回退逐键解析: %v", err)
			return nil
		}
		rows.Close()
	}
	return names
}

// topThreatEntries 计数 map → 前 n 条（值降序；同值按名称升序——确定性输出，
// 大屏 30s 轮询重渲染名次不抖动）。
func topThreatEntries(counts map[string]int, n int) []models.SecurityAttackType {
	entries := make([]models.SecurityAttackType, 0, len(counts))
	for name, value := range counts {
		entries = append(entries, models.SecurityAttackType{Name: name, Value: value})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Value != entries[j].Value {
			return entries[i].Value > entries[j].Value
		}
		return entries[i].Name < entries[j].Name
	})
	if len(entries) > n {
		entries = entries[:n]
	}
	return entries
}

// threatRollupMu 懒固化互斥（每次固化幂等 DELETE+INSERT）；ensure 在批次间
// 主动释放本锁，摄取钩子用 TryLock 排队而不阻塞请求路径。
var threatRollupMu sync.Mutex

// threatRollupEnsureMu 串行化 ensure 调用（与 threatRollupMu 分层）：批次间
// 释放文件/聚合锁但仍只允许一个 ensure 推进覆盖状态。
var threatRollupEnsureMu sync.Mutex

// threatRollupRewindPending 待处理回退目标（UTC 分钟 Unix 秒，0=无）。钩子
// 抢不到锁时置最小值，由下一次 ensure 批次间隙/入口合并处理，避免摄取提交
// 被长回填阻塞。
var threatRollupRewindPending atomic.Int64

// 待处理的「原地改判」分钟集合：改判是对既有行 UPDATE（事件 id 不变），
// 增量重固扫不到，必须全量重算；全量重算时「已计入行」与「迟到行」靠回退
// 时落库的迟到基线区分（见 services.ThreatRollupLateBaselinePrefix）。
// 钩子抢不到锁时与回退目标一起排队，由下一次 ensure 合并执行。
var (
	threatRollupReclassifyMu      sync.Mutex
	threatRollupReclassifyPending = map[int64]struct{}{}
)

var errThreatRollupRestart = errors.New("threat rollup restart after concurrent rewind")

// threatRollupRewindApplyInLock 是回退落库的单点调用入口（调用方已持
// threatRollupMu）：真实失败来自 DB 写锁/BUSY/磁盘满，构造代价高，测试经此
// 缝注入失败形态验证「失败必须回填 + 有界重试」。
var threatRollupRewindApplyInLock = threatRollupRewindToInLock

var (
	// threatRollupRewindApplyAttempts 是一次 ensure 轮内对回退队列的最大应用
	// 尝试次数：应用失败时队列已回填，若不像旧实现那样「失败也报已处理」，
	// ensure 就不会立即 continue；但仍需少量重试消化瞬时锁冲突，超过即把
	// 失败交回调用方（warmer 的 60s 节拍/请求路径既有告警）。
	threatRollupRewindApplyAttempts = 2
	// threatRollupRewindApplyBackoff 是重试前的线性退避基数（第 n 次重试等待
	// n×该值）；用 var 供测试置零。
	threatRollupRewindApplyBackoff = 50 * time.Millisecond
)

// threatScreenNow 时钟缝（可控时间轴验证「上一分钟在完整后
// 至少终固一次」——迟到写入必须被下一次固化覆盖）。
var threatScreenNow = func() time.Time { return time.Now().UTC() }

const (
	// threatRollupWatermarkKey 已覆盖区间的**最新**完整分钟（metrics_state 键）；
	// threatRollupCoveredFromKey 已覆盖区间的**最旧**分钟（空覆盖=lastComplete）。
	// 键名单源在 services：保留清理要读同一批键判定预聚合回填是否就绪。
	threatRollupWatermarkKey   = services.ThreatRollupWatermarkKey
	threatRollupCoveredFromKey = services.ThreatRollupCoveredFromKey
	// threatRollupBatchMinutes 单事务回填分钟数。
	threatRollupBatchMinutes = 60
	// threatRollupMaxBatchesPerCall 单次请求最多提交的事务批数（25 批 =
	// 24h 回填 + 最新两分钟段）——空库首屏先返回部分，后续轮询按水位续做，
	// 避免单请求长时间占锁/占连接。默认 24h 窗口一轮完成；更大窗口跨请求
	// 续做。
	threatRollupMaxBatchesPerCall = 25
	// threatRollupRepairMinutes 迟到事件回填窗口（≥摄取停顿 + 一轮 warmer）。
	threatRollupRepairMinutes = 10
	// threatRollupTargetReadyKey 目标维度 rollup 就绪标记：
	// 升级后缺失 → 强制重置覆盖区间重固——否则既有 coverage 宣称已覆盖，
	// 历史窗口的目标计数永久缺失（top_targets 与其余卡片窗口分裂）。
	threatRollupTargetReadyKey = services.ThreatRollupTargetReadyKey
	// threatRollupGeoIPGenerationKey 固化时使用的归属地库代际
	// 与当前代际不一致 → 重固窗口（库恢复后历史空归属地维度自愈）。
	threatRollupGeoIPGenerationKey = "threat_rollup_geoip_generation"
	// threatRollupClassifierVersionKey / threatRollupClassifierVersion 分类器口径
	// 代际：rollup 固化的是 categorizeAttack 的分类结果，而重建触发
	// 只覆盖目标维度（target_read/geoip 代际）——分类逻辑跨版本调整后，已固化
	// 分钟的 family 仍是旧口径且不会重算，大屏 top_attack_types/attack_type_share
	// 与安全总览（直读原始表、用当前分类）在同一窗口分裂。分类口径变更必须
	// 递增 threatRollupClassifierVersion，代际不一致按空覆盖重固。
	threatRollupClassifierVersionKey = "threat_rollup_classifier_version"
	// v3：固定 id:5 归信任名单（id→家族表统一：此前分桶误记 IP 访问控制）。
	threatRollupClassifierVersion = "3"
	// threatRollupPredicateVersionKey / threatRollupPredicateVersion 固化口径
	// 代际：保留地址排除谓词与攻击口径（爬虫放行不计入攻击）都会让已固化
	// 分钟的口径静默过时（水位机制只保护迟到事件，不保护语义变更）——口径
	// 变更必须 bump 本版本，代际不一致按空覆盖重固。
	// v2：爬虫放行的 logged 事件不再计入攻击面（总量/拦截率分母/攻击族/
	// Top 规则/被攻击目标）。
	threatRollupPredicateVersionKey = "threat_rollup_predicate_version"
	threatRollupPredicateVersion    = "2"
	// threatRollupActionEnumVersionKey / threatRollupActionEnumVersion 事件
	// action 取值枚举（blocked/logged 族）的口径代际：枚举/命名变更必须
	// bump，否则大屏 blocked/总量比例静默漂移。
	threatRollupActionEnumVersionKey = "threat_rollup_action_enum_version"
	threatRollupActionEnumVersion    = "1"
	// threatRollupRebuildFromKey 未完成的全量重建意图起点
	// 目标维度就绪标记缺失 / GeoIP 代际变化的触发窗口起点。意图存在期间每次
	// 固化都按 fullRebuild 处理并把回填下界扩到该起点，覆盖底端推进到起点后
	// 删除——修复「单次调用最多 23h，其余分钟的增量路径无新事件即 no-op，
	// 目标维度/归属地永不补算、就绪标记却已写入」的自愈中断。
	threatRollupRebuildFromKey = services.ThreatRollupRebuildFromKey
	// threatRollupStaleAfter 固化陈旧阈值：warmer 每 60s
	// 一轮，超过 3 分钟无成功固化视为陈旧——请求路径改为同步固化，持续失败
	// 以 500 显式暴露，不得把旧值伪装成最新 200。
	threatRollupStaleAfter = 3 * time.Minute
)

// loadThreatRollupState 读持久分钟状态（无行/空值/损坏 = 未初始化）。
func loadThreatRollupState(database *sql.DB, key string) (time.Time, bool, error) {
	raw, ok, err := loadThreatRollupRawState(database, key)
	if err != nil || !ok {
		return time.Time{}, false, err
	}
	parsed, perr := time.ParseInLocation("2006-01-02 15:04", raw, time.UTC)
	if perr != nil {
		// 状态损坏按「未初始化」处理（回填有界且幂等，重建成本可控）。
		return time.Time{}, false, nil
	}
	return parsed, true, nil
}

// loadThreatRollupRawState 读 metrics_state 原始值（无行/空值 = 未初始化）。
func loadThreatRollupRawState(database *sql.DB, key string) (string, bool, error) {
	var raw string
	err := database.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, key).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if strings.TrimSpace(raw) == "" {
		return "", false, nil
	}
	return raw, true, nil
}

// threatRollupRewindMinute 钳制回退目标到当前展示窗口下界：窗口外积压无需
// 重算历史 rollup（用户不可见），且避免把水位推到 emptyCoverage 判定之前
// 导致每次摄取都整窗重固。
func threatRollupRewindMinute(minute time.Time) time.Time {
	hours := threatRollupRewindWindowHours
	if req := threatRollupRequestedHoursLimit(); req > hours {
		hours = req
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	horizon := threatScreenNow().UTC().Add(-time.Minute).Truncate(time.Minute).Add(-time.Duration(hours) * time.Hour)
	minute = minute.UTC().Truncate(time.Minute)
	if minute.Before(horizon) {
		minute = horizon
	}
	return minute
}

func queueThreatRollupRewind(minute time.Time) {
	ts := minute.UTC().Truncate(time.Minute).Unix()
	for {
		cur := threatRollupRewindPending.Load()
		if cur != 0 && cur <= ts {
			return
		}
		if threatRollupRewindPending.CompareAndSwap(cur, ts) {
			return
		}
	}
}

// queueThreatRollupReclassify 排队原地改判分钟（幂等；只保留分钟粒度）。
func queueThreatRollupReclassify(minutes []time.Time) {
	if len(minutes) == 0 {
		return
	}
	threatRollupReclassifyMu.Lock()
	defer threatRollupReclassifyMu.Unlock()
	for _, m := range minutes {
		if m.IsZero() {
			continue
		}
		threatRollupReclassifyPending[m.UTC().Truncate(time.Minute).Unix()] = struct{}{}
	}
}

func takeThreatRollupReclassifyPending() []time.Time {
	threatRollupReclassifyMu.Lock()
	defer threatRollupReclassifyMu.Unlock()
	if len(threatRollupReclassifyPending) == 0 {
		return nil
	}
	out := make([]time.Time, 0, len(threatRollupReclassifyPending))
	for ts := range threatRollupReclassifyPending {
		out = append(out, time.Unix(ts, 0).UTC())
	}
	threatRollupReclassifyPending = map[int64]struct{}{}
	return out
}

// applyPendingThreatRollupRewindInLock 消费并应用待处理回退队列（调用方持锁）。
// 返回值：attempted=队列确有可消费项；succeeded=应用全部成功（无可消费项时
// 视为成功）。失败时已消费条目**已回填**，由下一次 TryLock 成功者重试。
func applyPendingThreatRollupRewindInLock() (attempted, succeeded bool) {
	ts := threatRollupRewindPending.Swap(0)
	reclassifyMinutes := takeThreatRollupReclassifyPending()
	if ts == 0 && len(reclassifyMinutes) == 0 {
		return false, true
	}
	var minute time.Time
	if ts != 0 {
		minute = time.Unix(ts, 0).UTC()
	}
	if threatRollupRewindApplyInLock(minute, reclassifyMinutes) {
		return true, true
	}
	// 失败回填：队列已被消费（Swap/整表置空），而改判是 UPDATE（事件 id 不变），
	// 增量重固按 id>高水位永远扫不到——不回填则该分钟的 blocked/logged 口径
	// 永久陈旧到下一次代际全量重固。回填保持幂等（minute 取更早者、改判分钟
	// 是集合），下一次 drain/TryLock 成功者重试。
	if !minute.IsZero() {
		queueThreatRollupRewind(minute)
	}
	queueThreatRollupReclassify(reclassifyMinutes)
	return true, false
}

// ThreatRollupRewindTo 摄取提交后回退 rollup 覆盖水位。
// minute=本批需要重固的最旧分钟（UTC；零值=本批只有原地改判）。
// reclassifyMinutes=本批对既有行原地改判（UPDATE，事件 id 不变）的分钟。
// 若 minute 落在已覆盖区间内（停机/升级积压、轮转补采），把 last_fixed 回退
// 到 minute-1——下一次 ensureThreatRollup 从该分钟起重固到窗口末端（幂等）。
// 普通插入分钟保留分钟事件高水位：迟到行 id 单调更大，增量重固即可合并；
// 原地改判分钟需全量重算，回退时把其高水位搬进迟到基线后再删键——否则
// 全量重算在「原始行被裁剪/含旧口径行」形态下 newTotal<oldTotal，迟到行会
// 被永久丢弃（高水位已被抹掉，后续增量也再扫不到）。
// 不得阻塞摄取提交——warmer 批次期间 TryLock 失败时仅排队，
// 由 ensure 的批次间隙/下一次 warmer 合并执行；窗口外目标钳制到展示下界。
func ThreatRollupRewindTo(minute time.Time, reclassifyMinutes []time.Time) {
	if db.MetricsDB == nil {
		return
	}
	if !minute.IsZero() {
		minute = threatRollupRewindMinute(minute)
	}
	if minute.IsZero() && len(reclassifyMinutes) == 0 {
		return
	}
	if !threatRollupMu.TryLock() {
		if !minute.IsZero() {
			queueThreatRollupRewind(minute)
		}
		queueThreatRollupReclassify(reclassifyMinutes)
		return
	}
	defer threatRollupMu.Unlock()
	applyPendingThreatRollupRewindInLock()
	if threatRollupRewindApplyInLock(minute, reclassifyMinutes) {
		return
	}
	// 直通路径同样必须消费回退返回值（与队列路径同实现）：失败即回填——水位
	// 不回退、原地改判分钟不进全量重算，该分钟口径会陈旧到下一次代际全量
	// 重固（改判是 UPDATE，id 不变，增量重固永远扫不到）。回填幂等，由下一次
	// drain/TryLock 成功者重试。
	if !minute.IsZero() {
		queueThreatRollupRewind(minute)
	}
	queueThreatRollupReclassify(reclassifyMinutes)
}

// drainThreatRollupRewindPending 由 ensure 在批次间隙调用：尝试一次性应用待
// 处理回退队列。返回值：
//   - attempted=false：无可消费项，或抢不到锁（留待下一次 ensure/下一轮节拍）；
//   - succeeded=true：可消费项全部应用成功（或本来就没有）。
//
// 应用失败时队列已由 applyPending 回填，调用方**不得**把它当作「已处理一轮」
// ——否则 ensure 会立刻重新固化并重试，形成无退避、无上限的紧凑循环（DB 写
// 锁/BUSY/磁盘满时每轮一次事务 + 一条 warn，warmer 协程被粘住）。
func drainThreatRollupRewindPending() (attempted, succeeded bool) {
	if threatRollupRewindPending.Load() == 0 && !hasPendingThreatRollupReclassify() {
		return false, true
	}
	if !threatRollupMu.TryLock() {
		return false, false
	}
	defer threatRollupMu.Unlock()
	return applyPendingThreatRollupRewindInLock()
}

func hasPendingThreatRollupReclassify() bool {
	threatRollupReclassifyMu.Lock()
	defer threatRollupReclassifyMu.Unlock()
	return len(threatRollupReclassifyPending) > 0
}

// 返回值：false=本次未完成（DB 读/写/提交失败），调用方负责把已消费的队列入参
// 回填重试。true 含「无需回退」的早退（从未固化/该分钟未被固化）。
func threatRollupRewindToInLock(minute time.Time, reclassifyMinutes []time.Time) bool {
	database := db.MetricsDB
	if database == nil {
		return true
	}
	lastFixed, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil {
		services.Logf("warn", "threat rollup rewind: read watermark failed: %v", err)
		return false
	}
	if !okFixed {
		return true // 从未固化：稍后的全量固化天然包含这些分钟
	}
	const minuteLayout = "2006-01-02 15:04"
	// 覆盖水位回退目标：minute-1（零值=本批只有原地改判，不动水位）。
	var target time.Time
	rewindCoverage := !minute.IsZero() && lastFixed.After(minute.UTC().Truncate(time.Minute).Add(-time.Minute))
	if rewindCoverage {
		target = minute.UTC().Truncate(time.Minute).Add(-time.Minute)
	}
	// 已固化过的原地改判分钟：高水位搬进迟到基线后再删（键值即「已计入行」
	// 的最大 id）。尚未固化的分钟无需处理——随后首次固化就是全量重算。
	baselines := make([]time.Time, 0, len(reclassifyMinutes))
	for _, m := range reclassifyMinutes {
		if m.IsZero() {
			continue
		}
		m = m.UTC().Truncate(time.Minute)
		if m.After(lastFixed) {
			continue
		}
		baselines = append(baselines, m)
	}
	if !rewindCoverage && len(baselines) == 0 {
		return true // 该分钟尚未被固化，无需回退
	}
	tx, err := database.Begin()
	if err != nil {
		services.Logf("warn", "threat rollup rewind: begin transaction failed: %v", err)
		return false
	}
	defer func() { _ = tx.Rollback() }() // 已 Commit 后为 no-op
	for _, m := range baselines {
		minuteStr := m.Format(minuteLayout)
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value)
			SELECT ?, value FROM metrics_state WHERE key=?
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			services.ThreatRollupLateBaselinePrefix+minuteStr, services.ThreatRollupEventHighwaterPrefix+minuteStr); err != nil {
			services.Logf("warn", "threat rollup rewind: save late baseline failed: %v", err)
			return false
		}
		if _, err := tx.Exec(`DELETE FROM metrics_state WHERE key=?`, services.ThreatRollupEventHighwaterPrefix+minuteStr); err != nil {
			services.Logf("warn", "threat rollup rewind: drop event highwater failed: %v", err)
			return false
		}
	}
	if rewindCoverage {
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupWatermarkKey, target.Format(minuteLayout)); err != nil {
			services.Logf("warn", "threat rollup rewind: write watermark failed: %v", err)
			return false
		}
	}
	if err := tx.Commit(); err != nil {
		services.Logf("warn", "threat rollup rewind: commit failed: %v", err)
		return false
	}
	if rewindCoverage {
		services.Logf("info", "threat rollup rewind: 摄取补齐历史分钟 %s，覆盖水位回退为 %s（下一次固化重算该段）",
			minute.UTC().Truncate(time.Minute).Format(minuteLayout), target.Format(minuteLayout))
	}
	if len(baselines) > 0 {
		services.Logf("info", "threat rollup rewind: %d 个原地改判分钟转全量重算（迟到基线已留底）",
			len(baselines))
	}
	return true
}

// ensureThreatRollup 按需固化 rollup（幂等、自愈、可跨请求续做）：
//
//	水位持久化在 metrics_state——空分钟同样推进，不再用数据行
//	  MAX(minute) 反推（空分钟不产行会让水位停滞）；
//	每次固化集合恒含 lastComplete 与 currentMinute——上一完整
//	  分钟在首次固化后仍可能被迟到写入补充，必须至少终固一次；当前分钟恒
//	  重固化（recent_rate 等「最近 N 分钟」口径）；
//	回填窗口与请求 hours 一致、下界钳制到 720h；按 60 分钟一批
//	  提交、单请求最多 24 批，水位与分钟数据同事务提交。
func ensureThreatRollup(hours int) error {
	threatRollupEnsureMu.Lock()
	defer threatRollupEnsureMu.Unlock()
	rewindAttempts := 0
	for {
		err := ensureThreatRollupWithYields(hours)
		if errors.Is(err, errThreatRollupRestart) {
			continue
		}
		if err != nil {
			return err
		}
		attempted, succeeded := drainThreatRollupRewindPending()
		if !attempted {
			return nil
		}
		if succeeded {
			continue
		}
		// 回退应用失败（队列已回填）：只有成功才 continue——旧实现在这里
		// 无条件继续，DB 写锁/BUSY/磁盘满时形成无退避、无上限的紧凑重试循环
		// （每轮一次事务 + 一条 warn，warmer 协程被粘住）。有限次重试消化
		// 瞬时冲突，仍失败则把队列留给下一轮节拍（warmer 60s / 请求路径）。
		rewindAttempts++
		if rewindAttempts >= threatRollupRewindApplyAttempts {
			return fmt.Errorf("threat rollup rewind: %d 次尝试后仍失败，队列已回填，留待下一轮", rewindAttempts)
		}
		if threatRollupRewindApplyBackoff > 0 {
			time.Sleep(time.Duration(rewindAttempts) * threatRollupRewindApplyBackoff)
		}
	}
}

func ensureThreatRollupWithYields(hours int) error {
	threatRollupMu.Lock()
	defer threatRollupMu.Unlock()
	// 句柄快照：后台 warmer 协程可能与测试换库/关停并发——入口快照后全程
	// 使用局部句柄，句柄被置换/关闭时 Begin 报错上抛而非 nil 解引用 panic。
	database := db.MetricsDB
	if database == nil {
		return errors.New("metrics db unavailable")
	}
	if hours < 1 {
		hours = 24
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	now := threatScreenNow().UTC()
	lastComplete := now.Add(-time.Minute).Truncate(time.Minute)
	currentMinute := now.Truncate(time.Minute)
	horizon := lastComplete.Add(-time.Duration(hours) * time.Hour)

	// 覆盖区间 [coveredFrom, lastFixed]（完整分钟，持久化在 metrics_state）：
	//   - 空覆盖 = coveredFrom 为 lastComplete（首个未来分钟）、lastFixed 为
	//
	//   - 请求窗口 [dFrom, dTo] 中「更旧未覆盖段」与「更新未覆盖段」分别按批
	//     补齐把水位推到最新后，后续宽窗口
	//     不得因「水位已到最新」而漏掉未回填的旧分钟）。
	// 水位与分钟数据同事务提交；空分钟同样推进；陈旧/未来水位钳制。
	dFrom := horizon
	dTo := lastComplete.Add(-time.Minute)
	if dFrom.After(dTo) {
		dFrom = dTo
	}
	coveredFrom, okCovered, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil {
		return err
	}
	lastFixed, okFixed, err := loadThreatRollupState(database, threatRollupWatermarkKey)
	if err != nil {
		return err
	}
	// 一致性归一：coveredFrom 在窗口之后、lastFixed
	// 在窗口之后、或 lastFixed 早于 （陈旧水位先于已覆盖底端）
	// 一律按空覆盖处理——空覆盖区间的端点=(dTo+1, dTo)，旧侧缺口一次性覆盖到
	// 窗口末端，回填有界且幂等。
	validCoverage := okCovered && okFixed && !coveredFrom.After(dTo) && !lastFixed.After(dTo) &&
		!lastFixed.Before(coveredFrom.Add(-time.Minute))
	emptyCoverage := !validCoverage
	// 窗口起点晚于已覆盖末端——中间存在未固化长缺口。窄窗（24h）
	// 不得把更早的回退目标当陈旧水位重置：从 lastFixed+1 续做，并受可见上限
	// 720h 约束，保证 7d 积压重固不被后续窄窗请求吞掉。
	if validCoverage && lastFixed.Before(dFrom.Add(-time.Minute)) {
		dFrom = lastFixed.Add(time.Minute)
		if floor := lastComplete.Add(-time.Duration(threatScreenMaxHours) * time.Hour); dFrom.Before(floor) {
			dFrom = floor
		}
	}
	// 目标维度 rollup 升级标记缺失（旧库首次运行含此修复的版本）→
	// 覆盖区间同按空处理，窗口内分钟全部重固并补出 rule_caddy_id 计数。
	rebuildNeeded := false
	if _, targetReady, terr := loadThreatRollupState(database, threatRollupTargetReadyKey); terr != nil {
		return terr
	} else if !targetReady {
		emptyCoverage = true
		rebuildNeeded = true
	}
	// 归属地维度只在固化时计算——xdb 在缺口分钟内不可用（启动期/
	// 热换窗口）会让该窗 country/province 永久为空。归属地库代际变化（首次
	// 加载/更新热换）→ 按空覆盖重固请求窗口，库恢复后历史空维度自愈；
	// 原始事件已被保留策略裁剪的分钟仍无法重建（已固化行只会保留原值）。
	geoipGen := strconv.FormatInt(services.GeoIPDataGeneration(), 10)
	if curGen, genOK, gerr := loadThreatRollupRawState(database, threatRollupGeoIPGenerationKey); gerr != nil {
		return gerr
	} else if !genOK || curGen != geoipGen {
		emptyCoverage = true
		rebuildNeeded = true
	}
	// 分类器代际不一致 → 历史分钟按空覆盖重固（与目标维度/归属地同机制）。
	if curVer, verOK, vErr := loadThreatRollupRawState(database, threatRollupClassifierVersionKey); vErr != nil {
		return vErr
	} else if !verOK || curVer != threatRollupClassifierVersion {
		emptyCoverage = true
		rebuildNeeded = true
	}
	// 谓词/action 枚举代际同上——写侧语义变更必须重固（水位只保护迟到
	// 事件，不保护语义变更）。
	for _, kv := range [][2]string{
		{threatRollupPredicateVersionKey, threatRollupPredicateVersion},
		{threatRollupActionEnumVersionKey, threatRollupActionEnumVersion},
	} {
		if cur, ok, sErr := loadThreatRollupRawState(database, kv[0]); sErr != nil {
			return sErr
		} else if !ok || cur != kv[1] {
			emptyCoverage = true
			rebuildNeeded = true
		}
	}
	if emptyCoverage {
		coveredFrom = dTo.Add(time.Minute)
		lastFixed = dTo
	}
	// 重建意图跨调用持久化。旧实现只在触发
	// 那一轮把 rebuildAll 置真——单次最多回填 23h（批数上限），宽窗口其余
	// 分钟的增量路径在「无新事件」时直接 no-op，目标维度/归属地永不补算，
	// 而目标就绪标记已在首轮写入（后续调用 rebuildAll=false），自愈中断且
	// backfill_incomplete 不再披露。持久化起点并据此扩展回填下界，使后续
	// 任意窗口的调用都继续全量重建，直到覆盖底端到达意图起点。
	rebuildFrom, hasRebuildFrom, err := loadThreatRollupState(database, threatRollupRebuildFromKey)
	if err != nil {
		return err
	}
	if rebuildNeeded {
		if !hasRebuildFrom || dFrom.Before(rebuildFrom) {
			rebuildFrom = dFrom
		}
		hasRebuildFrom = true
		if _, err := database.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupRebuildFromKey, rebuildFrom.Format("2006-01-02 15:04")); err != nil {
			return err
		}
	}
	rebuildAll := hasRebuildFrom
	if rebuildAll && rebuildFrom.Before(dFrom) {
		dFrom = rebuildFrom
	}
	saveCoverage := func(tx *sql.Tx, from, until time.Time) error {
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupCoveredFromKey, from.Format("2006-01-02 15:04")); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, threatRollupWatermarkKey, until.Format("2006-01-02 15:04"))
		return err
	}
	backfillBatches := threatRollupMaxBatchesPerCall - 1 // 预留最新两分钟事务
	// 批次间隙释放 threatRollupMu 让摄取钩子/读者通过；重新取锁时先合并待
	// 处理回退，并检测是否发生了并发水位回退——是则从头重跑（本地覆盖状态
	// 已失效），避免旧值覆盖新回退而漏重算。
	yield := func() error {
		threatRollupMu.Unlock()
		runtime.Gosched()
		threatRollupMu.Lock()
		applyPendingThreatRollupRewindInLock()
		current, ok, err := loadThreatRollupState(database, threatRollupWatermarkKey)
		if err != nil {
			return err
		}
		if ok && current.Before(lastFixed) {
			return errThreatRollupRestart
		}
		return nil
	}
	// 1) 旧侧缺口：紧邻已覆盖区间的更旧分钟，从新到旧按批补齐（降序推进，
	// 每批内部升序固化；批提交后 coveredFrom 前移）。
	if coveredFrom.After(dFrom) {
		newestOld := coveredFrom.Add(-time.Minute)
		if newestOld.After(dTo) {
			newestOld = dTo
		}
		for end := newestOld; !end.Before(dFrom) && backfillBatches > 0; backfillBatches-- {
			start := end.Add(-time.Duration(threatRollupBatchMinutes-1) * time.Minute)
			if start.Before(dFrom) {
				start = dFrom
			}
			tx, err := database.Begin()
			if err != nil {
				return err
			}
			for m := start; !m.After(end); m = m.Add(time.Minute) {
				if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
					tx.Rollback()
					return err
				}
			}
			if err := saveCoverage(tx, start, lastFixed); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if err := yield(); err != nil {
				return err
			}
			coveredFrom = start
			if start.Equal(dFrom) {
				break
			}
			end = start.Add(-time.Minute)
		}
	}
	// 2) 新侧缺口：已覆盖区间的更新分钟（升序按批推进）。
	if !lastFixed.Before(dTo) {
		// 已覆盖到窗口末端，无需新侧回填。
	} else {
		start := lastFixed.Add(time.Minute)
		if start.Before(dFrom) {
			start = dFrom
		}
		for !start.After(dTo) && backfillBatches > 0 {
			backfillBatches--
			end := start.Add(time.Duration(threatRollupBatchMinutes-1) * time.Minute)
			if end.After(dTo) {
				end = dTo
			}
			tx, err := database.Begin()
			if err != nil {
				return err
			}
			for m := start; !m.After(end); m = m.Add(time.Minute) {
				if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
					tx.Rollback()
					return err
				}
			}
			if err := saveCoverage(tx, coveredFrom, end); err != nil {
				tx.Rollback()
				return err
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			if err := yield(); err != nil {
				return err
			}
			lastFixed = end
			start = end.Add(time.Minute)
		}
	}
	// 3) 最新段：lastComplete（迟到写入终固）+ currentMinute（实时
	// 口径）——每轮恒固化，首屏 recent_rate 不依赖回填进度。
	{
		tx, err := database.Begin()
		if err != nil {
			return err
		}
		repairStart := lastComplete.Add(-time.Duration(threatRollupRepairMinutes-1) * time.Minute)
		if repairStart.Before(dFrom) {
			repairStart = dFrom
		}
		for m := repairStart; !m.After(lastComplete); m = m.Add(time.Minute) {
			if err := threatFixMinuteWithMode(tx, m, rebuildAll); err != nil {
				tx.Rollback()
				return err
			}
		}
		if !currentMinute.Equal(lastComplete) {
			if err := threatFixMinuteWithMode(tx, currentMinute, rebuildAll); err != nil {
				tx.Rollback()
				return err
			}
		}
		// 目标维度就绪标记与最新段同事务提交——任何成功固化后
		// 目标计数（至少最新两分钟）必然存在，后续轮次按正常 coverage 续做。
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupTargetReadyKey, now.Format("2006-01-02 15:04")); err != nil {
			tx.Rollback()
			return err
		}
		// 记录本轮使用的归属地库代际（下次代际变化触发重固）。
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupGeoIPGenerationKey, geoipGen); err != nil {
			tx.Rollback()
			return err
		}
		// 与固化结果同事务记录分类器口径代际。
		if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
			threatRollupClassifierVersionKey, threatRollupClassifierVersion); err != nil {
			tx.Rollback()
			return err
		}
		// 谓词/action 枚举代际与固化结果同事务落库。
		for _, kv := range [][2]string{
			{threatRollupPredicateVersionKey, threatRollupPredicateVersion},
			{threatRollupActionEnumVersionKey, threatRollupActionEnumVersion},
		} {
			if _, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, kv[0], kv[1]); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	// 覆盖底端已推进到持久化重建起点——意图窗口内的旧侧分钟
	// （以及本轮新侧/最新段）均已按全量重建固化，清除意图标记，恢复正常增量
	// 语义。批数用尽未到达时保留标记，后续调用继续全量重建。
	if rebuildAll && !coveredFrom.After(rebuildFrom) {
		if _, err := database.Exec(`DELETE FROM metrics_state WHERE key=?`, threatRollupRebuildFromKey); err != nil {
			return err
		}
	}
	markThreatRollupSuccess()
	return nil
}

// threatRollupWarmerStarted 后台固化协程启动标志（原子）。启动后大屏请求
// 路径不再懒固化（避免与 warmer 抢写锁/重复回填）；未启动（测试/旧路径）
// 保持请求路径懒固化。
var threatRollupWarmerStarted atomic.Bool

// threatRollupWarmerWg warmer 协程退出等待（关停/测试换库前先行等待，
// 避免固化中途句柄被关闭）。
var threatRollupWarmerWg sync.WaitGroup

// threatRollupReadyAt 最近一次成功固化的 UnixNano（0=从未成功，历史
// 请求路径据此区分「warmer 已启动」与「已有可用覆盖」。
// threatRollupReadyDB 记录该成功状态所属的指标库句柄——换库（测试/重启装配）
// 后旧就绪状态对新库无效，避免把上一库的覆盖误当当前库的。
var (
	threatRollupReadyAt atomic.Int64
	threatRollupReadyDB atomic.Pointer[sql.DB]
)

// threatRollupRequestedHours 最近请求过的最大窗口（小时）：宽窗口请求把
// 需求告知 warmer，后台每轮按 max(7d, 需求) 扩窗回填。
// 需求带**有界有效期**——大屏固定 24h 消费，hours 参数仅为后续扩展
// 保留；一次 30d 请求若永久生效，warmer 每分钟都按 30d 回填，后台成本被
// 单次请求永久抬升。超过 threatRollupRequestedHoursTTL 未再请求即复位。
var threatRollupRequestedHours atomic.Int64

// threatRollupRequestedHoursAt 最近一次宽窗口请求的 UnixNano（0=无需求）。
var threatRollupRequestedHoursAt atomic.Int64

// threatRollupRequestedHoursTTL 宽窗口需求有效期：需覆盖「大屏持续轮询」
// （30s 一轮）而远小于「永久」。过期即回落到默认 7d 预热窗口。
const threatRollupRequestedHoursTTL = 15 * time.Minute

// recordThreatRollupRequestedHours 记录一次宽窗口请求（>24h 才调用）：窗口
// 只升不降，但每次都刷新有效期；上限钳制到 threatScreenMaxHours。
func recordThreatRollupRequestedHours(hours int) {
	if hours <= 24 {
		return
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	for {
		cur := threatRollupRequestedHours.Load()
		if int64(hours) > cur {
			if !threatRollupRequestedHours.CompareAndSwap(cur, int64(hours)) {
				continue
			}
		}
		threatRollupRequestedHoursAt.Store(time.Now().UnixNano())
		return
	}
}

// threatRollupRequestedHoursLimit 当前有效的宽窗口需求（小时，0=无）：
// 过期需求就地 CAS 复位（并发写入者不会被覆盖——CAS 失败重读）。
func threatRollupRequestedHoursLimit() int {
	for {
		req := int(threatRollupRequestedHours.Load())
		if req <= 0 {
			return 0
		}
		seen := threatRollupRequestedHoursAt.Load()
		if seen != 0 && time.Since(time.Unix(0, seen)) <= threatRollupRequestedHoursTTL {
			return req
		}
		if threatRollupRequestedHours.CompareAndSwap(int64(req), 0) {
			threatRollupRequestedHoursAt.CompareAndSwap(seen, 0)
			return 0
		}
	}
}

// markThreatRollupSuccess 记录一次成功固化（任何路径：warmer / 请求懒固化）。
func markThreatRollupSuccess() {
	if cur := db.MetricsDB; cur != nil {
		threatRollupReadyDB.Store(cur)
	}
	threatRollupReadyAt.Store(time.Now().UnixNano())
}

// threatRollupUsable 当前指标库是否已有一次成功固化（就绪判定）。
func threatRollupUsable() bool {
	if threatRollupReadyAt.Load() == 0 {
		return false
	}
	cur := db.MetricsDB
	return cur != nil && threatRollupReadyDB.Load() == cur
}

// threatRollupStale 最近成功固化是否已超过陈旧阈值。
func threatRollupStale() bool {
	if !threatRollupUsable() {
		return true
	}
	return time.Since(time.Unix(0, threatRollupReadyAt.Load())) > threatRollupStaleAfter
}

// threatRollupCoverageReaches 持久 coverage 是否已覆盖请求窗口起点（宽窗口
// 请求决定是否需在请求路径补做旧侧分钟）。读取失败按「未覆盖」
// 处理（宁可多做一次幂等回填）。
func threatRollupCoverageReaches(hours int) bool {
	database := db.MetricsDB
	if database == nil {
		return true
	}
	horizon := threatScreenNow().UTC().Add(-time.Minute).Truncate(time.Minute).Add(-time.Duration(hours) * time.Hour)
	coveredFrom, ok, err := loadThreatRollupState(database, threatRollupCoveredFromKey)
	if err != nil || !ok {
		return false
	}
	return !coveredFrom.After(horizon)
}

// WaitThreatRollupWarmer 有界等待 warmer 协程退出（关停链在 db.Close 之前
// 调用，与同层 worker 同口径）：warmer 只在轮次之间检查 ctx，在途
// ensureThreatRollup 的批推进不会被打断——不等待就会让该批读写落在关闭后的
// 库上（"database is closed" 告警 + 批事务回滚）。d<=0 或超时返回 false，
// 调用方如实记录后继续退出（残留协程随进程消亡）。
func WaitThreatRollupWarmer(d time.Duration) bool {
	if d <= 0 {
		return false
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		threatRollupWarmerWg.Wait()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// StartThreatRollupWarmer 启动 rollup 后台固化协程（幂等：CAS 标志，重复
// 调用为空操作）：启动时立即 ensureThreatRollup(7d)，之后每 60s 一轮；
// ctx 取消即退出。单轮失败仅告警，下一轮自愈（固化本身幂等）。
func StartThreatRollupWarmer(ctx context.Context) {
	if !threatRollupWarmerStarted.CompareAndSwap(false, true) {
		return
	}
	threatRollupWarmerWg.Add(1)
	go func() {
		defer threatRollupWarmerWg.Done()
		run := func() {
			// 启动即预固化 7 天（UI 最大窗口），赶在保留期/行帽裁剪之前；
			// 只预热 24h 会让升级后 24h–7d 区间在裁剪后永久少计
			// 单次调用按 25 批有界推进，后续轮次续做。
			hours := threatRollupRewindWindowHours
			if req := threatRollupRequestedHoursLimit(); req > hours {
				hours = req
			}
			if hours > threatScreenMaxHours {
				hours = threatScreenMaxHours
			}
			if err := ensureThreatRollup(hours); err != nil {
				services.Logf("warn", "threat rollup warmer: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		run() // 启动即固化（首屏不等待首个 tick）
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				run()
			}
		}
	}()
}

// resetThreatRollupWarmerForTest 测试缝：复位 warmer 启动标志（生产不调用）。
func resetThreatRollupWarmerForTest() {
	threatRollupWarmerStarted.Store(false)
	threatRollupReadyAt.Store(0)
	threatRollupReadyDB.Store(nil)
	threatRollupRequestedHours.Store(0)
	threatRollupRequestedHoursAt.Store(0)
}

// threatRollupBlockedAction 大屏 blocked 计数的 action 取值单一事实源：
// queryThreatRecentBlocked（SUM 路径）与主扫描（Go 侧逐行累加）共用——
// 两侧口径漂移会被同一钉测捕获。
const threatRollupBlockedAction = "blocked"

// queryThreatRecentBlocked 近 N 个完整分钟 [fromMinute, toMinute) 的 blocked
// 计数（大屏 recent_rate 数据源）。上界开区间排除当前未满分钟——把不足
// 60s 的当前分钟按整分钟并入会使口径随秒数漂移（最坏偏高 ~20%），与
// rollup「最新完整分钟」语义对齐（指标滞后 ≤60s，可接受）。
// 测试注入缝：需要只让最后一条 SUM 失败，验证 500 不被 200 吞掉。
var queryThreatRecentBlocked = func(fromMinute, toMinute string) (int, error) {
	var blocked int
	err := db.MetricsDB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute >= ? AND minute < ? AND action='`+threatRollupBlockedAction+`'`, fromMinute, toMinute).Scan(&blocked)
	return blocked, err
}

// threatRollupEventHighwaterPrefix 分钟高水位键前缀——与保留清理共用单一
// 事实源（写入/删除两份硬编码曾漂移为「只写不删」）。
const threatRollupEventHighwaterPrefix = services.ThreatRollupEventHighwaterPrefix

func loadThreatRollupEventHighwater(tx *sql.Tx, minute string) (int64, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, threatRollupEventHighwaterPrefix+minute).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	id, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if perr != nil || id < 0 {
		services.Logf("warn", "threat rollup: corrupted event highwater for minute %s (%q), treating as unset", minute, raw)
		return 0, nil
	}
	return id, nil
}

func saveThreatRollupEventHighwater(tx *sql.Tx, minute string, id int64) error {
	_, err := tx.Exec(`INSERT INTO metrics_state (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		threatRollupEventHighwaterPrefix+minute, strconv.FormatInt(id, 10))
	return err
}

// loadThreatRollupLateBaseline 读某分钟的迟到合并基线（回退删高水位时的留底值）。
func loadThreatRollupLateBaseline(tx *sql.Tx, minute string) (int64, bool, error) {
	var raw string
	err := tx.QueryRow(`SELECT value FROM metrics_state WHERE key=?`, services.ThreatRollupLateBaselinePrefix+minute).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	id, perr := strconv.ParseInt(strings.TrimSpace(raw), 10, 64)
	if perr != nil || id < 0 {
		services.Logf("warn", "threat rollup: corrupted late baseline for minute %s (%q), treating as unset", minute, raw)
		return 0, false, nil
	}
	return id, true, nil
}

// threatRollupKey 分钟 rollup 的维度键（与 security_event_rollup 主键同集合）。
type threatRollupKey struct{ country, province, family, rule, action string }

// loadExistingRollup 读取某分钟已固化的两张 rollup 行（增量基线）。读入即按
// 当前攻击口径过滤：口径升级前固化的放行行（原始事件可能已被保留期裁剪、
// 无法重算）不得继续计入。目标维度行无规则/动作列，无法按行判定，按原值
// 保留（仅影响历史分钟的「被攻击目标」展示，已知且有界）。
func loadExistingRollup(tx *sql.Tx, minuteStr string) (map[threatRollupKey]int, map[string]int, error) {
	agg := map[threatRollupKey]int{}
	targetAgg := map[string]int{}
	oldRows, err := tx.Query(`SELECT country, province, family, rule, action, count FROM security_event_rollup WHERE minute=?`, minuteStr)
	if err != nil {
		return nil, nil, err
	}
	for oldRows.Next() {
		var k threatRollupKey
		var count int
		if err := oldRows.Scan(&k.country, &k.province, &k.family, &k.rule, &k.action, &count); err != nil {
			oldRows.Close()
			return nil, nil, err
		}
		if !services.SecurityEventCountsAsAttack(k.action, k.rule) {
			continue
		}
		agg[k] = count
	}
	if err := oldRows.Err(); err != nil {
		oldRows.Close()
		return nil, nil, err
	}
	oldRows.Close()
	targetRows, err := tx.Query(`SELECT rule_caddy_id, count FROM security_event_target_rollup WHERE minute=?`, minuteStr)
	if err != nil {
		return nil, nil, err
	}
	for targetRows.Next() {
		var ruleID string
		var count int
		if err := targetRows.Scan(&ruleID, &count); err != nil {
			targetRows.Close()
			return nil, nil, err
		}
		targetAgg[ruleID] = count
	}
	if err := targetRows.Err(); err != nil {
		targetRows.Close()
		return nil, nil, err
	}
	targetRows.Close()
	return agg, targetAgg, nil
}

// aggregateEvents 聚合 [from, to) 分钟内的原始事件到 rollup 维度，只计计入
// 攻击口径的事件（爬虫放行的 logged 事件不是攻击）；afterID>0 时只取 id 更大
// 的迟到事件（增量模式）。返回维度计数、目标计数与本次计入的事件总数。
func aggregateEvents(tx *sql.Tx, from, to time.Time, afterID int64) (map[threatRollupKey]int, map[string]int, int, error) {
	agg := map[threatRollupKey]int{}
	targetAgg := map[string]int{}
	rawQuery := `SELECT client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,'')), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action, COALESCE(rule_caddy_id,''), COUNT(*)
		FROM security_events
		WHERE event_time >= ? AND event_time < ?`
	args := []any{from.Format("2006-01-02 15:04:05"), to.Format("2006-01-02 15:04:05")}
	if afterID > 0 {
		rawQuery += ` AND id > ?`
		args = append(args, afterID)
	}
	rawQuery += `
		GROUP BY client_ip, COALESCE(NULLIF(rule_name,''), COALESCE(rule_triggered,'')), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), action, COALESCE(rule_caddy_id,'')`
	rows, err := tx.Query(rawQuery, args...)
	if err != nil {
		return nil, nil, 0, err
	}
	total := 0
	for rows.Next() {
		var ip, ruleName, ruleTriggered, ruleMsg, action, ruleCaddyID string
		var count int
		if err := rows.Scan(&ip, &ruleName, &ruleTriggered, &ruleMsg, &action, &ruleCaddyID, &count); err != nil {
			rows.Close()
			return nil, nil, 0, err
		}
		if isReservedIP(ip) {
			continue
		}
		if !services.SecurityEventCountsAsAttack(action, ruleTriggered) {
			continue
		}
		country, province := threatLocationParts(enrichIPLocation(ip))
		// top_rules 维度优先 rule_triggered（真正的 WAF/CRS/自定义规则 ID），
		// 无归属时才回退负载规则名；混用两者会让「TOP 命中规则」名不副实
		//
		ruleKey := ruleTriggered
		if ruleKey == "" {
			ruleKey = ruleName
		}
		agg[threatRollupKey{country, province, categorizeAttack(ruleTriggered, ruleMsg), ruleKey, action}] += count
		total += count
		if ruleCaddyID != "" {
			targetAgg[ruleCaddyID] += count
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, 0, err
	}
	rows.Close()
	return agg, targetAgg, total, nil
}

// threatFixMinuteWithMode 单分钟固化：首次/旧状态按全量重建，已有事件高水位后
// 增量模式只叠加 id 更大的迟到事件；fullRebuild 强制丢弃旧水位并全量重建。
func threatFixMinuteWithMode(tx *sql.Tx, m time.Time, fullRebuild bool) error {
	next := m.Add(time.Minute)
	minuteStr := m.Format("2006-01-02 15:04")
	previousMaxID, err := loadThreatRollupEventHighwater(tx, minuteStr)
	if err != nil {
		return err
	}
	// 迟到基线：回退（原地改判）删掉分钟高水位时留底的值。全量重算在「原始
	// 行被裁剪/含旧口径行」形态下 newTotal<oldTotal，只能保留已固化行——此时
	// 迟到行必须按 id > 基线 合并（基线 ≤ 任何已计入行 id），否则永久不入聚合。
	// 基线一旦被本事务消费即删除（成功路径与高水位同事务落库；事务回滚则
	// 一并回滚，不会出现重复合并）。
	lateBaseline, hasBaseline, err := loadThreatRollupLateBaseline(tx, minuteStr)
	if err != nil {
		return err
	}
	if hasBaseline {
		if _, err := tx.Exec(`DELETE FROM metrics_state WHERE key=?`, services.ThreatRollupLateBaselinePrefix+minuteStr); err != nil {
			return err
		}
		if previousMaxID > 0 {
			// 高水位仍在：基线冗余（高水位 ≥ 基线）。
			lateBaseline = 0
		}
	}
	var currentMaxID int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(id),0) FROM security_events WHERE event_time >= ? AND event_time < ?`,
		m.Format("2006-01-02 15:04:05"), next.Format("2006-01-02 15:04:05")).Scan(&currentMaxID); err != nil {
		return err
	}
	agg := map[threatRollupKey]int{}
	targetAgg := map[string]int{}
	incremental := !fullRebuild && previousMaxID > 0
	afterID := int64(0)
	if incremental {
		var lerr error
		agg, targetAgg, lerr = loadExistingRollup(tx, minuteStr)
		if lerr != nil {
			return lerr
		}
		afterID = previousMaxID
	}
	deltaAgg, deltaTarget, deltaTotal, err := aggregateEvents(tx, m, next, afterID)
	if err != nil {
		return err
	}
	for k, count := range deltaAgg {
		agg[k] += count
	}
	for id, count := range deltaTarget {
		targetAgg[id] += count
	}
	highwater := currentMaxID
	if previousMaxID > highwater {
		highwater = previousMaxID
	}
	if lateBaseline > highwater {
		highwater = lateBaseline
	}
	if incremental {
		if deltaTotal == 0 {
			return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
		}
	} else {
		newTotal := 0
		for _, count := range agg {
			newTotal += count
		}
		var oldTotal int
		if err := tx.QueryRow(`SELECT COALESCE(SUM(count),0) FROM security_event_rollup WHERE minute=?`, minuteStr).Scan(&oldTotal); err != nil {
			return err
		}
		// 判据必须排除迟到事件：部分裁剪后，迟到写入可能把 newTotal 抬回
		// oldTotal 以上，但「高水位/迟到基线之前的剩余行」仍少于已固化数。
		// 仅比较 newTotal 会在这种混合形态下覆盖并永久丢掉已固化历史。
		lateBaselineID := previousMaxID
		if lateBaselineID == 0 {
			lateBaselineID = lateBaseline
		}
		lateAgg := map[threatRollupKey]int{}
		lateTarget := map[string]int{}
		lateTotal := 0
		if lateBaselineID > 0 {
			var aerr error
			lateAgg, lateTarget, lateTotal, aerr = aggregateEvents(tx, m, next, lateBaselineID)
			if aerr != nil {
				return aerr
			}
		}
		if newTotal-lateTotal < oldTotal {
			// 原始事件已被保留期/行帽裁剪：保留旧行（读入时已按当前
			// 攻击口径过滤）并只叠加高水位（或回退留底的迟到基线）之后
			// 的事件。无基线时无法区分迟到与已计入，不做增量叠加。
			oldAgg, oldTarget, lerr := loadExistingRollup(tx, minuteStr)
			if lerr != nil {
				return lerr
			}
			kept := 0
			for _, count := range oldAgg {
				kept += count
			}
			for k, count := range lateAgg {
				oldAgg[k] += count
			}
			for id, count := range lateTarget {
				oldTarget[id] += count
			}
			agg, targetAgg = oldAgg, oldTarget
			if lateTotal == 0 && kept == oldTotal {
				return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
			}
		} else if newTotal == 0 && oldTotal == 0 {
			return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
		}
	}
	if _, err := tx.Exec(`DELETE FROM security_event_rollup WHERE minute = ?`, minuteStr); err != nil {
		return err
	}
	// 目标维度同批重固（rollup 主键无法承载 rule_caddy_id）。
	if _, err := tx.Exec(`DELETE FROM security_event_target_rollup WHERE minute = ?`, minuteStr); err != nil {
		return err
	}
	stmt, err := tx.Prepare(`INSERT INTO security_event_rollup (minute, country, province, family, rule, action, count) VALUES (?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	for k, count := range agg {
		if _, err := stmt.Exec(minuteStr, k.country, k.province, k.family, k.rule, k.action, count); err != nil {
			stmt.Close()
			return err
		}
	}
	if err := stmt.Close(); err != nil {
		return err
	}
	tstmt, err := tx.Prepare(`INSERT INTO security_event_target_rollup (minute, rule_caddy_id, count) VALUES (?, ?, ?)`)
	if err != nil {
		return err
	}
	for id, count := range targetAgg {
		if _, err := tstmt.Exec(minuteStr, id, count); err != nil {
			tstmt.Close()
			return err
		}
	}
	if err := tstmt.Close(); err != nil {
		return err
	}
	return saveThreatRollupEventHighwater(tx, minuteStr, highwater)
}

// threatLocationParts 归属地字符串 → (国家, 省简称)；中国省供省级聚合。
func threatLocationParts(location string) (string, string) {
	parts := strings.SplitN(location, "·", 3)
	country := ""
	province := ""
	if len(parts) > 0 {
		country = strings.TrimSpace(parts[0])
	}
	if country == "保留地址" {
		return "", ""
	}
	if country == "中国" && len(parts) > 1 {
		province = strings.TrimSpace(parts[1])
	}
	return country, province
}

// trafficCountry/trafficSnapshot Caddy admin /lb/traffic-stats 响应形状
// （caddygeoip per-country 原子计数器，attack/normal 双桶累计）。
type trafficCountry struct {
	Attack uint64 `json:"attack"`
	Normal uint64 `json:"normal"`
}

type trafficSnapshot struct {
	Countries map[string]trafficCountry `json:"countries"`
	SampleN   uint32                    `json:"sample_n"`
	// Collecting 是采集租约当前是否有效：无租约期间累计计数冻结，
	// 「数值不变」不等于「无流量」。
	Collecting bool `json:"collecting"`
}

// threatTrafficEmptyDegrade admin 不可达/抓取失败时的降级响应（200 空数据，
// available=false）——大屏 1-2s 轮询容忍瞬时不可达，不 500。collecting=false
// 与「可达但无租约」同形：两种情况都不得把冻结的累计当作实时流量。
func threatTrafficEmptyDegrade() gin.H {
	return gin.H{"countries": map[string]trafficCountry{}, "available": false, "sample_n": 1, "collecting": false}
}

// ControlThreatScreenCollector POST/DELETE /security/overview/threat-screen/collector
// 代理 Caddy admin 的流量采集租约：大屏打开时申请/续租，关闭时释放；
// 插件在无租约时跳过所有流量采集热路径（安全日志不受影响）。
func (h *Handlers) ControlThreatScreenCollector(c *gin.Context) {
	// 请求体上限 4096：超限显式 413（LimitReader 静默截断会把半截 JSON 原样
	// 转发给 admin，admin 侧 400 会把错误归因指向 admin，本地还拿不到
	// lease_id → 租约不登记/不释放）。空体（DELETE 走 query 回退）合法，
	// 非空非法 JSON 显式 400——不与「无字段」混淆。
	const collectorBodyLimit = 4096
	body, err := io.ReadAll(io.LimitReader(c.Request.Body, collectorBodyLimit+1))
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体读取失败"})
		return
	}
	if len(body) > collectorBodyLimit {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "采集控制请求体超过 4KB 上限"})
		return
	}
	target := strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/lb/traffic-collector"
	// 威胁大屏的攻击光流使用独立采样源；本次 collector 请求同时按 lease_id
	// 同步其本地采样租约（租约化，与 Caddy 侧 traffic_lease.go
	// 同模型：有效档位=存活租约 min，单租约释放不误杀其他租约）。
	// 安全事件日志不受影响。
	var collectorReq struct {
		LeaseID string `json:"lease_id"`
		TTLMs   *int64 `json:"ttl_ms"`
		SampleN *int   `json:"sample_n"`
	}
	if len(bytes.TrimSpace(body)) > 0 {
		if err := json.Unmarshal(body, &collectorReq); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "采集控制请求体格式无效"})
			return
		}
	}
	if collectorReq.LeaseID == "" && c.Request.Method == http.MethodDelete {
		collectorReq.LeaseID = c.Query("lease_id")
		// query 回退必须一并转发：Caddy 侧 DELETE 无 body 时读 query，
		// 不转发会让 admin 收到空 lease_id → releaseTrafficLease("") no-op →
		// 本地已释放而 Caddy 租约残留到 TTL 过期（响应 enabled=true 与本地
		// 状态矛盾）。与 GetThreatScreenFlowEvents 的 RawQuery 转发同形。
		if raw := c.Request.URL.RawQuery; raw != "" {
			target += "?" + raw
		}
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), c.Request.Method, target, bytes.NewReader(body))
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "采集控制请求构造失败"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("warn", "threat-screen collector: admin request failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "流量采集控制不可达"})
		return
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	// 先转发成功再落本地：admin 失败（503/400）时本地租约保持原状，
	// 避免 app/Caddy 两侧采样状态分叉。
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if c.Request.Method == http.MethodDelete {
			services.ReleaseThreatScreenAttackFlowLease(collectorReq.LeaseID)
		} else if collectorReq.LeaseID != "" {
			var ttl time.Duration
			if collectorReq.TTLMs != nil {
				ttl = time.Duration(*collectorReq.TTLMs) * time.Millisecond
			}
			sampleN := 0
			if collectorReq.SampleN != nil {
				sampleN = *collectorReq.SampleN
			}
			if err := services.AcquireThreatScreenAttackFlowLease(collectorReq.LeaseID, ttl, sampleN); err != nil {
				// 本地登记失败（租约超限等）不回滚 admin 侧已生效租约；
				// 响应原样透传，本地光流档位保持旧值。
				services.Logf("warn", "threat-screen collector: local attack-flow lease acquire failed: %v", err)
			}
		}
	}
	c.Data(resp.StatusCode, "application/json", respBody)
}

// GetThreatScreenFlowEvents GET /security/overview/threat-screen/events
// 代理 Caddy admin 逐请求正常流量环形缓冲；since_seq 增量拉取，仅大屏打开时
// 前端轮询。响应透传 enabled/sample_n/events/next_seq。
func (h *Handlers) GetThreatScreenFlowEvents(c *gin.Context) {
	target := strings.TrimRight(h.cfg.CaddyAdminURL, "/") + "/lb/traffic-events"
	if raw := c.Request.URL.RawQuery; raw != "" {
		target += "?" + raw
	}
	req, err := http.NewRequestWithContext(c.Request.Context(), http.MethodGet, target, nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "事件流请求构造失败"})
		return
	}
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("warn", "threat-screen events: admin request failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "逐请求事件流不可达"})
		return
	}
	defer resp.Body.Close()
	// 对齐同族读端点（GetCRSRuleContent/GetCRSSetupConfig 的 413 口径）
	// ——超限显式拒绝而非把截断的 JSON 以 200 透传（调用方会把残缺事件流当
	// 完整增量消费）。
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20+1))
	if err != nil {
		services.Logf("warn", "threat-screen events: read body failed: %v", err)
		c.JSON(http.StatusServiceUnavailable, models.APIResponse{Code: 503, Message: "逐请求事件流不可达"})
		return
	}
	if len(body) > 1<<20 {
		c.JSON(http.StatusRequestEntityTooLarge, models.APIResponse{Code: 413, Message: "逐请求事件流响应超过 1MB 读取上限"})
		return
	}
	// 应用统一信封：Caddy admin 返回裸 JSON，前端 request 封装按 data 字段
	// 消费（res.data）——裸透传会让 flowTask 每轮判定 enabled=false 并把游标
	// 重置为 0，正常请求蓝色光流永不绘制。
	var payload struct {
		Enabled bool `json:"enabled"`
		Events  []struct {
			Seq      uint64 `json:"seq"`
			Country  string `json:"country"`
			Province string `json:"province,omitempty"`
			At       int64  `json:"at"`
		} `json:"events"`
		NextSeq    uint64 `json:"next_seq"`
		SampleN    uint32 `json:"sample_n"`
		Gap        bool   `json:"gap"`
		GapSkipped uint64 `json:"gap_skipped"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		services.Logf("warn", "threat-screen events: decode failed: %v", err)
		c.JSON(http.StatusBadGateway, models.APIResponse{Code: 502, Message: "逐请求事件流响应格式无效"})
		return
	}
	// 国名与聚合端点/前端质心表同口径（geoipnames 单源）：Caddy 发射 xdb
	// 原始国名（英文），不翻译会让 COUNTRY_CENTROIDS 查找失败并落到海外兜底点。
	for i := range payload.Events {
		if name := geoipnames.CountryChinese(payload.Events[i].Country); name != "" {
			payload.Events[i].Country = name
		}
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: payload})
}

// GetThreatScreenTraffic GET /security/overview/threat-screen/traffic
// 大屏实时流量代理（Plan B）：读 Caddy admin 自定义端点 /lb/traffic-stats，
// 国名翻译中文（geoipnames 单源）+ Reserved/空/0 键过滤。1s TTL + singleflight
// 进程内缓存（key=admin URL，大屏 1-2s 轮询不对 admin 放大请求；失败不缓存）。
func (h *Handlers) GetThreatScreenTraffic(c *gin.Context) {
	data, ok := threatTrafficSnapshot(strings.TrimRight(h.cfg.CaddyAdminURL, "/"))
	if !ok {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: threatTrafficEmptyDegrade()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: data})
}

// fetchThreatTrafficSnapshot 抓取并翻译一次流量快照；任何失败（不可达/非
// 200/解码失败）ok=false 并告警——超时 2s，不阻塞大屏轮询协程。
func fetchThreatTrafficSnapshot(adminURL string) (gin.H, bool) {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(adminURL + "/lb/traffic-stats")
	if err != nil {
		services.Logf("warn", "threat-screen traffic: admin fetch failed: %v", err)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		services.Logf("warn", "threat-screen traffic: admin status %d", resp.StatusCode)
		return nil, false
	}
	var snap trafficSnapshot
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&snap); err != nil {
		services.Logf("warn", "threat-screen traffic: decode failed: %v", err)
		return nil, false
	}
	out := make(map[string]trafficCountry, len(snap.Countries))
	for country, entry := range snap.Countries {
		if country == "" || country == "Reserved" || country == "0" {
			continue
		}
		// 未收录的英文名由 CountryChinese 原样返回，无需再回退赋值
		// （前端质心表 miss 时按兜底位展示）。
		out[geoipnames.CountryChinese(country)] = entry
	}
	return gin.H{
		"countries": out,
		"available": true,
		"sample_n":  snap.SampleN,
		// 采集租约状态原样透传：无租约时计数冻结，前端据此提示而非把
		// 冻结的累计当作实时流量。
		"collecting": snap.Collecting,
	}, true
}

// threatBucketStep 是大屏滑动直方图槽（小时/日桶）的步长判据——仅
// threatHourlyBuckets 消费；rollup 落槽是分钟粒度固化，不使用本函数
// （调整桶步长不影响 rollup 聚合口径）。
func threatBucketStep(hours int) time.Duration {
	if hours <= 24 {
		return time.Hour
	}
	return 24 * time.Hour
}

// threatHourlyBuckets 生成威胁大屏滑动直方图槽（小时或日桶）；槽从真实
// 窗口起点等宽切分（标签=槽终点），避免整点/整日对齐把窗口前 sliver 钳入
// 首桶造成首柱跨度失真。hours<=24 为小时槽，否则日桶（上限 30）。
// 槽界为携带配置时区 loc 的真实时刻（逐槽本地边界，与总览趋势日桶的
// DST 修复同口径）——单一「当前偏移」平移在窗口跨 DST 切换点时会把切换
// 前的事件错配 1h 到相邻柱（默认 Asia/Shanghai 无 DST 不暴露）。
func threatHourlyBuckets(hours int, now time.Time, loc *time.Location) ([]time.Time, []models.SecurityAttackType) {
	nowLocal := now.In(loc)
	if hours < 1 {
		hours = 1
	}
	if hours > threatScreenMaxHours {
		hours = threatScreenMaxHours
	}
	windowStart := nowLocal.Add(-time.Duration(hours) * time.Hour)
	var bucketStarts []time.Time
	var bucketNames []string
	if threatBucketStep(hours) == time.Hour {
		for i := range hours {
			tb := windowStart.Add(time.Duration(i) * time.Hour)
			bucketStarts = append(bucketStarts, tb)
			bucketNames = append(bucketNames, tb.Add(time.Hour).Format("15:04"))
		}
	} else {
		n := (hours + 23) / 24
		if n > 30 {
			n = 30
		}
		for i := range n {
			tb := windowStart.AddDate(0, 0, i)
			bucketStarts = append(bucketStarts, tb)
			// 标签=槽终点但不得越过当前时刻：hours 非 24 整数倍时末槽终点
			// 会落到未来（如 30h → 窗口起点+2d = now+18h），柱状图末柱标签
			// 显示未来日期会被误读为时间轴越界。数据分桶由 threatBucketIndex
			// 末端钳制保证不错桶，此处只钳展示标签。
			labelEnd := tb.AddDate(0, 0, 1)
			if labelEnd.After(nowLocal) {
				labelEnd = nowLocal
			}
			bucketNames = append(bucketNames, labelEnd.Format("01-02"))
		}
	}
	hourly := make([]models.SecurityAttackType, len(bucketNames))
	for i := range hourly {
		hourly[i] = models.SecurityAttackType{Name: bucketNames[i], Value: 0}
	}
	return bucketStarts, hourly
}

// threatBucketIndex 把 UTC 事件时刻定位到槽：槽界是携带配置时区的真实时刻
// （DST 切换两侧各自正确），二分定位「最后一个不晚于 mt 的槽起点」；窗口前
// sliver 钳入首桶、窗口末尾之外钳入末桶（与旧钳位口径一致）。
func threatBucketIndex(mt time.Time, bucketStarts []time.Time) int {
	idx := sort.Search(len(bucketStarts), func(i int) bool { return mt.Before(bucketStarts[i]) }) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(bucketStarts) {
		idx = len(bucketStarts) - 1
	}
	return idx
}

// threatScreenZeroPayload 零值面板（MetricsDB 未装配）：键集与成功路径一致，
// top_targets 用与成功路径相同的元素类型（[]threatTopTarget，而非另一族
// SecurityAttackType）——空数组在 JSON 层无差别，但类型契约分叉会让后续
// 给零值面板补条目时静默产出缺字段的条目。
func threatScreenZeroPayload(hours int, now time.Time, loc *time.Location) gin.H {
	_, hourly := threatHourlyBuckets(hours, now, loc)
	return gin.H{
		"hours":                hours,
		"window_start":         "",
		"window_start_minute":  "",
		"rollup_stale":         threatRollupStale(),
		"rollup_last_success":  "",
		"rollup_coverage_from": "",
		"raw_coverage_from":    "",
		"raw_coverage_limited": false,
		"backfill_incomplete":  false,
		"total_events":         0,
		"blocked_events":       0,
		"logged_events":        0,
		"block_rate":           0.0,
		"ratelimit_blocks":     0.0,
		"ratelimit_available":  false,
		"active_sources":       0,
		"countries":            map[string]int{},
		"china_provinces":      map[string]int{},
		"top_countries":        []models.SecurityAttackType{},
		"top_attack_types":     []models.SecurityAttackType{},
		"top_rules":            []models.SecurityAttackType{},
		"top_targets":          []threatTopTarget{},
		"hourly_hist":          hourly,
		"attack_type_share":    []models.SecurityAttackType{},
		"recent_rate":          0.0,
		"ingestion":            services.SecurityEventsIngestionHealthSnapshot(),
	}
}

// GetSecurityThreatScreen GET /security/overview/threat-screen?hours=24
// 返回大屏聚合：窗口总量/拦截率/logged 数/限流拦截数（Caddy metrics 429，
// 重载口径）/活跃攻击源（近 10min 去重）/国家计数 map（ip_location 首段，
// 空归属跳过）/Top3 攻击国家、攻击类型与被攻击目标（top_targets，
// rule_caddy_id 分组 + lb_rules 名域）。任一安全库查询失败显式 500
// Caddy metrics 抓取失败降级
// 200——ratelimit_blocks=0 + ratelimit_available=false，其余维度照常
// （大屏 30s 轮询容忍指标瞬时不可达，可用性位披露）。
func (h *Handlers) GetSecurityThreatScreen(c *gin.Context) {
	hours := 24
	if raw := c.Query("hours"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 && n <= threatScreenMaxHours {
			hours = n
		}
	}
	now := threatScreenNow()
	loc := services.CurrentLocation()
	if db.MetricsDB == nil {
		// MetricsDB 未装配：零值面板 200 而非 panic
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: threatScreenZeroPayload(hours, now, loc)})
		return
	}

	since := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Second).Format("2006-01-02 15:04:05")
	activeSince := now.UTC().Add(-threatActiveSourceWindow).Truncate(time.Second).Format("2006-01-02 15:04:05")

	// 任一查询失败显式报错（单错误收敛，trackErr 同 GetSecurityOverview）
	var firstErr error
	trackErr := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// v2.3.8 rollup 路径：懒固化后单次扫描 rollup 产出全部维度（总量/拦截/
	// 国家/省/攻击族/规则/小时——原 5 条原始表窗口扫描合并为 1 条 rollup 扫
	// 描，与原始表规模解耦）。保留/私网已在固化时排除（口径不变）。
	// warmer 已启动时由后台协程承担固化（每 60s 一轮），请求路径不再常规懒
	// 固化（避免与用户请求抢写锁/重复回填）。修正
	//   - 首轮未完成或最近成功固化已陈旧（warmer 持续失败）→ 请求路径同步
	//     固化，不得把「已启动」当作「已有可用覆盖」；
	//   - 宽窗口（>24h）尚未覆盖到窗口起点 → 按持久 coverage 在请求路径补做
	//     旧侧分钟（单次有界批，后续轮询/ warmer 续做），7d 窗口不依赖恒
	//     24h 的 warmer。
	recordThreatRollupRequestedHours(hours)
	needsSync := !threatRollupWarmerStarted.Load() || threatRollupStale() ||
		(hours > 24 && !threatRollupCoverageReaches(hours))
	if needsSync {
		// 同步固化可能提交了部分批（错误路径同样会提交），读 rollup 分钟行的
		// 两份缓存（维度聚合 + top_targets）都必须失效：否则本次响应仍返回
		// 固化前的窗口数据。
		if err := ensureThreatRollup(hours); err != nil {
			trackErr(err)
		}
		invalidateThreatScreenRollupCaches()
	}
	// 宽窗口首轮只回填有界批数（threatRollupMaxBatchesPerCall），
	// 最近成功固化不代表窗口头部已覆盖——必须披露部分聚合，避免把少计的
	// 总量当作完整窗口返回。
	coverageFrom := ""
	backfillIncomplete := false
	windowStartMinute := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute)
	if coveredFrom, okCovered, cerr := loadThreatRollupState(db.MetricsDB, threatRollupCoveredFromKey); cerr != nil {
		trackErr(cerr)
	} else if okCovered {
		coverageFrom = coveredFrom.Format("2006-01-02 15:04")
		if coveredFrom.After(windowStartMinute) {
			backfillIncomplete = true
		}
	} else {
		backfillIncomplete = true
	}
	// 原始事件已被保留期/行帽裁剪时，缺失分钟的固化只能写 0——这是原始表的
	// 正常运维形态（保留天数 1..3650、行帽默认 100 万），与「rollup 可重建性」
	// 是两件事：rollup 行的保留期与事件保留期解耦且 ≥31 天，窗口数据完整。
	// 因此原始表最早事件只作信息提示（raw_coverage_limited），不参与
	// backfill_incomplete 判定，也不参与 30s 聚合缓存的可用性——把两个保留
	// 策略耦合会让高攻击站点（或短保留期部署）常驻「少计」告警并每次轮询
	// 重跑全窗口聚合。
	rawCoverageFrom := ""
	rawCoverageLimited := false
	if raw, err := threatRawCoverageStart(db.MetricsDB); err != nil {
		trackErr(err)
	} else {
		rawCoverageFrom = raw
		if rawCoverageFrom != "" && rawCoverageFrom > windowStartMinute.Format("2006-01-02 15:04:05") {
			rawCoverageLimited = true
			if coverageFrom == "" {
				// 异形 event_time（带外写库/异形导入）可能短于 19 字符：
				// 直接 [:16] 会 panic 整个处理器，统一走锚点 helper。
				coverageFrom = threatMinuteAnchor(rawCoverageFrom)
			}
		}
	}
	sinceMinute := now.UTC().Add(-time.Duration(hours) * time.Hour).Truncate(time.Minute).Format("2006-01-02 15:04")
	// 时间口径（勿再按「部分分钟」重报）：窗口总量/分桶/top 目标含当前分钟
	// 已固化的部分分钟（warmer 每轮恒固化 currentMinute，滞后 ≤60s）；只有
	// recent_rate 用「完整分钟」上界（固定 5 分钟除数，混入部分分钟会随秒数
	// 漂移）。两者的差异是有意设计，面板文案按「含当前分钟（截至最近固化）」
	// 描述。
	bucketStarts, hourly := threatHourlyBuckets(hours, now, loc)
	// 单次 SQL 侧聚合产出同屏全部维度（总量/拦截/国家/省/攻击族/规则/按槽
	// 分钟总量），30s 进程内缓存。旧实现逐行拉「分钟×维度基数」（30 天可达
	// 数百万行）到 Go 侧累加，宽窗口请求与 30s 轮询线性相乘。
	// 回填未完成（窗口头部尚未覆盖）时聚合不完整——本轮不缓存，避免少计
	// 结果在 30s 内被后续轮询复用。
	agg, aggErr := threatRollupDimAggregateQuery(db.MetricsDB, sinceMinute, bucketStarts, coverageFrom, !backfillIncomplete)
	trackErr(aggErr)
	total, blocked := agg.total, agg.blocked
	countries := agg.countries
	chinaProvinces := agg.chinaProvinces
	familyCounts := agg.familyCounts
	ruleCounts := agg.ruleCounts
	for i, value := range agg.bucketTotals {
		if i < len(hourly) {
			hourly[i].Value += value
		}
	}
	// 活跃攻击源：近 10min 去重 client_ip，保留/私网排除（与总量同口径）。
	// TTL 30s（与 30s 轮询同周期）：同一分钟锚点内命中一次，大屏轮询不再
	// 每轮重扫原始表。
	activeSources, activeErr := threatActiveSourcesCount(db.MetricsDB, activeSince, now)
	trackErr(activeErr)
	// top_targets：前 3 被攻击目标（读分钟 rollup 的目标
	// 维度，与 total/国家同窗口；原始表受保留期/行帽裁剪，不能作为旁路）
	topTargets, terr := threatTopTargets(sinceMinute, !backfillIncomplete)
	trackErr(terr)
	if firstErr != nil {
		services.Logf("error", "threat-screen query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁大屏数据查询失败"})
		return
	}

	// 限流拦截：Caddy /metrics 429 总计（与 GetSecurityRateLimitBlocks 同源）。
	// 抓取失败不再整卡 500——ratelimit_blocks=0 + ratelimit_available=false
	// 降级，其余维度照常 200（大屏轮询容忍指标瞬时不可达，可用性位披露）。
	blocks, err := services.ScrapeRateLimitBlocks(h.cfg.CaddyMetricsURL)
	ratelimitAvailable := true
	var ratelimit float64
	if err != nil {
		services.Logf("warn", "threat-screen scrape rate-limit blocks failed: %v", err)
		ratelimitAvailable = false
	} else {
		for _, block := range blocks {
			ratelimit += block.Count
		}
	}

	blockRate := 0.0
	if total > 0 {
		blockRate = float64(blocked) / float64(total) * 100
		// 一位小数（百分比展示口径）
		blockRate = float64(int(blockRate*10+0.5)) / 10
	}
	// recent_rate：近 5 个完整分钟 blocked/min（rollup 单前缀扫描；logged 不计）。
	// 当前未满分钟不参与——窗口跨度恒定 5.00 分钟（与 rollup 完整分钟语义一致）。
	nowMinute := threatScreenNow().UTC().Truncate(time.Minute)
	blocked5, rerr := queryThreatRecentBlocked(
		nowMinute.Add(-5*time.Minute).Format("2006-01-02 15:04"),
		nowMinute.Format("2006-01-02 15:04"),
	)
	trackErr(rerr)
	// 计算/响应前的最终错误检查——旧实现只在 rollup/active 扫描后
	// 检查一次，recent_rate 的 SUM 失败会被 200 响应吞掉（部分维度静默为 0）。
	// 产品语义保持整卡 500：不引入「部分卡片降级」的隐式可用性位。
	if firstErr != nil {
		services.Logf("error", "threat-screen query failed: %v", firstErr)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "威胁大屏数据查询失败"})
		return
	}
	recentRate := float64(int(float64(blocked5)/5.0*10+0.5)) / 10

	// logged_events = total - blocked（夹 >=0：口径防御，rollup 异常不输出负数）
	logged := total - blocked
	if logged < 0 {
		logged = 0
	}

	// 窗口起点（秒级，供前端展示）；rollup 陈旧度披露。
	// 就绪事实由 rollup_last_success 非空表达，前端以 rollup_stale 显示更新延迟。
	rollupLastSuccess := ""
	if threatRollupUsable() {
		rollupLastSuccess = time.Unix(0, threatRollupReadyAt.Load()).UTC().Format("2006-01-02 15:04:05")
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"hours":        hours,
		"window_start": since,
		// rollup 读取下界是分钟串（sinceMinute）：窗口起点前 <60s 的分钟段会
		// 计入总量/各维度与首柱——对外披露实际生效的分钟边界，避免调用方按
		// 秒级 window_start 推算「窗口内精确计数」。
		"window_start_minute": sinceMinute,
		"rollup_stale":        threatRollupStale(),
		"rollup_last_success": rollupLastSuccess,
		// 窗口头部覆盖披露——rollup_coverage_from 为已覆盖的最旧
		// 分钟；backfill_incomplete=true 表示本次响应的 total/各维度只覆盖
		// [rollup_coverage_from, now]，宽窗口回填仍在进行（后续轮询补齐）。
		"rollup_coverage_from": coverageFrom,
		"raw_coverage_from":    rawCoverageFrom,
		// 原始表覆盖受限（保留期/行帽裁剪）只作信息提示：窗口聚合来自 rollup，
		// 完整性与该标记无关（不参与 backfill_incomplete 与聚合缓存）。
		"raw_coverage_limited": rawCoverageLimited,
		"backfill_incomplete":  backfillIncomplete,
		"total_events":         total,
		"blocked_events":       blocked,
		"logged_events":        logged,
		"block_rate":           blockRate,
		"ratelimit_blocks":     ratelimit,
		"ratelimit_available":  ratelimitAvailable,
		"active_sources":       activeSources,
		"countries":            countries,
		"china_provinces":      chinaProvinces,
		"top_countries":        topThreatEntries(countries, 3),
		"top_attack_types":     topThreatEntries(familyCounts, 3),
		"top_rules":            topThreatEntries(labeledThreatRuleCounts(ruleCounts), 3),
		"top_targets":          topTargets,
		"hourly_hist":          hourly,
		"attack_type_share":    topThreatEntries(familyCounts, len(familyCounts)),
		"recent_rate":          recentRate,
		"ingestion":            services.SecurityEventsIngestionHealthSnapshot(),
	}})
}

// GetThreatScreenAttackFlow GET /security/overview/threat-screen/attack-flow
// 独立攻击流光流：只读内存环形缓冲，不扫描 security_events。安全事件日志
// 由 securityevents.go 全量落库，本端点仅供威胁大屏光流/弹框态势消费。
func (h *Handlers) GetThreatScreenAttackFlow(c *gin.Context) {
	since := uint64(0)
	if raw := c.Query("since"); raw != "" {
		if n, err := strconv.ParseUint(raw, 10, 64); err == nil {
			since = n
		}
	}
	limit := 200
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	events, next, gapSkipped := services.ThreatScreenAttackFlowSnapshot(since, limit)
	out := make([]gin.H, 0, len(events))
	for _, ev := range events {
		// 入口已排除保留地址（见 securityevents 入环前的同一判据）；此处保留
		// 兜底过滤，覆盖入环前收敛之前写入的旧条目。
		if isReservedIP(ev.ClientIP) {
			continue
		}
		location := enrichIPLocation(ev.ClientIP)
		country := ""
		province := ""
		if parts := strings.Split(location, "·"); len(parts) > 0 {
			country = parts[0]
			if len(parts) > 1 {
				province = parts[1]
			}
		}
		if country == "" {
			country = "未知"
		}
		out = append(out, gin.H{
			"seq":            ev.Seq,
			"at":             ev.At,
			"country":        country,
			"province":       province,
			"action":         ev.Action,
			"rule_triggered": ev.RuleTriggered,
			"weight":         ev.Weight,
		})
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"enabled":  services.ThreatScreenAttackFlowSampleN() > 0,
		"events":   out,
		"next_seq": next,
		"sample_n": services.ThreatScreenAttackFlowSampleN(),
		// 环形缓冲溢出导致的永久空洞（与正常光流同口径）：>0 表示本批之前
		// 有攻击事件未送达，前端须丢弃「连续光流」假设并跳到 next_seq 追赶。
		"gap":         gapSkipped > 0,
		"gap_skipped": gapSkipped,
	}})
}

// toastSummaryBetweenMaxAndAggregateForTest 仅测试注入的并发窗口钩子：在
// 「读 MAX(id)」与「聚合扫描」之间执行，用于钉住聚合上界（maxID 之后新落库
// 的事件不得计入本批）。生产恒为 nil（零成本）。
var toastSummaryBetweenMaxAndAggregateForTest func()

// GetSecurityEventToastSummary GET /security/events/toast-summary?since_id=N
// 弹框专用精确聚合：按游标扫描全部新安全事件，按「IP + 攻击类型 + 动作」
// 计数后返回摘要。事件列表仍走最新 N 条快照；本端点不受列表窗口截断影响。
func (h *Handlers) GetSecurityEventToastSummary(c *gin.Context) {
	sinceID := int64(0)
	if raw := c.Query("since_id"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			sinceID = n
		}
	}
	baseline := c.Query("baseline") == "1"
	limit := 20
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > 100 {
		limit = 100
	}
	empty := func(next int64) gin.H {
		return gin.H{"groups": []any{}, "next_id": next}
	}
	if db.MetricsDB == nil {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty(sinceID)})
		return
	}
	var maxID int64
	if err := db.MetricsDB.QueryRow(`SELECT COALESCE(MAX(id),0) FROM security_events`).Scan(&maxID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	if baseline {
		// 首次调用只给游标，不把历史事件回放成弹框；空库时下次 since=0
		// 仍按全量增量扫描（不会吞掉库中第一批真实攻击）。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty(maxID)})
		return
	}
	if sinceID > maxID {
		// 指标库重建/恢复导致 id 回退（客户端持有旧游标）：重新基线到当前
		// 库尾——返回 next_id=0 会让下一次轮询以 since_id=0 走全量增量扫描，
		// 把最多 1200 条历史事件当「新事件」弹框回放。与 baseline=1 的
		// 「只给游标不回放」语义对齐。
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty(maxID)})
		return
	}
	if sinceID == maxID {
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty(sinceID)})
		return
	}
	// 默认聚合上限：400 事件/秒 × 3s 轮询 ≈ 1200 条。超限时只聚合最新
	// 1200 条并推进到 maxID（跳过更老的弹框展示，安全日志仍完整）。这样
	// 2000/s 洪峰下 SQL 扫描与临时分组有硬上限，不会随积压无限增长。
	const toastSummaryMaxEvents = 400 * 3
	// 聚合上界必须固定为本次读到的 maxID：否则「读 MAX(id) 之后、聚合执行
	// 之前」新落库的事件会被计入本批，而 next_id 仍推进到 maxID——下一轮
	// 从 maxID 起重扫，同一事件被弹框两次（洪峰下每轮重复 1~10 条）。
	if hook := toastSummaryBetweenMaxAndAggregateForTest; hook != nil {
		hook()
	}
	rows, err := db.MetricsDB.Query(`
		SELECT client_ip, action, COALESCE(rule_triggered,''), COALESCE(rule_msg,''),
		       COUNT(*), MAX(id), AVG(COALESCE(duration_us,0))
		FROM (
			SELECT client_ip, action, rule_triggered, rule_msg, duration_us, id
			FROM security_events
			WHERE id > ? AND id <= ? AND event_time >= datetime('now','-5 minutes')
			  AND `+services.AttackEventSQLPredicate("rule_triggered", "action")+`
			ORDER BY id DESC
			LIMIT ?
		)
		GROUP BY client_ip, action, rule_triggered, rule_msg
		ORDER BY COUNT(*) DESC, MAX(id) DESC
		LIMIT 200`, sinceID, maxID, toastSummaryMaxEvents)
	if err != nil {
		services.Logf("error", "security event toast summary: query failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	defer rows.Close()

	type summary struct {
		ClientIP      string  `json:"client_ip"`
		IPLocation    string  `json:"ip_location"`
		Action        string  `json:"action"`
		AttackType    string  `json:"attack_type"`
		Count         int64   `json:"count"`
		LastID        int64   `json:"last_id"`
		AvgDurationUS float64 `json:"avg_duration_us"`
	}
	merged := make(map[string]*summary)
	for rows.Next() {
		var ip, action, ruleTriggered, ruleMsg string
		var count, lastID int64
		var avgDuration float64
		if err := rows.Scan(&ip, &action, &ruleTriggered, &ruleMsg, &count, &lastID, &avgDuration); err != nil {
			services.Logf("error", "security event toast summary: scan failed: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
			return
		}
		if isReservedIP(ip) {
			continue
		}
		attackType := categorizeAttack(ruleTriggered, ruleMsg)
		key := ip + "\x00" + action + "\x00" + attackType
		cur := merged[key]
		if cur == nil {
			cur = &summary{
				ClientIP:   ip,
				IPLocation: enrichIPLocation(ip),
				Action:     action,
				AttackType: attackType,
				LastID:     lastID,
			}
			merged[key] = cur
		}
		if cur.LastID < lastID {
			cur.LastID = lastID
		}
		total := cur.Count + count
		cur.AvgDurationUS = (cur.AvgDurationUS*float64(cur.Count) + avgDuration*float64(count)) / float64(total)
		cur.Count = total
	}
	if err := rows.Err(); err != nil {
		services.Logf("error", "security event toast summary: rows iteration failed: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
		return
	}
	groups := make([]*summary, 0, len(merged))
	for _, item := range merged {
		groups = append(groups, item)
	}
	sort.Slice(groups, func(i, j int) bool {
		if groups[i].Count != groups[j].Count {
			return groups[i].Count > groups[j].Count
		}
		return groups[i].LastID > groups[j].LastID
	})
	if len(groups) > limit {
		groups = groups[:limit]
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"groups":  groups,
		"next_id": maxID,
	}})
}

// GetSecurityEventFeed GET /security/events/feed?since_id=N&limit=50
// 大屏增量事件流（升序无漏语义），含归属地/攻击族富化（enrichIPLocation +
// categorizeAttack 单源）。limit 缺省 50、上限 200。
//   - since_id=0（首屏）：返回**最新** limit 条（降序扫描收集、响应按 id
//     升序输出），next_since_id=返回集最大 id，has_more=false（首屏不回溯
//     更老）；
//   - since_id>0（增量）：WHERE id > cursor ORDER BY id ASC 逐页扫描直至
//     凑满 limit 或到顶——>limit 积压分多次拉取无重无漏；has_more=本页
//     填满且可能还有更新未返回；
//   - 保留/私网 IP 过滤但游标照常推进（next_since_id=本批实际扫描到的
//     最大 id，含被过滤行）；单请求最多 20 页有界扫描。
func (h *Handlers) GetSecurityEventFeed(c *gin.Context) {
	const (
		defaultLimit = 50
		maxLimit     = 200
	)
	sinceID := int64(0)
	if raw := c.Query("since_id"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			sinceID = n
		}
	}
	limit := defaultLimit
	if raw := c.Query("limit"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			limit = n
		}
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	empty := func() gin.H {
		return gin.H{"events": []models.SecurityEventFeedItem{}, "since_id": sinceID, "next_since_id": sinceID, "limit": limit, "has_more": false}
	}
	if db.MetricsDB == nil {
		// MetricsDB 未装配：空列表 200 而非 panic
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: empty()})
		return
	}
	if sinceID > 0 {
		var maxID int64
		if err := db.MetricsDB.QueryRow(`SELECT COALESCE(MAX(id),0) FROM security_events`).Scan(&maxID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
			return
		}
		if sinceID > maxID {
			// 指标库重建/恢复后旧游标高于库尾：回到当前高水位，
			// 后续新事件即可从该游标继续增量消费。
			c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": []models.SecurityEventFeedItem{}, "since_id": sinceID, "next_since_id": maxID, "limit": limit, "has_more": false}})
			return
		}
	}
	// 游标高水位——next_since_id = 本批**实际扫描到的最大 id**
	//（含被保留地址过滤掉的行），分页循环扫描直至凑满 limit 或到顶。
	events := make([]models.SecurityEventFeedItem, 0, limit)
	nextSinceID := sinceID
	const maxScanPages = 20 // 有界扫描：洪峰下不让单请求无限翻页

	scanFailed := false
	// scanPage 执行一页查询：扫描/富化/保留地址过滤，追加到 events 并推进
	// nextSinceID；返回 (本页扫描行数, 本页末行 id)。任何失败置 scanFailed。
	scanPage := func(query string, args ...any) (int, int64) {
		rows, err := db.MetricsDB.Query(query, args...)
		if err != nil {
			services.Logf("error", "security event feed: query failed: %v", err)
			scanFailed = true
			return 0, 0
		}
		defer rows.Close()
		scanned := 0
		lastID := int64(0)
		for rows.Next() {
			scanned++
			var e models.SecurityEventFeedItem
			var ruleTriggered, ruleMsg string
			// Scan 失败必须中止
			if err := rows.Scan(&e.ID, &e.EventTime, &e.ClientIP, &e.Action, &e.RuleName, &ruleTriggered, &ruleMsg, &e.EventType, &e.DurationUs, &e.AnomalyScore); err != nil {
				services.Logf("error", "security event feed: scan failed: %v", err)
				scanFailed = true
				return scanned, lastID
			}
			lastID = int64(e.ID)
			if int64(e.ID) > nextSinceID {
				nextSinceID = int64(e.ID)
			}
			e.IPLocation = enrichIPLocation(e.ClientIP)
			// 保留/私网 IP 不进大屏事件流（v4 裁定，与聚合口径一致）；游标
			// 语义不受影响——next_since_id 恒为已扫描最大 id，被过滤行只是跳过。
			if isReservedIP(e.ClientIP) {
				continue
			}
			// 爬虫放行不是攻击：不进大屏事件流（与聚合口径一致）；游标照常
			// 推进——next_since_id 恒为已扫描最大 id，被过滤行只是跳过。
			if !services.SecurityEventCountsAsAttack(e.Action, ruleTriggered) {
				continue
			}
			e.AttackType = categorizeAttack(ruleTriggered, ruleMsg)
			e.RuleTriggered = ruleTriggered
			e.TriggerType = triggerTypeForRule(ruleTriggered)
			events = append(events, e)
		}
		if err := rows.Err(); err != nil {
			services.Logf("error", "security event feed: rows iteration failed: %v", err)
			scanFailed = true
		}
		return scanned, lastID
	}

	const selectCols = `SELECT id, event_time, client_ip, action, COALESCE(rule_name,''), COALESCE(rule_triggered,''), COALESCE(rule_msg,''), COALESCE(event_type,''), COALESCE(duration_us,0), COALESCE(anomaly_score,0)
		FROM security_events`
	hasMore := false
	if sinceID <= 0 {
		// 首屏：从最新行降序扫描收集 limit 条（保留地址过滤时向更老续扫），
		// 收集完成后整体反转为 id 升序输出；has_more 恒 false（不回溯更老）。
		upperBound := int64(0) // 0=无上界；首页后改为「上一页最小 id」，继续向更老行扫描
		for page := 0; page < maxScanPages && len(events) < limit; page++ {
			pageLimit := limit - len(events)
			query := selectCols + ` WHERE id > 0`
			var args []any
			if upperBound > 0 {
				query += ` AND id < ?`
				args = append(args, upperBound)
			}
			query += ` ORDER BY id DESC LIMIT ?`
			args = append(args, pageLimit)
			scanned, lastID := scanPage(query, args...)
			if scanFailed {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
				return
			}
			if lastID > 0 {
				upperBound = lastID // 继续向更老的行扫描（首页上界=0 表示从最新行开始）
			}
			if scanned < pageLimit {
				break // 已到顶（本页未填满 = 没有更老的行）
			}
		}
		for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
			events[i], events[j] = events[j], events[i]
		}
	} else {
		// 增量：id > cursor 升序逐页扫描直至凑满 limit 或到顶（无重无漏）。
		cursor := sinceID
		lastPageFull := false
		for page := 0; page < maxScanPages && len(events) < limit; page++ {
			pageLimit := limit - len(events)
			scanned, lastID := scanPage(selectCols+` WHERE id > ? ORDER BY id ASC LIMIT ?`, cursor, pageLimit)
			if scanFailed {
				c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "安全事件查询失败"})
				return
			}
			if lastID > 0 {
				cursor = lastID
			}
			lastPageFull = scanned == pageLimit
			if scanned < pageLimit {
				break // 已到顶（本页未填满 = 没有更新的行）
			}
		}
		// has_more：末页填满且游标已推进 = 可能还有更新未返回（下次轮询以
		// next_since_id 续拉）
		hasMore = lastPageFull && nextSinceID > sinceID
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"events": events, "since_id": sinceID, "next_since_id": nextSinceID, "limit": limit, "has_more": hasMore}})
}

// triggerTypeForRule 触发类型显示映射（v2.3.8 单源）：阶段 id → 业务语义类型。
// 爬虫事件独立于地域拦截（豁免/伪装不再落「IP 访问控制」桶，消除歧义）；
// WAF 拆 CRS/自定义（普通、旧版合成与 OR 分支均归自定义；
// 900000-999999=CRS）；固定 id（429/2/3/4/5/7/8/11/12/14）的族归属统一取
// legacyRuleFamilies（与总览攻击族分桶、事件页族筛选同源）。
func triggerTypeForRule(ruleTriggered string) string {
	// 预检段家族判定经 services.PrecheckRuleFamilyOf 单一事实源（段界
	// 字面量禁止复写——段基址调整时 handlers 不得静默分叉）。
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return "其他"
	}
	switch services.PrecheckRuleFamilyOf(n) {
	case services.PrecheckRuleFamilyGeoIP:
		return "地域拦截"
	case services.PrecheckRuleFamilyCrawlerExempt, services.PrecheckRuleFamilyCrawlerSpoof:
		return "爬虫Bot"
	}
	switch {
	case n >= services.GeoIPPrecheckSegmentLimit && n < services.SyntheticCustomRuleIDBase:
		return "WAF·CRS"
	case n >= 10000 && n < services.GeoIPPrecheckSegmentBase, n >= services.SyntheticCustomRuleIDBase:
		return "WAF·自定义"
	}
	if family := legacyRuleFamilyOf(n); family.key != "" {
		return family.key
	}
	return "其他"
}
