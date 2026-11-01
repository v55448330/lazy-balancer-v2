package services

// 正常请求日聚合持久化（2026-11）采集侧单源：
//   - accumulateDailyAgg：30s 采集轮在 storePerRuleMetrics 之后调用，把
//     「checkpoint → 当前累计」的钳制差分增量按本地日历日 UPSERT 进
//     metrics_daily_agg 并推进 checkpoint（单事务 + 进程内互斥，30s daemon
//     轮与重载前快照并发不双计）；
//   - TriggerImmediateMetricsCollection：重载前快照——Caddy /load 重建
//     metrics registry 使计数器归零，apply 链在真实 /load 前同步执行一轮
//     完整采集，使最后一段增量在归零前入账（消灭 ≤30s 盲区）。
//
// 表语义（metrics_daily_agg / metrics_counter_checkpoint）见 internal/db
// 建表注释；读路径（总览正常请求）在 handlers securityOverviewNormalHTTPDiff。

import (
	"fmt"
	"strings"
	"time"

	"lazy-balancer-v2/internal/db"
)

// metricsDailyAggDateLayout 本地日历日文本（写入与总览读窗口同源）。
const metricsDailyAggDateLayout = "2006-01-02"

// metricsFailureDailyAgg 日聚合累加失败族（状态转换日志 key，与 metrics
// 采集族同口径：首失败 warn、恢复 info、持续静默）。失败不致命——历史行
// 已落库，checkpoint 未推进，下一成功轮把两段增量一次补齐（自愈）。
const metricsFailureDailyAgg = "daily-agg"

// accumulateDailyAgg 把本轮 per-rule 累计快照与 checkpoint 的钳制差分增量
// 累加进 metrics_daily_agg（当日）并推进 checkpoint。
//
// 语义：
//   - 冷启动（规则无 checkpoint 行）：只记基线不落增量——metrics_history
//     计数器是 Caddy 启动以来的累计值，整段落成当日增量会虚高（与 L4
//     consumeL4Delta 首轮口径一致）；
//   - 计数器归零（cur < checkpoint，/load 重载/重启形态）：增量取 cur
//     （归零后全部为新增量，复用 DeltaUint64 单一钳制实现）；
//   - 规则删除后 checkpoint 行残留无害（无新样本比对，不参与读路径求和）。
//
// 错误上抛交调用方状态转换日志；checkpoint 推进与聚合累加同事务——聚合
// 写失败时 checkpoint 一并回滚，下轮重新结算同一区间，不丢不重。
func (m *MetricsService) accumulateDailyAgg(byRule map[string]*ruleLabelAggregate) error {
	return m.accumulateDailyAggAt(byRule, time.Now())
}

// accumulateDailyAggAt 是 accumulateDailyAgg 的显式时刻变体（测试注入采集
// 时刻以覆盖日界跨天；生产路径经 accumulateDailyAgg 传 time.Now）。local_date
// 按配置时区（CurrentLocation）取日历日——总览读窗口同源，双端一致。
func (m *MetricsService) accumulateDailyAggAt(byRule map[string]*ruleLabelAggregate, now time.Time) error {
	if db.MetricsDB == nil {
		return errMetricsDBUnavailable
	}
	if len(byRule) == 0 {
		return nil
	}
	// 进程内互斥：30s daemon 轮与重载前快照（apply 链）并发时，读
	// checkpoint→算增量→落账必须串行，否则两轮各读到同一旧 checkpoint 双计。
	m.dailyAggMu.Lock()
	defer m.dailyAggMu.Unlock()

	localDate := now.In(CurrentLocation()).Format(metricsDailyAggDateLayout)
	ruleIDs := make([]string, 0, len(byRule))
	for ruleID := range byRule {
		ruleIDs = append(ruleIDs, ruleID)
	}
	prev, err := loadCounterCheckpoints(ruleIDs)
	if err != nil {
		return fmt.Errorf("load metrics counter checkpoints: %w", err)
	}

	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return fmt.Errorf("begin daily agg batch: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	aggStmt, err := tx.Prepare(`
		INSERT INTO metrics_daily_agg (rule_id, local_date, requests_delta, blocked_delta, logged_delta)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(rule_id, local_date) DO UPDATE SET
			requests_delta = requests_delta + excluded.requests_delta,
			blocked_delta = blocked_delta + excluded.blocked_delta,
			logged_delta = logged_delta + excluded.logged_delta
	`)
	if err != nil {
		return fmt.Errorf("prepare daily agg upsert: %w", err)
	}
	defer func() { _ = aggStmt.Close() }()
	cpStmt, err := tx.Prepare(`
		INSERT INTO metrics_counter_checkpoint (rule_id, requests_total, requests_blocked, requests_logged)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(rule_id) DO UPDATE SET
			requests_total = excluded.requests_total,
			requests_blocked = excluded.requests_blocked,
			requests_logged = excluded.requests_logged
	`)
	if err != nil {
		return fmt.Errorf("prepare checkpoint upsert: %w", err)
	}
	defer func() { _ = cpStmt.Close() }()

	for ruleID, agg := range byRule {
		baseline := prev[ruleID]
		// DeltaUint64 单一钳制实现：cur<prev（归零）取 cur，否则 cur−prev。
		dTotal := int64(DeltaUint64(nonNegativeCounter(agg.requests), nonNegativeCounter(baseline.requests)))
		dBlocked := int64(DeltaUint64(nonNegativeCounter(agg.blocked), nonNegativeCounter(baseline.blocked)))
		dLogged := int64(DeltaUint64(nonNegativeCounter(agg.logged), nonNegativeCounter(baseline.logged)))
		if _, hasBaseline := prev[ruleID]; !hasBaseline {
			// 冷启动：基线轮只记 checkpoint 不落增量（累计值非增量）。
			dTotal, dBlocked, dLogged = 0, 0, 0
		} else if dTotal != 0 || dBlocked != 0 || dLogged != 0 {
			// 零增量轮跳过聚合写（checkpoint 不动）；有增量才 UPSERT。
			if _, err := aggStmt.Exec(ruleID, localDate, dTotal, dBlocked, dLogged); err != nil {
				return fmt.Errorf("accumulate daily agg for %s: %w", ruleID, err)
			}
		}
		if _, err := cpStmt.Exec(ruleID, agg.requests, agg.blocked, agg.logged); err != nil {
			return fmt.Errorf("advance counter checkpoint for %s: %w", ruleID, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit daily agg batch: %w", err)
	}
	return nil
}

// counterCheckpoint 是单规则三列累计的已入账水位。
type counterCheckpoint struct {
	requests, blocked, logged int64
}

// nonNegativeCounter 把解析侧可能出现的负值计数钳到 0（畸形 exposition 负数
// 不得经 uint64 往返变成巨额增量，污染不可逆累加的日聚合）。正常 Prometheus
// counter 恒非负，本函数是防污染护栏而非语义通道。
func nonNegativeCounter(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

// loadCounterCheckpoints 读给定规则的已入账水位（无行规则不入 map=冷启动）。
func loadCounterCheckpoints(ruleIDs []string) (map[string]counterCheckpoint, error) {
	out := make(map[string]counterCheckpoint, len(ruleIDs))
	for start := 0; start < len(ruleIDs); start += 500 {
		end := start + 500
		if end > len(ruleIDs) {
			end = len(ruleIDs)
		}
		batch := ruleIDs[start:end]
		placeholders := make([]string, len(batch))
		args := make([]any, len(batch))
		for i, id := range batch {
			placeholders[i] = "?"
			args[i] = id
		}
		rows, err := db.MetricsDB.Query(`SELECT rule_id, requests_total, requests_blocked, requests_logged
			FROM metrics_counter_checkpoint WHERE rule_id IN (`+strings.Join(placeholders, ",")+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ruleID string
			var cp counterCheckpoint
			if err := rows.Scan(&ruleID, &cp.requests, &cp.blocked, &cp.logged); err != nil {
				rows.Close()
				return nil, err
			}
			out[ruleID] = cp
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}
	return out, nil
}

// TriggerImmediateMetricsCollection 同步执行一轮完整指标采集（重载前快照）。
// apply 链（applyConfigWithOptions）在真实 /load 前调用：/load 重建
// metrics registry 使 lazybalancer_* 计数族归零，重载前未结算的增量借此在
// 归零前完成「快照→差分→日聚合入账→checkpoint 推进」。采集服务未接线
// （启动早期/测试/嵌入形态）时 no-op。同步执行：/metrics 抓取预算 5s，
// 重载写路径为此最多阻塞一个抓取预算——换取统计零丢失（方案裁定）。
// 采集内部失败按状态转换口径留痕（warn 一次），不阻断重载。
func TriggerImmediateMetricsCollection() {
	m := currentMetricsCollector()
	if m == nil {
		return
	}
	m.collect()
}
