package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"time"

	"lazy-balancer-v2/internal/db"
)

const (
	// 默认保留与操作日志同口径 90 天(3 个月)——
	// 原 30 天静默分裂(读 DB 失败/0 值时静默降级 30 天,兄弟组件 90 天)。
	// 默认值单源=db.Default*（DDL/启动迁移/读侧
	// COALESCE/导入归一同一常量族），本包别名仅供包内可读性。
	securityEventsRetentionDefaultDays = db.DefaultSecurityEventsRetentionDays
	securityEventsRetentionDefaultMax  = db.DefaultSecurityEventsRowCap // 2026-09-14 用户裁定:10 万→100 万(索引全覆盖,无查询性能影响)
	// securityEventsRetentionDeleteBatch 是年龄裁剪与 count 超限裁剪共用的单批
	// 删除行数（E 起年龄裁剪亦按此批次执行，同口径）：大批量单语句 DELETE
	// 会长时间持指标库写锁，阻塞摄取 tick。
	// v2.3.8 批次上调（100/s 压力设计：摊销删除吞吐翻四倍，批间让写锁）
	securityEventsRetentionDeleteBatch = 20000
)

// ThreatRollupEventHighwaterPrefix 分钟事件高水位键前缀（单源）：写入侧=大屏
// rollup 固化（handlers 包引用本常量），清理侧=保留任务按同一 rollupCutoff
// 删除——两处不得各自硬编码。
const ThreatRollupEventHighwaterPrefix = "threat_rollup_max_event_id:"

// 大屏 rollup 的覆盖/状态键（metrics_state）。定义在本包是因为保留清理必须
// 读取同一批键来判定「预聚合首轮/代际回填是否就绪」——写侧（handlers）与
// 清理侧各自硬编码会让就绪判据随任一侧改名而静默失效。
const (
	// ThreatRollupWatermarkKey 已覆盖区间的最新完整分钟。
	ThreatRollupWatermarkKey = "threat_rollup_last_fixed_minute"
	// ThreatRollupCoveredFromKey 已覆盖区间的最旧分钟。
	ThreatRollupCoveredFromKey = "threat_rollup_covered_from"
	// ThreatRollupTargetReadyKey 目标维度 rollup 就绪标记（缺失=从未成功固化）。
	ThreatRollupTargetReadyKey = "threat_rollup_target_ready"
	// ThreatRollupRebuildFromKey 未完成的全量重建意图起点（存在=回填未走完）。
	ThreatRollupRebuildFromKey = "threat_rollup_rebuild_from"
	// ThreatRollupLateBaselinePrefix 回退时被删除的分钟事件高水位在此留底：
	// 高水位删掉后下一次固化走全量重算，而「已计入行」与「迟到行」只能靠该
	// 基线区分（原始行被裁剪/含旧口径行时全量重算总量小于已固化总量，迟到
	// 行必须按 id > 基线 合并，否则永久不入聚合）。与高水位键同生命周期清理。
	ThreatRollupLateBaselinePrefix = "threat_rollup_late_baseline:"
)

// SecurityEventsRetentionSnapshot 一次读取策略并返回（面板摘要, 行数上限）：
// 日志统计面板同一响应内需同时展示两项，收敛为单次
// global_config 点查（此前 Summary 与 Max 各读一遍同一条 SQL）。
// 摘要必须同时表达 Days 与 Max 双口径——cleanup
// 按 count-max 裁剪，只写「保留 N 天」会让行帽提前裁剪的用户可见文案与实际
// 行为漂移（securityEventsRetentionPolicy 本就 Days+Max 双口径）。
// 行帽按行不按字节：单行最坏 ≈ 请求头 64KiB + 请求体 64KiB + URI 8KiB +
// rule_msg 2KiB（采集上限 securityEvents*Cap，另有文本截断标记）——摘要
// 披露理论体积上限，避免「100 万行」被误读为固定小体积。
func SecurityEventsRetentionSnapshot() (string, int) {
	policy, _ := securityEventsRetentionPolicyFromDB()
	return fmt.Sprintf("每日清理 · 保留 %d 天 / 上限 %d 行（按行计，单行最大约 %s，理论体积上限约 %s）",
		policy.Days, policy.Max, securityEventsRowMaxLabel(), securityEventsRowCapByteBudget(policy.Max)), policy.Max
}

// securityEventsRowMaxLabel 是单行上限的披露文案（KiB 取整，与摘要同单位）。
// 计数源为 securityEventsRowMaxBytes——新增采集字段时披露自动跟随。
func securityEventsRowMaxLabel() string {
	return fmt.Sprintf("%dKiB", securityEventsRowMaxBytes()/(1<<10))
}

// securityEventsRowCapByteBudget 行帽对应的理论体积上限（单行按
// securityEventsRowMaxBytes 计，索引/元数据余量忽略——披露用约数，
// 非配额语义）。
func securityEventsRowCapByteBudget(rowCap int) string {
	bytes := int64(rowCap) * securityEventsRowMaxBytes()
	switch {
	case bytes >= 1<<30:
		return fmt.Sprintf("%d GiB", bytes/(1<<30))
	case bytes >= 1<<20:
		return fmt.Sprintf("%d MiB", bytes/(1<<20))
	default:
		return fmt.Sprintf("%d KiB", bytes/(1<<10))
	}
}

// securityEventsRetentionPolicy 是安全事件保留策略的解析结果（单源——清理体、
// 行帽展示与面板摘要共用同一次读逻辑，避免多处口径分裂）。
type securityEventsRetentionPolicy struct {
	Days int // 生效保留天数
	Max  int // 生效行数上限
}

// securityEventsRetentionPolicyFromDB 读取安全事件保留策略（独立配置项）：
// security_events_retention_days / security_events_row_cap；0/缺省使用内置
// 默认 90 天 / 100 万行。审计日志保留月数只作用于 audit_logs，不参与本表。
//
// 写侧拒绝 0（retention 1..3650、row_cap 1..1e8），
// 导入把 0 归一为默认值，SVC 以一次性 marker 迁移存量 0/NULL。读侧保留本
// 0/NULL → 内置默认的 legacy 防御（带外写库/旧库），行为不变——不回写、不
// 改写库值。
func securityEventsRetentionPolicyFromDB() (securityEventsRetentionPolicy, error) {
	policy := securityEventsRetentionPolicy{Days: securityEventsRetentionDefaultDays, Max: securityEventsRetentionDefaultMax}
	database := db.DB
	if database == nil {
		return policy, errors.New("security events retention: main database is unavailable")
	}
	var explicitDays, explicitCap int
	if err := database.QueryRow(`SELECT COALESCE(security_events_retention_days,0), COALESCE(security_events_row_cap,0) FROM global_config WHERE id=1`).Scan(&explicitDays, &explicitCap); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return policy, nil
		}
		// 面板摘要可显示默认值，但清理调用方必须拿到错误并暂停删除。
		if lvl := logStateTransition("security-events-retention-read", true); lvl != "" {
			Logf(lvl, "security events retention: read retention settings failed, falling back to %d days: %v", policy.Days, err)
		}
		return policy, err
	}
	if lvl := logStateTransition("security-events-retention-read", false); lvl != "" {
		Logf(lvl, "security events retention: retention settings read recovered")
	}
	if explicitDays > 0 {
		policy.Days = explicitDays
	}
	if explicitCap > 0 {
		policy.Max = explicitCap
	}
	return policy, nil
}

// securityEventsRetentionSettings 读取保留策略（天数, 行帽）——展示与默认值钉测消费。
func securityEventsRetentionSettings() (days, max int) {
	policy, _ := securityEventsRetentionPolicyFromDB()
	return policy.Days, policy.Max
}

// threatRollupBackfillPending 判定大屏预聚合（rollup）首轮/代际重建是否仍在
// 进行。就绪判据只看 metrics_state 的存在性（无需与 handlers 侧的代际版本
// 常量比较，避免跨包依赖）：重建意图键**存在**=全量重建未走完；目标维度就绪/
// 覆盖底端/覆盖水位任一**缺失**=从未完成过一次固化。空值按缺失处理（损坏状态
// 等同未就绪，行帽最多延后一轮）。
func threatRollupBackfillPending(database *sql.DB) (bool, error) {
	nonEmpty := func(key string) (bool, error) {
		var present int
		err := database.QueryRow(`SELECT 1 FROM metrics_state WHERE key=? AND TRIM(COALESCE(value,''))<>'' LIMIT 1`, key).Scan(&present)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	}
	// 重建键「存在即 pending」：空/空白值属于损坏的半写状态，不能被
	// 解读为无重建意图，否则其余 ready 键齐全时会误删尚未固化的原始事件。
	var rebuildMarker int
	err := database.QueryRow(`SELECT 1 FROM metrics_state WHERE key=? LIMIT 1`, ThreatRollupRebuildFromKey).Scan(&rebuildMarker)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	if err == nil {
		return true, nil
	}
	for _, key := range []string{
		ThreatRollupTargetReadyKey,
		ThreatRollupCoveredFromKey,
		ThreatRollupWatermarkKey,
	} {
		present, err := nonEmpty(key)
		if err != nil {
			return false, err
		}
		if !present {
			return true, nil
		}
	}
	return false, nil
}

// 保留策略是安全事件历史的**唯一有意**删除路径：事件存放在 metrics 库
// （不是可丢弃遥测——同库 metrics_history 可再生，事件历史不可再生），库损坏
// 隔离重建属意外丢失，由 db 层显式披露并留痕（db.reportMetricsQuarantine）。
// 天数与行帽双口径同时生效：先按年龄删，再按行帽裁剪最旧行。
//
// securityEventsRetentionCleanup deletes events older than the configured
// retention window, then trims the oldest rows while the table still holds
// more rows than the configured maximum. The DB handle is captured locally so
// a concurrent test teardown (db.DB = nil) cannot nil-deref mid-pass.
// 批间让出写锁的等待同时检查 ctx——Stop（cancel 后等待 worker 退出）
// 得以在大批量首遍（如数据恢复后的百万行）中及时中止，不再被拖到 docker
// SIGKILL 跳过 db.Close。
// SecurityEventsRetentionResult 单轮保留清理的各表删除量。任务日志必须按
// 构成披露：聚合/高水位删除不计入事件数时，停摆后首次清理在事件表无过期行
// 的形态会显示「删除 0 条」，运维据此误判保留策略未生效。
type SecurityEventsRetentionResult struct {
	Events       int // security_events 行
	Rollup       int // security_event_rollup 行
	TargetRollup int // security_event_target_rollup 行
	Highwater    int // metrics_state 分钟 rollup 状态键（事件高水位 + 迟到基线）
	// AgeDeferred / RowCapDeferred 表示原始事件的年龄/行帽裁剪被 rollup
	// 就绪门跳过；两类删除都会让尚未固化的分钟永久缺计，必须同门。
	AgeDeferred    bool
	RowCapDeferred bool
}

// Aggregates 聚合派生数据的删除量（三类之和）。
func (r SecurityEventsRetentionResult) Aggregates() int {
	return r.Rollup + r.TargetRollup + r.Highwater
}

// SecurityEventsRetentionCleanupDetail 是单轮清理的唯一入口（任务体传
// rc.Ctx：批间 ctx.Done() 分支才在生产可达，停机时百万行清理可及时中止，
// 不拖过宽限期被 SIGKILL 跳过 db.Close/WAL 落盘），返回事件/聚合/高水位
// 各表删除量与首个清理错误（供任务引擎把失败写进 task_runs）。
// 只返回事件数的兼容包装已删除——生产任务体只用本函数，其余形态没有调用方。
func SecurityEventsRetentionCleanupDetail(ctx context.Context) (SecurityEventsRetentionResult, error) {
	return securityEventsRetentionCleanup(ctx)
}

func securityEventsRetentionCleanup(ctx context.Context) (SecurityEventsRetentionResult, error) {
	var result SecurityEventsRetentionResult
	database := db.MetricsDB
	if database == nil {
		return result, nil
	}
	policy, err := securityEventsRetentionPolicyFromDB()
	if err != nil {
		Logf("warn", "security events retention: deferring all deletion because retention settings are unavailable: %v", err)
		return result, err
	}
	days, max := policy.Days, policy.Max
	// 年龄与行帽都会删除不可再生的原始事件，必须共同等待预聚合首轮/
	// 代际回填完成。就绪判据读失败同样按未就绪处理，宁可晚一轮清理。
	if pending, perr := threatRollupBackfillPending(database); perr != nil {
		result.AgeDeferred = true
		result.RowCapDeferred = true
		// 就绪判据读失败=metrics 库/状态表异常：不得静默成功（任务必须落 failed
		// 并退避重试），否则「清理未执行」会被审计成成功轮。
		Logf("warn", "security events retention: rollup backfill readiness unknown (%v), age and row-cap trims deferred", perr)
		return result, fmt.Errorf("读取预聚合就绪状态失败（清理未执行）: %w", perr)
	} else if pending {
		result.AgeDeferred = true
		result.RowCapDeferred = true
		Logf("info", "security events retention: 预聚合回填未完成，年龄与行帽裁剪本轮跳过（待回填完成后执行）")
	}
	if !result.AgeDeferred {
		// 年龄裁剪同样分批执行（与 count 裁剪同口径）：大表单条 DELETE 长时间持
		// 指标库写锁，阻塞摄取 tick。
		for {
			res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events WHERE event_time < datetime('now', printf('-%d days', ?)) ORDER BY id ASC LIMIT ?)`, days, securityEventsRetentionDeleteBatch)
			if err != nil {
				Logf("warn", "security events retention: age-based cleanup failed: %v", err)
				return result, err
			}
			affected, _ := res.RowsAffected()
			result.Events += int(affected)
			if affected == 0 {
				break
			}
			// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消
			select {
			case <-ctx.Done():
				Logf("info", "security events retention: age-based cleanup canceled mid-pass")
				// 返回契约统一为「已删多少报多少」——取消
				// 路径此前 return 0 丢弃已提交批次，§6.5 摘要行少报。下同三处。
				return result, nil
			case <-time.After(10 * time.Millisecond):
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return result, nil
	}
	// 行帽与年龄共用上方就绪门；此分支只负责行数上限。
	if !result.RowCapDeferred {
		var count int
		if err := database.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
			Logf("warn", "security events retention: row count failed: %v", err)
			return result, err // SEC-L1：age 阶段已删计数不丢弃
		}
		if overflow := count - max; overflow > 0 {
			remaining := overflow
			for remaining > 0 {
				batch := remaining
				if batch > securityEventsRetentionDeleteBatch {
					batch = securityEventsRetentionDeleteBatch
				}
				// 按事件时间（event_time ASC, id ASC）
				// 裁剪而非自增 id——摄取停摆后的补采/归档重放会以新 id 插入旧
				// event_time 的行，按 id 删会先删「最早插入」而非「最旧事件」，
				// 即先丢新事件、留住补采的旧事件。与上方年龄裁剪同一时间口径
				// （idx_security_events_time 支撑排序）。
				res, err := database.Exec(`DELETE FROM security_events WHERE id IN (SELECT id FROM security_events ORDER BY event_time ASC, id ASC LIMIT ?)`, batch)
				if err != nil {
					Logf("warn", "security events retention: count-based cleanup failed: %v", err)
					return result, err
				}
				affected, _ := res.RowsAffected()
				if affected == 0 {
					break
				}
				remaining -= int(affected)
				// count 阶段删除同样计入返回（此前只减 remaining 从不累加
				// total——审计建议遗漏点：仅改 return 不补累计，count 阶段删除在
				// 正常终点同样少报）。
				result.Events += int(affected)
				// 批间短暂让出写锁，避免长时间阻塞摄取 INSERT；同时响应 ctx 取消
				select {
				case <-ctx.Done():
					Logf("info", "security events retention: count-based cleanup canceled mid-pass")
					return result, nil
				case <-time.After(10 * time.Millisecond):
				}
			}
		}
	}
	// security_event_rollup 保留清理——全仓此前无任何
	// 删除点，分钟聚合行无限增长。保留天数取 max(31, 事件保留天数)：31 天
	// 下界保证「当前与上一完整分钟」恒在（大屏 recent_rate/小时直方最小窗口
	// 只有 24h）。按分钟分批（每批 60 个分钟组）删除，批间让写锁并响应 ctx。
	rollupDays := days
	if rollupDays < 31 {
		rollupDays = 31
	}
	rollupCutoff := time.Now().UTC().AddDate(0, 0, -rollupDays).Format("2006-01-02 15:04")
	for {
		res, err := database.Exec(`DELETE FROM security_event_rollup WHERE minute < ? AND minute IN (
			SELECT minute FROM security_event_rollup WHERE minute < ? GROUP BY minute ORDER BY minute LIMIT 60)`, rollupCutoff, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: rollup cleanup failed: %v", err)
			return result, err
		}
		affected, _ := res.RowsAffected()
		result.Rollup += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: rollup cleanup canceled mid-pass (deleted %d)", result.Rollup)
			return result, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if result.Rollup > 0 {
		Logf("info", "security events retention: rollup cleanup removed %d rows older than %s", result.Rollup, rollupCutoff)
	}
	// 目标维度 rollup 与主 rollup 同生命周期——同批次/
	// 同保留下界清理，否则 top_targets 投影无限增长。
	for {
		res, err := database.Exec(`DELETE FROM security_event_target_rollup WHERE minute < ? AND minute IN (
			SELECT minute FROM security_event_target_rollup WHERE minute < ? GROUP BY minute ORDER BY minute LIMIT 60)`, rollupCutoff, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: target rollup cleanup failed: %v", err)
			return result, err
		}
		affected, _ := res.RowsAffected()
		result.TargetRollup += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: target rollup cleanup canceled mid-pass (deleted %d)", result.TargetRollup)
			return result, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if result.TargetRollup > 0 {
		Logf("info", "security events retention: target rollup cleanup removed %d rows older than %s", result.TargetRollup, rollupCutoff)
	}
	// 分钟 rollup 状态键（事件高水位 + 回退迟到基线）与 rollup 同生命周期
	// ——此前每分钟一行常驻 metrics_state（约 1440 行/天、52.5 万行/年），
	// 全仓无删除点。按同一 rollupCutoff 清理（键后缀为 'YYYY-MM-DD HH:MM'
	// 同形态，字符串比较即时间序）。
	// 前缀匹配必须用 GLOB：前缀含 5 个 `_`，SQLite LIKE 里 `_`=任意单字符，
	// 模式比意图宽——未来出现近似命名的键（同长度前缀）会被误删（迟到基线
	// 误删会让迟到行永久不入聚合）。GLOB 的 `_` 是字面量，`*` 才是通配。
	for {
		res, err := database.Exec(`DELETE FROM metrics_state WHERE key IN (
			SELECT key FROM metrics_state WHERE (key GLOB ? AND substr(key, ?) < ?) OR (key GLOB ? AND substr(key, ?) < ?) LIMIT 500)`,
			ThreatRollupEventHighwaterPrefix+"*", len(ThreatRollupEventHighwaterPrefix)+1, rollupCutoff,
			ThreatRollupLateBaselinePrefix+"*", len(ThreatRollupLateBaselinePrefix)+1, rollupCutoff)
		if err != nil {
			Logf("warn", "security events retention: rollup highwater cleanup failed: %v", err)
			return result, err
		}
		affected, _ := res.RowsAffected()
		result.Highwater += int(affected)
		if affected == 0 {
			break
		}
		select {
		case <-ctx.Done():
			Logf("info", "security events retention: rollup highwater cleanup canceled mid-pass (deleted %d)", result.Highwater)
			return result, nil
		case <-time.After(10 * time.Millisecond):
		}
	}
	if result.Highwater > 0 {
		Logf("info", "security events retention: rollup highwater cleanup removed %d keys older than %s", result.Highwater, rollupCutoff)
	}
	// 本轮有删除时考虑截断 WAL（含仅 rollup 清理；100/s 持续写入+滚动删除
	// 下防 WAL 无界）。TRUNCATE 检查点在活跃写者（摄取 tick/rollup warmer）
	// 下易遇 BUSY 且与 30s busy_timeout 叠加放大 tick 延迟——不再每轮清理
	// 批尾执行，收敛为低频门控 + BUSY 显式计数观测（语义不变，频次解耦）。
	if result.Events > 0 || result.Rollup > 0 || result.TargetRollup > 0 || result.Highwater > 0 {
		securityEventsCheckpointWALIfDue(database, time.Now())
	}
	return result, nil
}

// securityEventsWalCheckpointMinInterval 是 WAL TRUNCATE 检查点的最小间隔
// （var 供测试收窄）。
var securityEventsWalCheckpointMinInterval = 10 * time.Minute

// securityEventsWalCheckpointState 低频门控与 BUSY 观测状态（测试可重置）。
var securityEventsWalCheckpointState struct {
	mu        sync.Mutex
	lastRun   time.Time
	runCount  int
	busyCount int
}

// securityEventsCheckpointWALIfDue 距上次检查点超过最小间隔才执行
// wal_checkpoint(TRUNCATE)。BUSY（结果行 busy=1，活跃写者下的正常让出）
// 显式计数并留痕——观测而非改语义；错误告警同旧口径。
func securityEventsCheckpointWALIfDue(database *sql.DB, now time.Time) {
	securityEventsWalCheckpointState.mu.Lock()
	if now.Sub(securityEventsWalCheckpointState.lastRun) < securityEventsWalCheckpointMinInterval {
		securityEventsWalCheckpointState.mu.Unlock()
		return
	}
	securityEventsWalCheckpointState.lastRun = now
	securityEventsWalCheckpointState.mu.Unlock()

	var busy, logFrames, checkpointed int
	err := database.QueryRow(`PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointed)
	securityEventsWalCheckpointState.mu.Lock()
	securityEventsWalCheckpointState.runCount++
	if busy != 0 {
		securityEventsWalCheckpointState.busyCount++
	}
	busyTotal := securityEventsWalCheckpointState.busyCount
	securityEventsWalCheckpointState.mu.Unlock()
	if err != nil {
		Logf("warn", "security events retention: wal checkpoint failed: %v", err)
		return
	}
	if busy != 0 {
		Logf("info", "security events retention: wal checkpoint busy（活跃写者让出，累计 %d 次）", busyTotal)
	}
}
