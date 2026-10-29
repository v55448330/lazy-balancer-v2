package services

// （用户裁定）：删除规则后的 metrics_history 清理失败
// 此前仅 Logf（无审计、无重试）。裁定=失败落操作审计 + taskengine 有界重试
// ——本轮由周期任务 metrics-orphan-cleanup 承担：按「已删除规则」谓词收敛
// 清理残留历史指标（每轮限量分批，天然有界；收敛后每轮零工作）。
//
// 口径：
//   - 仅动 rule_id 非 NULL 的行（全局指标行 rule_id=NULL，不得误删）。
//   - 存活规则清单来自主库 lb_rules（caddy_id 不复用——残留行无功能影响，
//     仅占盘；7 天保留期（CleanupMetricsHistory）另有兜底，本任务只是把
//     「删除时清理失败」的余量提前收敛）。

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"lazy-balancer-v2/internal/db"
)

// metricsOrphanPurgeRulesPerRun 单轮最多清理的孤儿规则数（有界重试的
// 「有界」落点：积压超限时下一轮继续，不在一轮内无限放大删除事务）。
// 变量形态便于测试收窄。
var metricsOrphanPurgeRulesPerRun = 500

// metricsOrphanPurgeRowsPerBatch 单条 DELETE 的行数上限。保留期 7 天 × 30s
// 采样 ⇒ 单规则最多约 2 万行；积压 500 条时一次性 DELETE 可达千万行，长写
// 事务会阻塞 30s 节拍的 metrics 写入。按 rowid 分批删除、批间复核 ctx
// （让出写锁并支持任务取消）。
var metricsOrphanPurgeRowsPerBatch = 5000

// PurgeOrphanMetricsHistory 清理 metrics 库中已删除规则的残留历史指标，
// 返回本轮删除的规则数。调用方（taskengine metrics-orphan-cleanup）按错误
// 落 task_runs failed——不得静默成功。
//
// 库未初始化（启动早期/关停竞态里仍在跑的本轮/嵌入形态）时返回
// errMetricsDBUnavailable 而不是 (0, nil)：静默零值会让「本轮清理全停」与
// 「已收敛无残留」同形（任务体据 err 分流，nil 会写「清理完成：删除 0 个」
// 并落 success），与兄弟函数 PurgeOrphanRuleLogs 的 ScanError 口径不一致。
func PurgeOrphanMetricsHistory(ctx context.Context) (int, error) {
	if db.DB == nil || db.MetricsDB == nil {
		return 0, fmt.Errorf("跳过孤儿规则指标清理（不删除）: %w", errMetricsDBUnavailable)
	}
	liveIDs, err := liveRuleIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取存活规则清单: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	orphans, err := orphanMetricsRuleIDs(ctx)
	if err != nil {
		return 0, fmt.Errorf("读取指标库规则清单: %w", err)
	}
	pending := make([]string, 0, len(orphans))
	for _, ruleID := range orphans {
		if !liveIDs[ruleID] {
			pending = append(pending, ruleID)
		}
	}
	if len(pending) == 0 {
		return 0, nil
	}
	sort.Strings(pending) // 确定性：同一积压跨轮次优先清理同一前缀
	if limit := metricsOrphanPurgeRulesPerRun; limit > 0 && len(pending) > limit {
		pending = pending[:limit]
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	batch := metricsOrphanPurgeRowsPerBatch
	if batch <= 0 {
		batch = 5000
	}
	// deletedRules 是本轮**已完整清空**的孤儿规则数：失败分支必须返回真实
	// 部分计数（与 CleanupAuditLogs「已删除批次不可逆，失败返回真实部分计数」
	// 同口径）——否则任务日志「本轮已清理 0 个规则后中止」与已删掉的前 N 条
	// 无关，排障者无法区分「反复失败原地打转」与「在推进」。
	deletedRules := 0
	for _, ruleID := range pending {
		for {
			// 每批重读句柄：关停排空超时后 db.Close() 才执行（并把
			// MetricsDB 置 nil），在途轮可能在下一批撞上 nil——入口只判一次
			// 不足以防 nil 解引用 panic。nil 时返回可见错误（任务落 failed），
			// 已删批次不可逆但计数如实。
			metricsDB := db.MetricsDB
			if metricsDB == nil {
				return deletedRules, errMetricsDBUnavailable
			}
			result, execErr := metricsDB.ExecContext(ctx,
				`DELETE FROM metrics_history WHERE rowid IN (SELECT rowid FROM metrics_history WHERE rule_id = ? LIMIT ?)`,
				ruleID, batch)
			if execErr != nil {
				return deletedRules, fmt.Errorf("删除孤儿规则指标: %w", execErr)
			}
			deleted, rowErr := result.RowsAffected()
			if rowErr != nil {
				return deletedRules, fmt.Errorf("删除孤儿规则指标: 读取影响行数: %w", rowErr)
			}
			// 本批未打满=该规则已清空，处理下一条。
			if deleted < int64(batch) {
				deletedRules++
				// 清空最后一条后仍须以取消态收尾：否则任务取消/关停被当作
				// 清理完成（success），与「本轮只删掉了部分规则」的事实不符。
				if err := ctx.Err(); err != nil {
					return deletedRules, err
				}
				break
			}
			if err := ctx.Err(); err != nil {
				return deletedRules, err
			}
		}
	}
	return deletedRules, nil
}

// beforeLiveRuleIDsQuery 保留存活规则查询前注入缝，供关停交错回归测试使用。
var beforeLiveRuleIDsQuery = func() {}

// liveRuleIDs 读取主库存活规则 caddy_id 集合。
func liveRuleIDs(ctx context.Context) (map[string]bool, error) {
	// 后台任务体统一读 db.GetDB() 注册句柄（与 orphanMetricsRuleIDs 的每批
	// 重读同型）：db.SetDB(nil)（关停 db.Close 链/句柄切换）后仍在跑的本轮
	// 不得继续在已注销句柄上读删——nil 解引用 panic 与「已注销句柄照常工作」
	// 都要挡住。
	beforeLiveRuleIDsQuery()
	database := db.GetDB()
	if database == nil {
		return nil, errors.New("数据库未初始化")
	}
	rows, err := database.QueryContext(ctx, `SELECT caddy_id FROM lb_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	live := map[string]bool{}
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		live[ruleID] = true
	}
	return live, rows.Err()
}

// orphanMetricsRuleIDs 读取 metrics 库出现过的非 NULL rule_id（去重排序）。
// 句柄先取值再判 nil（与 PurgeOrphanMetricsHistory 每批重读同源）：关停时
// db.Close() 置 nil，入口判过非 nil 之后这里仍可能撞上 nil。
func orphanMetricsRuleIDs(ctx context.Context) ([]string, error) {
	metricsDB := db.MetricsDB
	if metricsDB == nil {
		return nil, errMetricsDBUnavailable
	}
	rows, err := metricsDB.QueryContext(ctx, `SELECT DISTINCT rule_id FROM metrics_history WHERE rule_id IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ruleIDs := make([]string, 0)
	for rows.Next() {
		var ruleID string
		if err := rows.Scan(&ruleID); err != nil {
			return nil, err
		}
		ruleIDs = append(ruleIDs, ruleID)
	}
	return ruleIDs, rows.Err()
}
