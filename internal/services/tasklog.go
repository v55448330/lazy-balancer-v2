package services

import (
	"context"
	"fmt"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskLogf 业务摘要行（INFO 级，统一 tee 到 tasks/{id}.log）。
func TaskLogf(taskID, stage, format string, args ...any) {
	TaskLogfContext(context.Background(), taskID, stage, format, args...)
}

// TaskLogfContext 是 TaskLogf 的任务上下文形态，日志阈值读取随任务取消。
func TaskLogfContext(ctx context.Context, taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTimeContext(ctx, taskID, "INFO", stage, fmt.Sprintf(format, args...))
}

// TaskLogfWarn 业务告警行（WARN 级；状态变化/失败类信号使用）。
func TaskLogfWarn(taskID, stage, format string, args ...any) {
	TaskLogfWarnContext(context.Background(), taskID, stage, format, args...)
}

func TaskLogfWarnContext(ctx context.Context, taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTimeContext(ctx, taskID, "WARN", stage, fmt.Sprintf(format, args...))
}

// writeUpdateLog 更新流水日志单实现（时间戳/级别/阶段口径唯一来源——
// TeeTaskLogTime 与引擎生命周期行同用 engineLogTimeStr 斜杠形态）。
// 三族导出名保持（调用方零改动），禁止再复制「自算时间戳+TeeTaskLog」形态。
func writeUpdateLog(taskID, level, stage, message string) {
	taskengine.TeeTaskLogTime(taskID, level, stage, message)
}

// WriteCRSUpdateLog CRS 更新流水（单一日志入口，统一 tee 到 tasks/crs.log）。
func WriteCRSUpdateLog(level, stage, message string) {
	writeUpdateLog("crs", level, stage, message)
}

// WriteIP2RegionUpdateLog IP2Region 更新流水（统一到 tasks/ip2region.log）。
func WriteIP2RegionUpdateLog(level, stage, message string) {
	writeUpdateLog("ip2region", level, stage, message)
}

// AppendThreatUpdateLog 威胁库更新流水（统一到 tasks/threat.log）。
func AppendThreatUpdateLog(level, stage, message string) {
	writeUpdateLog("threat", level, stage, message)
}

// WriteCrawlerUpdateLog 爬虫地址库更新流水（统一到 tasks/crawlerbot-update.log）。
// 错误行同样必须走本入口——直接 TeeTaskLogTime 会绕过时间戳/级别口径单源。
func WriteCrawlerUpdateLog(level, stage, message string) {
	writeUpdateLog(CrawlerTaskID, level, stage, message)
}

// 任务日志大小配置缓存（缓存机制单源 dbValueCache——此前与审计
// 侧各有一套实现，任务侧还把读库失败的回退值写进缓存）。TTL 5 分钟：设置保存
// 经 InvalidateTaskLogSizeCache 立刻生效，TTL 只覆盖带外改库。
var taskLogSizeCache = dbValueCache{ttl: 5 * time.Minute}

// InvalidateTaskLogSizeCache 使任务日志大小配置缓存失效。
// 设置保存成功后必须调用——否则改库后仍有最长 5 分钟（TTL）按旧阈值滚动。
func InvalidateTaskLogSizeCache() {
	taskLogSizeCache.invalidate()
}

// beforeTaskLogSizeQuery 保留任务日志阈值查询前注入缝，供关停交错回归测试使用。
var beforeTaskLogSizeQuery = func() {}

func getTaskLogSizeBytes(ctx context.Context) int64 {
	// 未初始化库回退治理默认值（db.DefaultTaskLogSizeMB）；与多数配置读取
	// helper 的 db.DB==nil 守卫一致。
	defaultBytes := int64(db.DefaultTaskLogSizeMB) * 1024 * 1024
	beforeTaskLogSizeQuery()
	database := db.DB
	if database == nil {
		return defaultBytes
	}
	return taskLogSizeCache.getCtx(ctx, func(queryCtx context.Context) (int64, error) {
		var sizeMB int
		if err := database.QueryRowContext(queryCtx, "SELECT COALESCE(task_log_size_mb, ?) FROM global_config WHERE id = 1", db.DefaultTaskLogSizeMB).Scan(&sizeMB); err != nil {
			// 任务取消/关停不是配置故障：静默回退默认值，不得污染状态转换日志。
			if queryCtx.Err() != nil {
				return 0, queryCtx.Err()
			}
			// SetTaskLogSizeBytesFn 在每次任务日志写入前求值，主库持续故障时
			// 裸 warn 会按写入行数洪泛并与全项目去重口径漂移。
			if lvl := logStateTransition("task-log-size-refresh", true); lvl != "" {
				Logf(lvl, "读取任务日志大小配置失败,按默认值 %dMB 降级: %v", db.DefaultTaskLogSizeMB, err)
			}
			// 失败不缓存：回退值只对本轮生效，下一轮重试。
			return 0, err
		}
		if lvl := logStateTransition("task-log-size-refresh", false); lvl != "" {
			Logf(lvl, "读取任务日志大小配置已恢复")
		}
		if sizeMB <= 0 {
			sizeMB = db.DefaultTaskLogSizeMB
		}
		return int64(sizeMB) * 1024 * 1024, nil
	}, defaultBytes)
}
