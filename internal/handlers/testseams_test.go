package handlers

// 测试专用复位入口：这些函数只被本包测试消费（复位包级缓存/退避/采样状态），
// 不属于生产调用面，因此宿主是同包测试文件而不是产品文件——产品文件承载它们
// 会让生产调用面判断失真（见 testonly_symbols_test.go 的守卫）。
//
// 同包测试可直接调用未导出符号，无需为测试扩大产品文件的表达式面。

import (
	"time"
)

// resetAuditOptionsCacheForTest 仅供测试隔离。
func resetAuditOptionsCacheForTest() {
	auditOptionsCache.Lock()
	defer auditOptionsCache.Unlock()
	auditOptionsCache.expiresAt = time.Time{}
	auditOptionsCache.payload = nil
}

// resetAuditLogCountCacheForTest 仅供测试隔离（跨用例的审计库交换后不得
// 读到上一夹具的计数）。
func resetAuditLogCountCacheForTest() {
	auditLogCounts.Lock()
	auditLogCounts.entries = nil
	auditLogCounts.Unlock()
}

// resetBrandingSyncGateForTest 清空采样门状态（跨用例隔离）。
func resetBrandingSyncGateForTest() {
	brandingSyncMu.Lock()
	brandingSyncLast = time.Time{}
	brandingSyncDataDir = ""
	brandingSyncFingerprint = ""
	brandingSyncMu.Unlock()
	brandingApplyPending.Store(false)
}

// resetCaddyRestartBackoffForTest 测试缝：复位退避状态（生产不调用）。
func resetCaddyRestartBackoffForTest() {
	caddyRestartBackoff.mu.Lock()
	caddyRestartBackoff.attempts = 0
	caddyRestartBackoff.nextAttempt = time.Time{}
	caddyRestartBackoff.lastStatus = ""
	caddyRestartBackoff.triggerMod = time.Time{}
	caddyRestartBackoff.appliedMod = time.Time{}
	caddyRestartBackoff.removalWarned = time.Time{}
	caddyRestartBackoff.statWarned = false
	caddyRestartBackoff.mu.Unlock()
}

// resetLogStatsVolumeStateForTest 仅供测试隔离（跨用例的注入失败状态不得
// 让后续断言的「首报」被去重成 0 条）。
func resetLogStatsVolumeStateForTest() {
	logStatsVolumeState.Lock()
	logStatsVolumeState.failed = nil
	logStatsVolumeState.Unlock()
}

// resetLogStatsRowCountCacheForTest 仅供测试隔离（跨用例的 DB 交换后不得
// 读到上一夹具的行数）。
func resetLogStatsRowCountCacheForTest() {
	logStatsRowCounts.Lock()
	logStatsRowCounts.entries = nil
	logStatsRowCounts.Unlock()
}

func resetCaddyMetricsSnapshotCacheForTest() {
	caddyMetricsSnapshots.Lock()
	caddyMetricsSnapshots.entries = nil
	caddyMetricsSnapshots.Unlock()
}

// resetMetricsDashboardCacheForTest 测试缝：清空面板缓存与共享抓取快照
// （生产不调用；两者同属指标读路径，隔离必须同步，否则跨用例读到上一夹具
// 的抓取字节）。
func resetMetricsDashboardCacheForTest() {
	metricsDashboardState.Lock()
	metricsDashboardState.url = ""
	metricsDashboardState.outcome = metricsDashboardOutcome{}
	metricsDashboardState.expiresAt = time.Time{}
	metricsDashboardState.valid = false
	metricsDashboardState.Unlock()
	resetCaddyMetricsSnapshotCacheForTest()
}

// resetRuleStageStatsCacheForTest 测试缝：清空缓存（生产不调用）。
func resetRuleStageStatsCacheForTest() {
	ruleStageStatsCache.Reset()
}

// resetSecurityOverviewAggCacheForTest 测试缝：清空总览聚合缓存（生产不调用）。
func resetSecurityOverviewAggCacheForTest() {
	securityOverviewAggCache.Reset()
}

// resetSecurityPolicy24hCountsCacheForTest 测试缝：清空缓存（生产不调用）。
func resetSecurityPolicy24hCountsCacheForTest() {
	securityPolicy24hCountsMu.Lock()
	securityPolicy24hCountsCache = map[securityPolicy24hCountsKey]securityPolicy24hCountsEntry{}
	securityPolicy24hCountsMu.Unlock()
}

// resetThreatRollupWarmerForTest 测试缝：复位 warmer 启动标志（生产不调用）。
func resetThreatRollupWarmerForTest() {
	threatRollupWarmerStarted.Store(false)
	threatRollupReadyAt.Store(0)
	threatRollupReadyDB.Store(nil)
	threatRollupReadyGeneration.Store("")
	threatRollupRequestedHours.Store(0)
	threatRollupRequestedHoursAt.Store(0)
}

// resetThreatActiveSourcesCacheForTest 测试缝：清空缓存（生产不调用）。
func resetThreatActiveSourcesCacheForTest() {
	threatActiveSourcesCache.Reset()
}

// resetThreatScreenCachesForTest 测试缝：清空大屏进程内缓存（生产不调用）。
func resetThreatScreenCachesForTest() {
	topTargetsCache.Reset()
	threatRollupDimAggregateCache.Reset()
	threatTrafficCache.Range(func(key, _ any) bool {
		threatTrafficCache.Delete(key)
		return true
	})
}
