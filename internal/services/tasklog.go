package services

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// TaskLogf 业务摘要行（INFO 级，统一 tee 到 tasks/{id}.log）。
func TaskLogf(taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTime(taskID, "INFO", stage, fmt.Sprintf(format, args...))
}

// TaskLogfWarn 业务告警行（WARN 级；状态变化/失败类信号使用）。
func TaskLogfWarn(taskID, stage, format string, args ...any) {
	taskengine.TeeTaskLogTime(taskID, "WARN", stage, fmt.Sprintf(format, args...))
}

// WriteCRSUpdateLog CRS 更新流水（单一日志入口，统一 tee 到 tasks/crs.log）。
func WriteCRSUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("crs", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// WriteIP2RegionUpdateLog IP2Region 更新流水（统一到 tasks/ip2region.log）。
func WriteIP2RegionUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("ip2region", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// AppendThreatUpdateLog 威胁库更新流水（统一到 tasks/threat.log）。
func AppendThreatUpdateLog(level, stage, message string) {
	taskengine.TeeTaskLog("threat", time.Now().In(CurrentLocation()).Format("2006/01/02 15:04:05"), level, stage, message)
}

// 任务日志大小配置缓存（5 分钟 TTL；写入前滚动统一读取）。
var (
	certJobLogSizeCached     atomic.Int64
	certJobLogSizeCachedAt   atomic.Int64
	certJobLogSizeCacheTTLNs = int64(5 * time.Minute)
	certJobLogSizeRefreshMu  sync.Mutex
)

func getTaskLogSizeBytes() int64 {
	// 未初始化库回退默认 10MB；与多数配置读取 helper 的 db.DB==nil 守卫一致。
	if db.DB == nil {
		return 10 * 1024 * 1024
	}
	now := time.Now().UnixNano()
	cachedAt := certJobLogSizeCachedAt.Load()
	if cachedAt != 0 && now-cachedAt < certJobLogSizeCacheTTLNs {
		return certJobLogSizeCached.Load()
	}
	certJobLogSizeRefreshMu.Lock()
	defer certJobLogSizeRefreshMu.Unlock()
	// Double-check after acquiring lock to avoid thundering herd.
	if cachedAt = certJobLogSizeCachedAt.Load(); cachedAt != 0 && time.Now().UnixNano()-cachedAt < certJobLogSizeCacheTTLNs {
		return certJobLogSizeCached.Load()
	}
	var sizeMB int
	if err := db.DB.QueryRow("SELECT COALESCE(task_log_size_mb, 10) FROM global_config WHERE id = 1").Scan(&sizeMB); err != nil {
		Logf("warn", "读取任务日志大小配置失败,按 10MB 降级: %v", err)
		sizeMB = 10
	}
	if sizeMB <= 0 {
		sizeMB = 10
	}
	bytes := int64(sizeMB) * 1024 * 1024
	certJobLogSizeCached.Store(bytes)
	certJobLogSizeCachedAt.Store(now)
	return bytes
}
