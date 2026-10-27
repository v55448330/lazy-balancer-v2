package services

import (
	"context"
	"sync"
	"time"
)

// dbValueCache 单个 DB 数值配置的缓存槽。
//
// 背景：任务日志大小阈值（task_log_size_mb）与审计日志大小阈值
// （audit_log_size_mb）此前各有一套「TTL + 原子量/互斥量」实现——审计侧
// 「读库失败不缓存」，任务侧却把瞬时故障的 10MB 回退值写进
// 5 分钟缓存：DB 抖动一次即让任务日志按偏小阈值被提前滚动，且两套实现易
// 单侧漏改。
//
// 本类型只承载缓存机制（TTL + 同槽单飞 + 显式失效）；读库语句与回退值仍由
// 调用方决定。统一口径：**load 失败不写入缓存**，回退值只对本轮生效，下一轮
// 重试——不把瞬时故障钉死整个窗口。
type dbValueCache struct {
	ttl   time.Duration
	mu    sync.Mutex
	value int64
	at    time.Time
}

// get 返回有效期内缓存值；未命中时持锁调用 load（同槽单飞——审计轮转 2s
// tick 只会产生一次查询，并发读不到部分初始化的值）。load 失败返回 fallback
// 且不缓存。
//
// 无 ctx 形态：调用点不在关停/排空预算内时使用；预算内的调用点必须用 getCtx。
func (c *dbValueCache) get(load func() (int64, error), fallback int64) int64 {
	return c.getCtx(context.Background(), func(context.Context) (int64, error) { return load() }, fallback)
}

// getCtx 是 get 的 ctx 形：load 用 queryCtx 发读库语句，取消已发出即按 ctx
// 返回（同族口径见 auditRetentionMonths：不把「查询被主库写锁挡住」拖过关停/
// 导入排空预算）。缓存语义与 get 完全一致（失败不缓存、回退值只对本轮生效）。
func (c *dbValueCache) getCtx(ctx context.Context, load func(context.Context) (int64, error), fallback int64) int64 {
	if v, ok := c.fresh(); ok {
		return v
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if v, ok := c.freshLocked(); ok {
		return v
	}
	v, err := load(ctx)
	if err != nil {
		return fallback
	}
	c.value, c.at = v, time.Now()
	return v
}

// invalidate 清空缓存。是否接线由调用方的生效时效要求决定：任务日志侧在
// 设置保存/导入/集群应用后调用（否则最长 TTL 内仍按旧阈值滚动）；审计轮转
// 侧有意不接线——60s TTL 生效延迟对按大小轮转无实际影响（见
// auditlog_rotation.go auditLogSizeCacheTTL 注释），调用方不得把本方法
// 当作「保存后必须调用」的普遍契约。
func (c *dbValueCache) invalidate() {
	c.mu.Lock()
	c.at = time.Time{}
	c.mu.Unlock()
}

func (c *dbValueCache) fresh() (int64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.freshLocked()
}

func (c *dbValueCache) freshLocked() (int64, bool) {
	if c.at.IsZero() || time.Since(c.at) >= c.ttl {
		return 0, false
	}
	return c.value, true
}
