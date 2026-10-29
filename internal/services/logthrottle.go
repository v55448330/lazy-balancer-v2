package services

import (
	"sync"
	"sync/atomic"
	"time"
)

// LogThrottle 是「持续故障日志节流」的单槽窗口：窗口内只放行首条，窗口过后
// 放行下一条（故障排除后不得永久静默）。公开端点降级/读失败这类留痕点共用
// 同一结构，替代逐点手写的 sync.Mutex + at time.Time + 窗口比较三件套。
//
// 单槽（而非按 key 分槽）是有意为之：故障源不可信（issuer/用户 ID 随异常输入
// 无界增长），按 key 建槽会变成无界内存。
type LogThrottle struct {
	mu   sync.Mutex
	last time.Time
}

// Allow 报告本条日志是否放行：距上次放行已满 window（或从未放行）时记账并
// 返回 true；否则 false。放行后写什么由调用方决定。
func (t *LogThrottle) Allow(window time.Duration) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	if !t.last.IsZero() && now.Sub(t.last) < window {
		return false
	}
	t.last = now
	return true
}

// Reset 清空窗口：下一条日志视作新窗口首条（测试隔离用）。
func (t *LogThrottle) Reset() {
	t.mu.Lock()
	t.last = time.Time{}
	t.mu.Unlock()
}

// LogEscalation 追踪一个留痕点的连续失败状态：连续失败的首条升级 error 级
// （持久故障必须可见），后续降回 warn（登录热路径不得刷屏），成功后 Reset
// 复位——下次失败重新升级。touchLastLogin / OIDC 显示名刷新共用的留痕分级。
type LogEscalation struct {
	failing atomic.Bool
}

// Level 返回本次失败应使用的日志级别，并把状态置为「失败中」。
func (e *LogEscalation) Level() string {
	if e.failing.Swap(true) {
		return "warn"
	}
	return "error"
}

// Reset 连续失败结束（某次成功）后复位：下次失败重新升级。
func (e *LogEscalation) Reset() { e.failing.Store(false) }
