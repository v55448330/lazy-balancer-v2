package services

// taskengine_wire_runtime.go —— 运行期生命周期任务（runtime lifecycle daemons）
// 的注册与装配：把 6 项曾游离在引擎外的自建循环（metrics 采集/rollup warmer/
// caddy-restart 监听/限流桶清扫/apikey usage flusher/运行日志阈值 + 时区刷新）
// 按 task-engine 标准 v2.2 归口为注册任务。唯一许可的执行形态=Daemon +
// taskengine.RunTicker（或 Periodic）。
//
// 【由 InitTaskEngine 调用】registerRuntimeLifecycleTasks(te)（调用接线由主审
// 完成）。推荐插入点：InitTaskEngine 尾部 ResumeScheduling() 之后、
// startRoleReconciler(te) 之前——此时偏好已应用、调度已恢复，StartLoop 语义
// 与默认启动清单一致。本函数自带偏好门（显式停止的 daemon 不启动），插在
// applyTaskLoopPrefs 之前/之后均安全。
//
// 装配期同步首跑：runtime-log-threshold 与 runtime-tz-refresh 的阈值/时区
// 读取在注册时同步执行一次（同一 Once 函数），避免 daemon 异步首跑前面板
// 出现兜底阈值/占位时区空窗。
//
// 钩子注入（跨包工作体，main 在 InitTaskEngine 前装配，与既有 Set* 钩子同型）：
//   - SetMetricsCollector           *MetricsService（采集/清理工作体）
//   - SetThreatRollupWarmerRound    handlers.RunThreatRollupWarmerRound
//   - SetCaddyRestartWatcherRound   handlers.CaddyRestartWatcherOnce 闭包
//   - SetRateLimitBucketSweep       middleware.SweepRateLimitBuckets 闭包
//
// 钩子未接线（测试/极早窗口）时 daemon Run 立即返回 nil（空闲、零噪音、
// 不产任务行）——生产 main 在 InitTaskEngine 之前完成全部注入；db 直连工作体
// （apikey flusher/时区/日志阈值）无钩子、恒工作。

import (
	"context"
	"sync/atomic"
	"time"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/taskengine"
)

// ---- 跨包工作体钩子（main 装配；测试经同名注入缝 + Cleanup 复位）----

var (
	metricsCollectorPtr        atomic.Pointer[MetricsService]
	threatRollupWarmerRoundFn  atomic.Pointer[func() error]
	caddyRestartWatcherRoundFn atomic.Pointer[func()]
	rateLimitBucketSweepFn     atomic.Pointer[func() int]
)

// SetMetricsCollector 注入指标采集/清理工作体（main 在 InitTaskEngine 前）。
func SetMetricsCollector(m *MetricsService) { metricsCollectorPtr.Store(m) }

func currentMetricsCollector() *MetricsService { return metricsCollectorPtr.Load() }

// SetThreatRollupWarmerRound 注入威胁大屏 rollup 单轮预热工作体。
func SetThreatRollupWarmerRound(fn func() error) {
	if fn == nil {
		threatRollupWarmerRoundFn.Store(nil)
		return
	}
	threatRollupWarmerRoundFn.Store(&fn)
}

func currentThreatRollupWarmerRound() func() error {
	if fn := threatRollupWarmerRoundFn.Load(); fn != nil {
		return *fn
	}
	return nil
}

// SetCaddyRestartWatcherRound 注入 Caddy 重启触发文件单轮探测工作体。
func SetCaddyRestartWatcherRound(fn func()) {
	if fn == nil {
		caddyRestartWatcherRoundFn.Store(nil)
		return
	}
	caddyRestartWatcherRoundFn.Store(&fn)
}

func currentCaddyRestartWatcherRound() func() {
	if fn := caddyRestartWatcherRoundFn.Load(); fn != nil {
		return *fn
	}
	return nil
}

// SetRateLimitBucketSweep 注入限流桶清扫工作体（middleware.SweepRateLimitBuckets）。
func SetRateLimitBucketSweep(fn func() int) {
	if fn == nil {
		rateLimitBucketSweepFn.Store(nil)
		return
	}
	rateLimitBucketSweepFn.Store(&fn)
}

func currentRateLimitBucketSweep() func() int {
	if fn := rateLimitBucketSweepFn.Load(); fn != nil {
		return *fn
	}
	return nil
}

// ---- 装配 ----

// registerRuntimeLifecycleTasks 注册运行期生命周期任务族并按默认启动清单拉起
// （用户显式停止的 daemon 经偏好门跳过——见文件头「由 InitTaskEngine 调用」）。
func registerRuntimeLifecycleTasks(te *taskengine.Engine) {
	// 装配期同步首跑（避免阈值/时区空窗——与 daemon 节拍共用同一 Once 函数）。
	RefreshRuntimeLogSizeOnce()
	RefreshTimezoneOnce()

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "metrics-collector",
		Family:      "system",
		Name:        "指标采集",
		Description: "按配置间隔从 Caddy admin /metrics 抓取并聚合仪表盘指标（启动立即采集一轮）；从 Caddy 崩溃到恢复期间只丢样本不中断",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			m := currentMetricsCollector()
			if m == nil {
				return nil // 未接线（测试/未装配）：零工作；生产装配先于 InitTaskEngine
			}
			taskengine.RunTicker(rc.Ctx, m.tickerInterval(), nil, func(context.Context) { m.collect() })
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "metrics-history-cleanup",
		Family:      "system",
		Name:        "指标历史清理",
		Description: "每日清理超过 7 天保留期的指标历史（5000 行/批让锁推进）；失败进任务失败终态，不得恒成功",
		Category:    "系统",
		Kind:        taskengine.KindPeriodic,
		IntervalFn:  func() time.Duration { return 24 * time.Hour },
		Run: func(rc taskengine.RunContext) error {
			m := currentMetricsCollector()
			if m == nil {
				return nil
			}
			return m.cleanupHistory()
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "threat-rollup-warmer",
		Family:      "security",
		Name:        "威胁大屏 rollup 预热",
		Description: "每 60s 预固化威胁大屏分钟级聚合（启动立即一轮，按持久 coverage 续做到 7d/请求窗口）；就绪后请求路径不再懒固化",
		Category:    "安全防护",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			round := currentThreatRollupWarmerRound()
			if round == nil {
				return nil
			}
			taskengine.RunTicker(rc.Ctx, time.Minute, nil, func(context.Context) {
				if err := round(); err != nil {
					Logf("warn", "%v", err)
				}
			})
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "caddy-restart-watcher",
		Family:      "system",
		Name:        "Caddy 重启自愈监听",
		Description: "每 2s 探测监督器写入的 Caddy 重启触发文件，命中后经任务引擎以 caddy-restart 触发执行与启动一致的配置载入（失败指数退避 2s→30s、落行降频）",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			round := currentCaddyRestartWatcherRound()
			if round == nil {
				return nil
			}
			taskengine.RunTicker(rc.Ctx, 2*time.Second, nil, func(context.Context) { round() })
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "ratelimit-bucket-sweep",
		Family:      "system",
		Name:        "限流桶清扫",
		Description: "每 60s 删除已过窗的登录限流内存桶，回收键空间（桶级锁短临界区，不阻塞限流判定）",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			sweep := currentRateLimitBucketSweep()
			if sweep == nil {
				return nil
			}
			taskengine.RunTicker(rc.Ctx, time.Minute, nil, func(context.Context) { _ = sweep() })
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "apikey-usage-flusher",
		Family:      "system",
		Name:        "API Key 使用时间落库",
		Description: "每 60s 批量落库 api_keys.last_used 请求热路径脏标记；每小时一并清理过期吊销 JWT 与过期集群注册密钥（注册密钥写带 SQL 级主节点角色条件）",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			runAPIKeyUsageFlusher(rc.Ctx)
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "runtime-log-threshold",
		Family:      "system",
		Name:        "运行日志阈值刷新",
		Description: "每 30s 读取 global_config.runtime_log_size_mb 并应用到运行日志滚动阈值（装配期已同步首跑，daemon 只做后续节拍）",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			taskengine.RunTicker(rc.Ctx, 30*time.Second, nil, func(context.Context) { RefreshRuntimeLogSizeOnce() })
			return nil
		},
	})

	mustRegisterTask(te, taskengine.Descriptor{
		ID:          "runtime-tz-refresh",
		Family:      "system",
		Name:        "时区刷新",
		Description: "每 30s 读取 global_config.timezone 并应用到面板/任务/审计展示时区（装配期已同步首跑，daemon 只做后续节拍）",
		Category:    "系统",
		Kind:        taskengine.KindDaemon,
		Run: func(rc taskengine.RunContext) error {
			taskengine.RunTicker(rc.Ctx, 30*time.Second, nil, func(context.Context) { RefreshTimezoneOnce() })
			return nil
		},
	})

	// 默认启动清单（常驻/循环族默认运行；用户显式停止的按偏好保持停止，
	// 语义与 InitTaskEngine 内置默认清单一致——先读偏好再 StartLoop，
	// 不留假启动记录）。
	taskLoopPrefs := loadTaskLoopPrefs()
	for _, id := range []string{
		"metrics-collector", "metrics-history-cleanup",
		"threat-rollup-warmer", "caddy-restart-watcher",
		"ratelimit-bucket-sweep", "apikey-usage-flusher",
		"runtime-log-threshold", "runtime-tz-refresh",
	} {
		if enabled, found := taskLoopPrefs[id]; found && !enabled {
			continue
		}
		te.StartLoop(id)
	}
}

// ---- apikey-usage-flusher 工作体 ----

// apiKeyAuxCleanupInterval 附表清理节拍（原 db 包 1h cleanupTicker 口径）。
const apiKeyAuxCleanupInterval = time.Hour

// apiKeyAuxCleanupNextDue 附表清理下次到期 Unix 秒（0=未安排）。Run 启动时
// 对齐旧「1h 后首轮」节拍；失败同样顺延（不 hot-loop）。到期判定在 RunTicker
// fn 内做业务闸门——节拍仍由宿主 daemon 唯一驱动，无第二个调度源。
var apiKeyAuxCleanupNextDue atomic.Int64

func runAPIKeyUsageFlusher(ctx context.Context) {
	// 首轮对齐旧节拍：附表清理自 1h 后开始（flush 则由 RunTicker bootstrap
	// 立即执行一次——脏表为空时零写）。
	apiKeyAuxCleanupNextDue.CompareAndSwap(0, time.Now().Add(apiKeyAuxCleanupInterval).Unix())
	taskengine.RunTicker(ctx, time.Minute, nil, func(ctx context.Context) {
		if err := db.FlushAPIKeyLastUsed(); err != nil {
			if lvl := logStateTransition("apikey-usage-flush", true); lvl != "" {
				Logf(lvl, "flush API key usage: %v", err)
			}
		} else if lvl := logStateTransition("apikey-usage-flush", false); lvl != "" {
			Logf(lvl, "flush API key usage recovered")
		}
		if now := time.Now(); now.Unix() >= apiKeyAuxCleanupNextDue.Load() {
			apiKeyAuxCleanupNextDue.Store(now.Add(apiKeyAuxCleanupInterval).Unix())
			if err := db.CleanupAPIKeyAuxTables(ctx); err != nil {
				if lvl := logStateTransition("apikey-aux-cleanup", true); lvl != "" {
					Logf(lvl, "%v", err)
				}
			} else if lvl := logStateTransition("apikey-aux-cleanup", false); lvl != "" {
				Logf(lvl, "cleanup revoked JWT IDs / cluster registration secrets recovered")
			}
		}
	})
}
