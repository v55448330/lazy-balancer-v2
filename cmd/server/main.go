package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider/dnspod"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/dnsprovider/tencent"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/middleware"

	"lazy-balancer-v2/internal/services"
)

// 版本经 config(APP_VERSION env / Dockerfile ARG 兜底)进入 cfg.Version——
// 启动日志与 branding API 同源(此前独立 ldflags 变量无注入链,恒 "dev")。

// startupError 标记「服务尚未开始监听」的启动期失败（库初始化、集群触发器
// 就绪门、管理 TLS 证书解析与监听绑定）。main 据此与运行期崩溃（serve 中途
// 中止）分判文案——把启动失败记成「HTTP server stopped unexpectedly」会让
// 运维去查 OOM/崩溃，而真实原因通常是挂载权限、库损坏或证书口令错。
type startupError struct{ err error }

func (e *startupError) Error() string { return e.err.Error() }

func (e *startupError) Unwrap() error { return e.err }

// startupFailed 包装启动期失败（仅用于「尚未开始监听」的返回点）。
func startupFailed(err error) error { return &startupError{err: err} }

func main() {
	os.Exit(runMain(os.Args, runHealthcheck, run))
}

// runMain 把健康检查分流放在正常启动的唯一入口之前；serve 包含 flag 解析、
// 配置读取与 DB 装配，注入替身即可证明探针路径不会触碰这些启动依赖。
func runMain(args []string, healthcheck func() int, serve func() error) int {
	if healthcheckRequested(args) {
		return healthcheck()
	}
	if err := serve(); err != nil {
		var startupFailure *startupError
		if errors.As(err, &startupFailure) {
			services.Logf("error", "startup failed: %v", startupFailure.err)
		} else {
			services.Logf("error", "HTTP server stopped unexpectedly: %v", err)
		}
		return 1
	}
	return 0
}

func run() error {
	// Parse flags
	configPath := flag.String("config", "", "Config file path")
	initDB := flag.Bool("init", false, "Initialize database")
	flag.Parse()

	// Load configuration。启动期告警先收集（此刻日志尚未接入运行日志文件与
	// 级别门，直接打印只到容器 stdout），日志装配完成后统一重放。
	cfg, cfgWarnings := config.LoadCollectWarnings(*configPath)

	// 信号注册前置到 run() 开头、一切阻塞装配
	// （DB/日志/InitTaskEngine 内含 BootSync：配置载入/证书物化/Caddy 应用，
	// 最坏数十秒）之前。此前注册排在监听前——启动窗口内 SIGTERM 走默认动作
	// 立即退出：不写 drain pause 标记、不排水 Caddy、cleanup defer 全不执行，
	// 升级/停止恰好落在启动窗口时在途代理连接被容器 teardown 硬断。
	// 缓冲=1：窗口内到达的信号保留在通道里，进入 waitForServerStop 后立即
	// 被消费为正常关停（下方另有监听前的显式检查，避免先开监听再退）。
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)

	// SetFlags(0) 是下方 services.NewApplicationLogWriter
	// 日志级别过滤的隐式契约——过滤按行首 "WARNING:"/"ERROR:" 前缀判定（tz.go
	// applicationLogWriter），标准 log 前缀会破坏该判定。此处改 flags 须同步
	// applicationLogWriter 的前缀剥离逻辑（同注释互指）。
	log.SetFlags(0)
	var logWriter io.Writer = os.Stdout
	var runtimeLogFile string
	// LogFileEnabled 已恒 true(2026-09-14 裁定)——恒真条件移除。
	if w, err := services.NewRotatingFileWriter(cfg.LogFile); err == nil {
		logWriter = io.MultiWriter(os.Stdout, w)
		defer w.Close()
		runtimeLogFile = cfg.LogFile
	} else {
		// 显式配置了 LOG_FILE 但打开失败必须可见——静默回落仅 stdout 会让
		// 「配置了日志文件却是空的」无从排查。
		log.Printf("log file %s could not be opened, falling back to stdout only: %v", cfg.LogFile, err)
	}
	log.SetOutput(services.NewApplicationLogWriter(&tzLogWriter{w: logWriter}))

	// Initialize database（前置设施——非任务，不入 task_runs）
	if err := db.Initialize(cfg.DataDir); err != nil {
		return startupFailed(fmt.Errorf("initialize database: %w", err))
	}
	defer func() {
		if err := db.Close(); err != nil {
			services.Logf("error", "close databases during shutdown: %v", err)
		}
	}()
	services.ApplyLogLevel()
	// 配置载入期告警重放：此刻运行日志文件写端与级别门都已装配，误配信号
	// （未知键/类型错误/弱 JWT 密钥/caddy_admin_url 失联/APP_VERSION 未注入）
	// 才进入统一日志链——此前只到容器 stdout，只采集日志文件的部署看不到。
	for _, warning := range cfgWarnings {
		services.Logf("warn", "%s", warning)
	}
	// 独立 module 边界包（acme/ownership 不得回依赖 services）的
	// 日志接缝在此装配——装配后其告警进入统一日志级别链（services.Logf）。
	acme.SetLogf(services.Logf)
	ownership.SetLogf(services.Logf)
	// dnsprovider 两实现的 TXT 残留告警接缝（修复前裸 log.Printf）。
	dnspod.SetLogf(services.Logf)
	tencent.SetLogf(services.Logf)
	if err := handlers.EnsureBrandingFile(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to ensure branding file: %v", err)
	}
	if _, err := handlers.SyncDefaultLandingText(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to sync landing text: %v", err)
	}
	if _, err := handlers.SeedDefaultBlockPage(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to seed default block page: %v", err)
	}
	// 品牌载入留痕(2026-09-11 裁定):操作日志+系统日志记录各字段自定义/默认。
	handlers.StartupBrandingLog(cfg.DataDir)

	if *initDB {
		log.Println("Database initialized successfully")
		return nil
	}

	// 集群版本触发器就绪门（先于任务引擎与一切后台写者）。
	// HTTP 侧的 fail-closed 只覆盖请求链；引擎内的周期任务（CRS/IP2Region/
	// 威胁/爬虫/cert-renewal/autoban）直接经主库句柄写同步表，触发器缺失时
	// 这些写不 bump cluster_version——面板看起来「同步写 500，保护到位」，实际
	// 后台写者照常落库且不 bump：从节点 304 门恒定命中旧指纹，主端稳态变更
	// 永不传播，任务日志全绿。触发器是同步正确性的结构性前提，安装失败即拒绝
	// 启动（容器重启策略接管），不得带病运行。
	if err := middleware.InstallClusterVersionTriggers(db.GetDB()); err != nil {
		return startupFailed(fmt.Errorf("install cluster version triggers before task engine start: %w", err))
	}

	var tz string
	// 默认时区单源 db.DefaultTimezone（DDL DEFAULT 与迁移归一同一常量）——
	// 启动期读侧写死字面量会与库默认值分叉：DDL 改动后进程时区仍取旧值，
	// 运行期时间轴与面板展示时间轴静默不一致。
	if loaded, err := startupTimezone(db.DB); err != nil {
		// 时区读取失败不得静默——此前整库读错误直接落
		// 「按进程默认时区运行」，所有墙面时间（任务排程/task_runs/审计）
		// 与实际配置时区分叉且无任何信号。
		services.Logf("error", "failed to read timezone from global_config (falling back to process default): %v", err)
	} else {
		tz = loaded
	}
	if tz != "" {
		// 正确性由 ConfigureLocation 决定（面板/任务/审计/tzLogWriter 的展示
		// 时区单源，atomic 指针）。time.Local 只影响第三方库的默认格式化，
		// 但必须在本进程任何 worker 启动之前赋值——logrotate 的 time.Now()
		// 会读它（裸写与后台读构成数据竞争）。因此本段排在 StartLogRotate 前。
		if loc, err := services.ConfigureLocation(tz); err != nil {
			services.Logf("error", "failed to load timezone %s: %v", tz, err)
		} else {
			time.Local = loc
			log.Printf("Timezone set to %s", tz)
		}
		// TZ 只影响后续 os/exec 子进程（caddy CLI 校验）的环境；与
		// ConfigureLocation 互不相关，失败不得阻断主路径（此前 else-if 把
		// 两条串行，setenv 失败会让面板时区静默不生效）。
		if err := os.Setenv("TZ", tz); err != nil {
			services.Logf("error", "failed to set TZ environment（仅影响 caddy CLI 等子进程）: %v", err)
		}
	}
	// 运行日志大小刷新 worker 在库就绪且时区生效后启动：首次刷新即读真实库值
	//（此前包 init 自启，首刷必撞 nil 库空转，启动 30s 内按兜底 100MB）。
	services.StartLogRotate(context.Background())

	// Initialize services
	caddyService := services.NewCaddyServiceWithMetricsURL(cfg.CaddyAdminURL, cfg.CaddyMetricsURL)
	// 2026-09-06 裁定 ③：每次成功下发后落盘最后已知正确配置，启动 DB 渲染
	// 被拒时回退应用（负载均衡可用性兜底）。
	// 2026-09-06 裁定 ④'：任意 Caddy 修改三层校验的 Caddy 层——写路径在事务内
	// 应用前用 caddy CLI（真 validate-only）校验最终渲染；二进制缺失/超时自动
	// 放行（事务内应用仍门控）。
	caddyService.EnableCLIValidation()
	caddyService.SetLastGoodPath(filepath.Join(cfg.DataDir, "last_good_caddy_config.json"))
	// 数据类更新（xdb/CRS/CA 证书文件）后的重载必须强制——配置
	// JSON 不变时 Caddy 会跳过 provision（errSameConfig 短路），插件内存停留
	// 旧库而更新流程报成功。三个消费方（IP 库/CRS/CA 队列）全是数据更新入口。
	caddyReloader := func() error {
		return caddyService.GenerateAndApplyConfigForce()
	}
	// CA 证书队列走 InLock 变体——部署临界区按全局锁序
	// CaddyOpLock → DeployLock 先持 CaddyOpLock（与规则补偿恢复链同序，
	// 消除 AB-BA），重载回调不得再自取锁（重入死锁）。CRS/IP 库/威胁库
	// 管理器的调用点不持 CaddyOpLock，仍用自取锁的 Force 变体。
	// 审计项：后台数据类重载统一经 TrackBackgroundReload 记账——失败进状态接口
	// 与面板横幅（此前只有应用日志，caddy_apply_error 仅覆盖 handler 写路径）。
	services.InitCAQueueManager(services.TrackBackgroundReload(services.BackgroundApplyCertDeploy, func() error {
		return caddyService.GenerateAndApplyConfigForceInLock()
	}), cfg.DataDir)
	services.InitCRSUpdateManager(services.TrackBackgroundReload(services.BackgroundApplyCRS, caddyReloader))
	services.InitIP2Region()
	services.InitIP2RegionUpdateManager(services.TrackBackgroundReload(services.BackgroundApplyIP2Region, caddyReloader))
	metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
	syncService := services.NewSyncService(db.DB, cfg, caddyService)
	lifecycle := newRuntimeLifecycle(syncService, func() lifecycleWorker {
		return services.NewCertificateService()
	})
	clusterService := services.NewClusterService(db.DB, cfg.DataDir)
	caProviderService := services.NewCAProviderService(cfg.DataDir)

	h := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddyService, MetricsService: metricsService,
		SyncService: syncService, ClusterService: clusterService, CAProviderService: caProviderService,
	})

	// Seed the CRS rules tree into a fresh /app/waf bind mount (a persisted
	// snapshot with user-updated rules wins over the pristine image copy),
	// then materialize cert files from DB, then apply Caddy config on startup
	// WAF 文件目录按 data_dir 派生（容器 /app/data → /app/waf 恒等；本地开发
	// 落到数据目录同级）。须在首个渲染（ApplyConfigOnStartup）之前。
	// 派生面含 Coraza 审计日志路径——目录创建必须排在其后，否则
	// 自定义 data_dir 下仍会去建 /app/logs/waf-audit 并漏建真实目录。
	services.ConfigureWafDirs(cfg.DataDir)
	// 审计日志目录必须在首次 ApplyConfigOnStartup
	// 前保证存在——coraza NewWAF 时 OpenFile 不建父目录,缺失=/load 拒收。
	// 级别为 error（与相邻的 IP 名单目录同口径）：同一类前置依赖、同一失败
	// 后果（整份配置被 /load 拒收），warn 在 log_level=error 的常见生产配置下
	// 会被整行丢弃，排障从「配置应用失败」倒查不到目录权限根因。
	if err := services.EnsureWafAuditDir(); err != nil {
		services.Logf("error", "创建 WAF 审计目录失败（含 WAF 的配置将被 /load 拒收）: %v", err)
	}
	// @ipListFast 名单投影目录（v2.3.x）：渲染期 fail-closed 依赖目录可写。
	if err := services.EnsureIPListDir(); err != nil {
		services.Logf("error", "初始化 IP 名单目录失败: %v", err)
	}
	// 系统配置载入（单一 oneshot 任务：规则库→证书→Caddy 渲染三段；完成于
	// 面板监听之前——载入完成前系统不可达（强于只读））
	// runConfigLoad 为共享执行体——启动与任务监控手动触发走同一函数
	// （2026-09-29 用户裁定：任务逻辑迁入任务后，手动执行与系统启动触发
	// 效果必须一致，含「载入」审计与全部前置物化步骤）。
	// operator 透传——手动重载载入审计归因操作者，启动（空）归 system。
	runConfigLoad := func(operator string) error {
		services.SeedCRSRules()
		services.ReconcileCRSState()
		services.TaskLogf("startup:config-load", "libs", "规则库载入完成（CRS %s 对账）", services.CurrentCRSVersionForLog())
		// 归一前落库的安全策略枚举空串行（发射端零产出 + Update 拒修的
		// 遗留状态），有实际变更时主节点递增集群版本让从节点收敛。
		services.NormalizeLegacySecurityPolicyEnums(context.Background())
		services.MaterializeAllCertsFromDB()
		return h.ApplyConfigOnStartup(operator)
	}
	// 启动执行移入引擎 BootSync（下方 InitTaskEngine 尾部
	// 同步触发 startup:config-load——面板监听前完成不变量保持；失败语义同旧：
	// 仅记录不退出）。
	// Caddy 重启监听——监督器触发后走与启动相同的 DB 渲染→应用流程
	// (修正 last_good 快照可能滞后于 DB 的窗口)。
	h.StartCaddyRestartWatcher()
	// 配置一致性看门狗：周期比对 DB 规则与 Caddy 运行配置，不一致时三通道告知
	// （系统日志/操作日志/前端横幅），恢复由用户手动重启完成。
	// 统一任务引擎：看门狗/安全事件摄取/运行日志清理三常驻族迁入
	// （单轮体+引擎节拍；原生自循环与 TaskRuntime 注册表退役）。
	services.SetConfigLoadRerun(runConfigLoad) // 启动 BootSync 与手动重载=同一执行体（含载入审计）
	// B 完全标准化：常驻服务真实生命周期挂钩（daemon Run start→阻塞→stop；
	// 幂等守卫吸收 lifecycle 直调与 daemon 挂钩的双调用）
	services.SetCertIssuanceLifecycleHooks(lifecycle.StartACME, lifecycle.StopACME)
	// 同步侧必须与证书侧对称注入 runtimeLifecycle 的方法而非裸
	// syncService.Start/Stop——stopped 门（「Shutdown 后不得再拉起」）
	// 与 l.mu 串行化只存在于 lifecycle 包装内，裸方法会让任何迟代/新增调用方
	// 绕过退出门。StopSync 自身幂等（Shutdown 已调用）。
	services.SetSyncLifecycleHooks(lifecycle.StartSync, lifecycle.StopSync)
	services.SetSyncLifecycleHaltedProbe(syncService.IsHalted)
	// 自愈链最后一跳：Halted 的同步服务只能由 Resume 复活（Start 是 no-op）。
	services.SetSyncLifecycleResumeHook(syncService.Resume)
	// 自动备份执行器必须先于 InitTaskEngine：启用且存在补跑槽时，
	// 引擎首轮可能在毫秒内到期，不得在 nil executor 下记录成功。
	services.SetAutoBackupExecutor(func(ctx context.Context, trigger, operator string, engineRunID int64) error {
		_, err := h.RunAutoBackupOnce(ctx, trigger, operator, engineRunID)
		return err
	})
	// 威胁库依赖（reloader/投影回调/manager 单例）必须先于
	// InitTaskEngine 装配——引擎启动即按 due 槽调度 threat，manager nil 曾让
	// Run 落 success（威胁库永不更新且缺陷不可见）。与 auto-backup executor
	// 同型：任务体依赖的运行期钩子一律前置。
	services.SetThreatReloader(services.TrackBackgroundReload(services.BackgroundApplyThreat, caddyReloader))
	// 投影热路径（2026-10-15 用户裁定：威胁库重载门退役）——名单内容变化的
	// 引用面收敛改走投影重写（零 /load，@ipListFast 匹配器与受信代理网段
	// tp.txt/lb_file ≤1s stat 热感知）；threatReloader 仅残留热路径未证实
	// 收敛时的 fail-safe 回退。
	services.SetThreatProjectionRefresher(func() (services.IPListProjectionOutcome, error) { return caddyService.RefreshIPListProjections() })
	// 摄取提交后回退 rollup 覆盖水位——停机/升级积压事件落在 warmer
	// 已覆盖分钟时重固（否则大屏永久少计；warmer 首轮先于摄取首 pass 运行）。
	services.SetSecurityEventsRollupRewrite(handlers.ThreatRollupRewindTo)
	services.InitThreatUpdateManager()
	services.InitTaskEngine(cfg.CaddyAdminURL, runtimeLogFile) // 前置设施——非任务
	// 引擎收尾统一交由下方 tail defer（StopTaskEngine 幂等）；此处不再重复
	// defer（双 defer 依赖幂等，收敛单点收尾）。

	// 威胁大屏 rollup 后台固化（幂等：启动即一次 + 每 60s 一轮；启动后大屏
	// 请求路径不再懒固化，避免与用户请求抢写锁/重复回填）。
	warmerCtx, warmerCancel := context.WithCancel(context.Background())
	cancelThreatRollupWarmer := warmerCancel
	handlers.StartThreatRollupWarmer(warmerCtx)

	// Setup router
	router := middleware.SetupRouter(h, cfg)
	restart, requestRestart := newRestartSignal()
	services.SetRestartRequiredHandler(requestRestart)
	defer services.SetRestartRequiredHandler(nil)

	// Start services
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		metricsService.Start()
	}()
	// 角色读取走单源 services.RoleOf（COALESCE(is_master,1) 与
	// readonly/cluster_version/任务引擎同口径）——此前裸 SELECT 对 NULL 扫描
	// 失败并按从节点处理，与其余守卫语义分叉。仅用于爬虫名单播种；读取失败
	// 仍按从节点处理。
	isMaster, err := services.RoleOf(context.Background(), db.DB)
	if err != nil {
		services.Logf("error", "failed to read cluster role: %v", err)
		isMaster = false
	}
	// 自动封禁名单变化后的收敛。投影热路径优先（2026-10-15 用户裁定）
	// 资格门（被启用策略引用；受信代理引用面已随 tp.txt/lb_file 热路径化
	// 退役）命中 → RefreshIPListProjectionsInLock 零 /load 收敛（@ipListFast
	// 匹配器 ≤1s stat 热感知）；资格未命中/不可判定/未证实收敛 →
	// autobanReloader 全量重载回退（60s 节流暂存合并）。
	// merge 读改写+收敛全程持 CaddyOpLock，两个注入必须为 InLock 变体（自取
	// 锁变体在临界区内重入=死锁）。
	services.SetAutobanReloader(services.TrackBackgroundReload(services.BackgroundApplyAutoban, func() error {
		return caddyService.GenerateAndApplyConfigForceInLock()
	}))
	services.SetAutobanProjectionRefresher(func() (services.IPListProjectionOutcome, error) { return caddyService.RefreshIPListProjectionsInLock() })
	if isMaster {
		if err := services.GetCrawlerUpdateManager().Prime(); err != nil {
			services.Logf("error", "crawlerbot-update: 内置首版名单预载失败: %v", err)
		}
	}
	// 审计日志轮转由事件摄入循环驱动（先采集后轮转），此处无需独立启动器
	// 安全事件采集已由任务引擎接管（InitTaskEngine 注册 2s 循环）
	// 关停预算单例——waitForServerStop 的 HTTP/Caddy 段与下方
	// cleanup defer 的引擎排空/ACME 收尾共用同一 deadline（惰性起算）。
	shutdown := newShutdownBudget()
	defer func() {
		// 进入关停收尾的第一件事：停止向 quit 转发信号。此后第二次
		// SIGTERM/SIGINT 走默认动作，可强制结束卡在收尾段的进程——此前只有
		// quit/restart 分支显式 Stop，serverErrors 异常退出与早退路径在收尾
		// 窗口（最坏 25s）内第二次信号会被缓冲丢弃，恰是最需要「第二击」的
		// 场景没有逃生门。signal.Stop 幂等，与 waitForServerStop 内的显式调用
		// 并存安全。
		signal.Stop(quit)
		cancelThreatRollupWarmer()
		// warmer 只在轮次之间检查 ctx：在途固化批不会被打断，可能继续读写到
		// db.Close 之后（"database is closed" 告警 + 该批回滚）。与同层 worker
		// 一致按剩余预算有界等待，且不动收尾段预留。
		if !handlers.WaitThreatRollupWarmer(shutdown.segmentReserving(threatWarmerStopSegmentMax, trailingStopReserve)) {
			services.Logf("warn", "威胁大屏 rollup warmer 未在关停预算内退出，放弃等待（进程继续退出）")
		}
		// 事件摄入与其余 worker 同生命周期——db.Close 前 cancel，
		// 否则退出窗口内每 2s 对已关闭 MetricsDB 刷 "database is closed" 告警。
		// 引擎排空按剩余预算派生（为 ACME 收尾预留），不再使用
		// StopTaskEngine 的 30s 默认——30s 本身已超 compose stop_grace_period。
		stopTaskEngineWithin(shutdown) // M2:引擎统一收尾(摄取/看门狗/清理)
		// 以下等待全部从关停预算派生有界——旧形态
		// <-metricsDone / StopX 的无界 <-done 在 collect/refresh 阻塞
		// （http.Client 10s、DB busy_timeout 30s）时可把进程拖过 compose
		// grace 被 SIGKILL。超时放弃等待并 warn：进程继续退出，残留
		// goroutine 随进程消亡，比拖过 grace 被强杀（WAL 写中段断）安全。
		// metricsService.Stop 内部的清理等待（固定 3s）同样不可预算：有界执行
		// 且不侵占收尾段预留（此前它无条件吃掉 3s，ACME 段可被钳成 0）。
		runWithin("metrics 清理等待", shutdown.segmentReserving(metricsCleanupSegmentMax, trailingStopReserve), metricsService.Stop)
		awaitChannelWithin("metrics 采集循环", metricsDone, shutdown.segment(metricsStopSegmentMax))
		// 时区/日志轮转的 Stop*Within 把 within<=0 定义为「无界等待」，与同层
		// awaitChannelWithin/runWithin 的「0=放弃」相反。segment() 在预算耗尽时
		// 返回 0，直接传入会把最需要按时退出的分支变成永不放 弃——必须显式跳过
		// （worker 随进程退出，残留 goroutine 由进程回收）。
		stopWithinIfBudgeted(shutdown.segment(tzStopSegmentMax), services.StopTimezoneRefreshWithin)
		stopWithinIfBudgeted(shutdown.segment(logRotateStopSegmentMax), services.StopLogRotateWithin)
		// 证书 worker 的等待有界（此前 Stop 自身无界阻塞、超时 select 不可达）。
		lifecycle.ShutdownWithTimeout(shutdown.segment(acmeStopSegmentMax))
	}()

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	// 版本单一事实源=config(APP_VERSION env/Dockerfile ARG 兜底)——此前打印
	// ldflags 变量 version(无注入链恒 "dev"),与 branding API 版本分叉
	// (v2.3.0 首发漏注入,记忆在案)。不存在 ldflags 注入通道。
	log.Printf("Starting lazy-balancer-v2 %s on %s", cfg.Version, addr)
	server := newAdminHTTPServer(addr, router)

	// 监听协议必须走严格读取变体：宽容版在库读取失败时回退 Enabled=false，
	// 本进程会以明文 HTTP 在同一端口提供登录与 API（无跳转、无拒绝），把
	// 「配置读不到」静默变成「未启用 HTTPS」的安全属性丢失。读失败即拒绝
	// 启动（与 ResolveCertificate 失败同口径），由编排层重试；不得降级监听。
	tlsCfg, tlsErr := startupAdminTLSConfig()
	if tlsErr != nil {
		return startupFailed(tlsErr)
	}
	services.RecordRuntimeAdminTLS(tlsCfg)
	serverErrors := make(chan error, 1)
	// 启动窗口内已收到退出信号——不再开监听，直接走正常关停收尾
	// （cleanup defer 负责引擎/worker；排水与 pause 标记与监听路径同口径）。
	// quit 在 run() 开头注册且缓冲=1，BootSync 期间的信号在此保留而非触发
	// 默认终止。
	if takePendingSignal(quit) {
		services.Logf("info", "启动窗口内收到退出信号，跳过监听并执行关停收尾")
		// 与 waitForServerStop 同口径：进入关停后停信号通道，用户的第二次
		// /SIGTERM 恢复默认动作（可强制结束卡顿的收尾）。
		signal.Stop(quit)
		drainCaddy(cfg.CaddyAdminURL, shutdown.segment(caddyDrainSegmentMax))
		return nil
	}
	if tlsCfg.Enabled {
		cert, err := tlsCfg.ResolveCertificate(cfg.DataDir)
		if err != nil {
			return startupFailed(fmt.Errorf("管理面板 HTTPS 启用失败: %w", err))
		}
		log.Printf("管理面板 HTTPS 监听 %s（证书来源：%s，HTTP 明文请求 302 跳转）", addr, tlsCfg.Mode)
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return startupFailed(fmt.Errorf("HTTPS 监听失败: %w", err))
		}
		go func() { serverErrors <- server.ServeTLS(newHTTPRedirectMux(ln), "", "") }()
	} else {
		// 显式 Listen 再 Serve（等价 ListenAndServe）：绑定失败属启动期失败
		// （服务从未开始监听），必须能与运行期 serve 中止分判。
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return startupFailed(fmt.Errorf("HTTP 监听失败: %w", err))
		}
		go func() { serverErrors <- server.Serve(ln) }()
	}

	serverErr := waitForServerStop(server, serverStopSignals{quit: quit, restart: restart, serverErrors: serverErrors, caddyAdminURL: cfg.CaddyAdminURL, budget: shutdown})
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", serverErr)
	}
	return nil
}

// startupAdminTLSConfig 读取管理面板 HTTPS 配置用于启动监听。读失败必须
// 返回 error（run 据此拒绝启动）：宽容 loader 的回退值 Enabled=false 会让本
// 进程以明文 HTTP 提供管理面，而从外部看只是「HTTPS 关闭」，不构成可接受的
// 降级。独立成函数以便钉住该判定。
func startupAdminTLSConfig() (services.AdminTLSConfig, error) {
	cfg, err := services.LoadAdminTLSConfigE()
	if err != nil {
		return services.AdminTLSConfig{}, fmt.Errorf("读取管理面板 HTTPS 配置失败，拒绝以明文方式监听管理端口（请检查数据库可用性后重启）: %w", err)
	}
	return cfg, nil
}

// startupTimezone 读取启动期进程时区（global_config.id=1）。
// NULL/缺行落到 db.DefaultTimezone 单源；读错误原样上抛，由调用方留痕并退回
// 进程默认时区（与其余时区读侧同口径）。独立成函数以便钉住「默认值单源 +
// NULL/缺行」两种形状。
func startupTimezone(database *sql.DB) (string, error) {
	var tz string
	if err := database.QueryRow("SELECT COALESCE(timezone, ?) FROM global_config WHERE id=1", db.DefaultTimezone).Scan(&tz); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// 无配置行（全新库/初始化中断）：落到治理默认值——「未配置」不是
			// 读失败，不该退回进程默认时区。
			return db.DefaultTimezone, nil
		}
		return "", err
	}
	if tz == "" {
		return db.DefaultTimezone, nil
	}
	return tz, nil
}

// newAdminHTTPServer 统一面板 HTTP 超时。请求头仍保持 10s 慢头护栏；
// 大体积备份导入/导出（上限由 handlers.maxConfigImportBytes 定义，不在本文件
// 重复数字）与含 CRS/IP2Region 的大备份下载需要分钟级正文读写预算，不再沿用
// 30s/60s 的绝对截止。
func newAdminHTTPServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       5 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       120 * time.Second,
	}
}

func newRestartSignal() (<-chan struct{}, func()) {
	restart := make(chan struct{}, 1)
	return restart, func() {
		select {
		case restart <- struct{}{}:
		default:
		}
	}
}

// 关停预算----
//
// compose 的 stop_grace_period=30s，而关停链此前各段独立超时：
// HTTP Shutdown ≤10s + drainCaddy ≤2s + engine.Stop 30s + StopACME 无界
// <-done——最坏远超 grace，PID1 在引擎排空完成前收到 SIGKILL，正是
// engine.Stop 注释要避免的「审计/日志尾部丢失 + task_runs 行滞留 running」。
// Go 侧改为单一总预算 25s（留 5s 余量给日志 flush/进程退出），
// 各段从共享 deadline 派生并钳制：
//
// 实际 defer 顺序（与 cleanup defer 体逐行对应）：
//
//	HTTP ≤10s → Caddy 排水 ≤2s → 威胁大屏 warmer ≤2s
//	→ 引擎排空 = 剩余 − trailingStopReserve
//	→ 引擎句柄清理 = min(≤5s, 剩余 − trailingStopReserve)
//	→ metrics 清理等待 = min(≤3s, 剩余 − trailingStopReserve)
//	→ metrics 采集 ≤2s → 时区 ≤1s → 日志轮转 ≤1s
//	→ 证书收尾 ≤5s（段内 = 同步停止 ≤3s + ACME 收尾 = 剩余）
//
// 证书收尾段由 runtimeLifecycle.ShutdownWithTimeout 消费：段内先跑集群同步停止
// （min(传入预算, syncStopSegmentMax=3s)），剩余预算全部留给 ACME 收尾。
// 时区/日志轮转两段在预算归 0 时直接跳过（Stop*Within 的 within<=0 语义是
// 无界等待，不能把 segment() 的 0 传进去）。
//
// 最坏 10+2+2+2+0+0+2+1+1+5 = 25s ≤ 30s grace（引擎吃满时两处
// segmentReserving 段按设计归 0）。deadline 之外还有 engineHandleSwapGrace
// (50ms) 与各 select 定时器的调度余量。唯一事实源是
// shutdown_budget_test.go 的 fake-clock 最坏路径断言——本注释只是导读；
// 新增收尾段必须同时加常量、更新 trailingStopReserve 与测试。
const (
	processShutdownBudget  = 25 * time.Second
	httpShutdownSegmentMax = 10 * time.Second
	caddyDrainSegmentMax   = 2 * time.Second
	acmeStopSegmentMax     = 5 * time.Second
	// 收尾段上限：metrics 采集循环退出等待（collect 最坏阻塞
	// 在 http.Client 10s + DB busy_timeout 30s）、时区/日志轮转刷新 worker
	// 退出等待（refresh 阻塞在 DB busy_timeout）——正常路径均为空闲 select
	// 循环，cancel 后 µs 级退出，段上限只兜卡住形态；超时放弃等待（进程继续
	// 退出，残留 goroutine 随进程消亡）。
	metricsStopSegmentMax   = 2 * time.Second
	tzStopSegmentMax        = 1 * time.Second
	logRotateStopSegmentMax = 1 * time.Second
	// 关停链中三处「不可预算的同步收尾」的等待上限——对应实现内部的固定
	// 上界（引擎全局句柄清理的角色对账 5s、metrics 停止清理 3s、威胁大屏
	// warmer 在途批 2s）。这些调用不接受 deadline，必须由本层按预算有界执行；
	// 它们只允许花「引擎排空后尚未用完的预算」，不得侵占下方
	// trailingStopReserve（见 segmentReserving）。
	engineHandleStopSegmentMax = 5 * time.Second
	metricsCleanupSegmentMax   = 3 * time.Second
	threatWarmerStopSegmentMax = 2 * time.Second
	// engineHandleSwapGrace 预算耗尽时等待「摘除引擎句柄」的极小窗口：<0.2%
	// grace，可观测上不改变关停总壁钟，但不允许已停引擎的句柄活过 db.Close。
	engineHandleSwapGrace = 50 * time.Millisecond
	// trailingStopReserve 引擎排空必须为后续收尾段预留的预算。
	trailingStopReserve = metricsStopSegmentMax + tzStopSegmentMax + logRotateStopSegmentMax + acmeStopSegmentMax
)

// shutdownBudget 进程关停的单一时间预算。
//
// 惰性起算：deadline 在首次调用时按 processShutdownBudget 设定，而不是在
// run() 开头——启动（BootSync 可达数十秒）不得吃掉关停预算；未进入
// waitForServerStop 的错误早退路径首次调用时同样获得完整预算。
// now 是测试注入缝（fake clock 验证最坏路径的段派生）。非并发安全：只在
// 关停单 goroutine（waitForServerStop → cleanup defer）内使用。
type shutdownBudget struct {
	now      func() time.Time
	deadline time.Time
}

func newShutdownBudget() *shutdownBudget { return &shutdownBudget{now: time.Now} }

// remaining 距关停 deadline 的剩余预算（耗尽返回 0）。
func (b *shutdownBudget) remaining() time.Duration {
	if b.now == nil {
		b.now = time.Now
	}
	if b.deadline.IsZero() {
		b.deadline = b.now().Add(processShutdownBudget)
	}
	if r := b.deadline.Sub(b.now()); r > 0 {
		return r
	}
	return 0
}

// segment 段上限 = min(段自身上限, 总预算剩余)。
func (b *shutdownBudget) segment(max time.Duration) time.Duration {
	if r := b.remaining(); r < max {
		return r
	}
	return max
}

// segmentReserving 段上限 = min(段自身上限, 剩余预算 − reserveAfter)，
// 预算已不足以留下后续预留时返回 0（调用方据此放弃等待）。
//
// 用于插在收尾段之前、自身又不可预算的同步收尾（引擎句柄清理/metrics 清理
// 等待/威胁大屏 warmer）：它们只能花「还没被用完的预算」，不得把
// trailingStopReserve 挤成 0——否则其后的 ACME/metrics 段按剩余钳制后归 0，
// 收尾直接放弃等待。
func (b *shutdownBudget) segmentReserving(max, reserveAfter time.Duration) time.Duration {
	r := b.remaining() - reserveAfter
	if r <= 0 {
		return 0
	}
	if r < max {
		return r
	}
	return max
}

// engineDrain 引擎排空上限 = 剩余预算 − 收尾段预留（metrics/时区/日志轮转
// 等待 + ACME 收尾）。
//
// 引擎排空是关停链最长的一段（部分在途任务段不消费取消信号），若吃满
// 剩余预算，其后的收尾段将无预算可用。归零时返回 1ms：引擎把 <=0 视为
// 「未指定」并回落到默认 30s（engine.StopWithTimeout），绝不能传 0。
func (b *shutdownBudget) engineDrain() time.Duration {
	d := b.remaining() - trailingStopReserve
	if d <= 0 {
		return time.Millisecond
	}
	return d
}

// stopTaskEngineWithin 引擎排空按关停预算执行，再清全局句柄。
// services.StopTaskEngine 内部的 Stop()=30s 默认会超出 compose grace，生产
// 退出路径必须走本函数（测试/服务包的既有直调入口不受影响）。
//
// 排空本身走 StopWithTimeout；随后的全局句柄清理（services.StopTaskEngine）
// 内部还有一段固定上界的角色对账等待（对账 goroutine 卡在 DB 读时最长 5s），
// 不接受调用方 deadline——按「引擎排空后尚未用完的预算」有界执行，绝不侵占
// 收尾段预留（ACME 段曾被这两处等待挤成 0）。
func stopTaskEngineWithin(b *shutdownBudget) {
	te := services.TaskEngine()
	if te == nil {
		return
	}
	te.StopWithTimeout(b.engineDrain())
	// 全局句柄清理（摘除句柄 + 停引擎 + 等角色对账 ≤5s）。摘除在函数入口
	// 即完成，后台读取方立即看到 nil；等待部分不可预算，因此总是发起清理，
	// 只按「引擎排空后尚未用完的预算」决定等多久——不再无条件吃掉 3~5s。
	done := make(chan struct{})
	go func() {
		defer close(done)
		services.StopTaskEngine()
	}()
	wait := b.segmentReserving(engineHandleStopSegmentMax, trailingStopReserve)
	if wait <= 0 {
		// 预算不足以留出收尾段预留：只等一个摘除句柄的极小窗口（<0.2% grace），
		// 之后不再等待——已停引擎的句柄绝不留到 db.Close 之后。
		select {
		case <-done:
		case <-time.After(engineHandleSwapGrace):
			services.Logf("warn", "关停预算已不足以等待 任务引擎全局句柄清理 收尾，只发起清理不等待（进程继续退出）")
		}
		return
	}
	awaitChannelWithin("任务引擎全局句柄清理", done, wait)
}

// runWithin 关停期的有界单次调用：fn 放进 goroutine，等待由预算派生；超时
// （或预算已耗尽）放弃等待并 warn——进程继续退出，残留 goroutine 随进程
// 消亡。d<=0 表示预算不足以留出后续预留，直接不等待。
func runWithin(what string, d time.Duration, fn func()) bool {
	if d <= 0 {
		services.Logf("warn", "关停预算已不足以等待 %s 收尾，跳过等待（进程继续退出）", what)
		return false
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	return awaitChannelWithin(what, done, d)
}

// awaitChannelWithin 关停收尾的预算派生有界等待：ch 在 d
// 内关闭返回 true；超时（或 d<=0 预算已耗尽）放弃等待、warn 并返回 false——
// 进程继续退出，残留 goroutine 随进程消亡。正常路径（ch 已关闭/随即关闭）
// 立即返回，不等满预算。
func awaitChannelWithin(what string, ch <-chan struct{}, d time.Duration) bool {
	if d <= 0 {
		services.Logf("warn", "关停预算已耗尽，放弃等待 %s 退出（进程继续退出）", what)
		return false
	}
	select {
	case <-ch:
		return true
	case <-time.After(d):
		services.Logf("warn", "%s 未在关停预算 %s 内退出，放弃等待（进程继续退出）", what, d)
		return false
	}
}

// stopWithinIfBudgeted 在预算为正时执行有界停止，预算耗尽（d<=0）时跳过并
// 返回 false。用于把「within<=0=无界等待」形态的 Stop*Within 接到关停预算上：
// segment() 归零表示总预算已用完，此时调用即等于取消有界等待。
func stopWithinIfBudgeted(d time.Duration, stop func(time.Duration) bool) bool {
	if d <= 0 {
		services.Logf("warn", "关停预算已耗尽，跳过该收尾段的等待（worker 随进程退出）")
		return false
	}
	return stop(d)
}

// takePendingSignal 非阻塞读取启动窗口内已缓存的退出信号（quit 缓冲=1，
// BootSync 期间到达的信号在此保留）。
func takePendingSignal(quit <-chan os.Signal) bool {
	select {
	case <-quit:
		return true
	default:
		return false
	}
}

type serverStopSignals struct {
	quit         chan os.Signal
	restart      <-chan struct{}
	serverErrors <-chan error
	// caddyAdminURL Caddy admin 端点。
	caddyAdminURL string
	// budget 进程关停总预算；nil=新建（测试直调形态）。
	budget *shutdownBudget
}

func waitForServerStop(server *http.Server, signals serverStopSignals) error {
	select {
	case <-signals.quit:
	case <-signals.restart:
	case err := <-signals.serverErrors:
		return err
	}
	// 无论由 quit 还是 restart 触发，都在进入关停流程前统一停
	// 信号通道（先于 "Shutting down..." 与 ≤10s 的 HTTP Shutdown 窗口）。
	// 此前仅 quit 分支停通道：restart 分支的关停窗口内第二个信号会被通道
	// 缓冲，随后被 run() 返回后的 defer signal.Stop 冲刷丢弃，无法触发默认
	// 终止（用户第二次 / SIGTERM 应能强制结束卡顿的关停）。
	// serverErrors 分支直接返回：服务已异常，由 run() 的关停收尾 defer 首行
	// signal.Stop 收尾（同样关闭第二次信号的逃生门）。
	signal.Stop(signals.quit)

	log.Println("Shutting down...")
	// HTTP 段从关停总预算派生（≤10s），后续引擎排空/ACME 收尾
	// 在同一 deadline 内获得剩余预算。
	budget := signals.budget
	if budget == nil {
		budget = newShutdownBudget()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), budget.segment(httpShutdownSegmentMax))
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		services.Logf("error", "HTTP server shutdown failed: %v", err)
		if closeErr := server.Close(); closeErr != nil {
			services.Logf("error", "HTTP server forced close failed: %v", closeErr)
		}
	}
	// 进程退出前给 Caddy 排水窗口——此前 PID1 退出后容器 teardown 直接
	// SIGKILL 残存进程（含监督器与 Caddy），每次升级/重启硬断全部在途代理
	// 连接。POST /stop 让 Caddy 优雅关停；admin 不可达（已停/独立部署）静默
	// 略过。restart 路径同理（进程退出由容器编排重建，Caddy 排水后由新容器
	// 监督器重拉）。
	drainCaddy(signals.caddyAdminURL, budget.segment(caddyDrainSegmentMax))
	return nil
}

// caddyPauseFileDefaultPath 与 handlers 包的 caddyPauseFile（internal/handlers/caddy.go）
// 及 docker-entrypoint.sh 的 CADDY_PAUSE_FILE 同值 "/tmp/lazy-balancer-caddy-paused"
// ——main 包不 import handlers 的未导出变量，自持路径并以注释互指；任一侧
// 改路径须三处同步。
const caddyPauseFileDefaultPath = "/tmp/lazy-balancer-caddy-paused"

// caddyPauseFilePath 是停机路径的 pause 标记路径（包级变量而非常量：
// 测试需要注入临时目录验证「不存在则建/已存在不覆盖/写失败留痕」三条语义；
// 与 handlers 侧同形态）。
var caddyPauseFilePath = caddyPauseFileDefaultPath

// writeDrainPauseFile：排水前建 pause 标记，让监督器把
// 本次优雅停机按「admin 停止」分支处理（docker-entrypoint.sh 见文件不重启、
// CRASHES 不 +1）——此前 drainCaddy 直接 POST /stop，监督器一律按崩溃重拉，
// 排水窗口内 1s 退避重绑 80/443，伪 Crash 噪音+排水语义被消解。
// 与 stopCaddy（handlers/caddy.go）刻意不同：仅当文件不存在时写（不覆盖
// stopCaddy 用户意图停机的在场标记）；写后即使排水请求失败也不回滚——本
// 函数只在整个进程退出路径上调用，而 stopCaddy 是长驻运行期操作，停失败
// 必须回滚让监督器继续看护。
// pause 生命周期=容器运行期。注意：docker stop/start、restart 复用同一容器
// 可写层，/tmp 并不清空（事故：曾误假设「随容器重建清空」，导致
// 重启后监督器开机 standby、Caddy 永不拉起）——跨重启残留由监督器启动首行
// 清残兜底（docker-entrypoint.sh）；非容器部署下次 startCaddy
// 亦会删标记。此处粘滞因此安全。
func writeDrainPauseFile() {
	if info, err := os.Stat(caddyPauseFilePath); err == nil {
		// 同名目录占据标记路径时 Stat 也成功——静默当作「已存在」会让
		// supervisor 按崩溃重拉（伪 CRASHES）且 app 侧零线索。留痕后照常返回
		// （写入必然失败，且这不是本函数能自愈的带外状态）。
		if info.IsDir() {
			services.Logf("warn", "Caddy pause 标记路径 %s 被同名目录占据（监督器将按崩溃重拉，需人工清理）", caddyPauseFilePath)
		}
		return
	}
	// 写失败必须可见：pause 语义失效时监督器按崩溃重拉（排水窗口内抢绑
	// 80/443 + 伪 CRASHES 计数），现象在 Caddy/监督器侧，app 侧零线索则
	// 排查无门。行为保持 best-effort：仍继续排水请求。
	if err := os.WriteFile(caddyPauseFilePath, nil, 0o644); err != nil {
		services.Logf("warn", "Caddy pause 标记 %s 写入失败（监督器将按崩溃重拉）: %v", caddyPauseFilePath, err)
	}
}

// drainCaddy best-effort 请求 Caddy admin /stop（timeout 上限，错误只记日志）。
// timeout 由关停预算派生（≤2s）；预算已耗尽时跳过请求直接返回，
// 让进程按时退出（容器 teardown 仍会回收 Caddy）。
func drainCaddy(adminURL string, timeout time.Duration) {
	if adminURL == "" {
		return
	}
	writeDrainPauseFile()
	if timeout <= 0 {
		services.Logf("warn", "关停预算已耗尽，跳过 Caddy 排水请求（Caddy 随容器 teardown 回收）")
		return
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(adminURL, "/")+"/stop", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("info", "Caddy 排水请求未达（可能已停止）: %v", err)
		return
	}
	// 非 2xx 必须留痕：admin 半死（返回 500）时此前零日志，pause 标记又照留，
	// 排障时无法从 app 侧判断 Caddy 是否真的收到 /stop。仍按 best-effort 返回。
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		services.Logf("info", "Caddy 排水请求被拒（status=%d），Caddy 可能未执行优雅关停", resp.StatusCode)
	}
	_ = resp.Body.Close()
}

type tzLogWriter struct {
	w io.Writer
}

// Write 必须按 io.Writer 契约返回 len(p)——向下写的是 prefix+p，直接转交
// 底层返回值会报告 n > len(p)。当前唯一消费者（log.Logger）忽略 n，但一旦
// 日志链路引入缓冲/io.Copy/短写校验，越界 n 会被当成合法字节数使用。
//
// 整行**单次**写：下游 RotatingFileWriter 按每次 Write 判定轮转并先轮转后写，
// 前缀与正文分两次写时，跨阈值的那一行会被拆进两个文件（旧文件尾部只剩裸
// 时间戳、新文件首行没有时间戳）——按行首解析的日志采集与取证因此错位。
// 拼接缓冲取自 sync.Pool，避免每行新分配（日志密集时每秒数百行）。
//
// 短写（底层 n<len(line) 且 err==nil）不重试、不留痕：当前唯一下游
// RotatingFileWriter 直写 *os.File，短写不出现；未来接入缓冲/io.Copy 形态时
// 必须先在此显式处理短写（否则整行被静默截断，且本函数按契约返回 len(p)
// 会让上游以为写成功）。
func (t *tzLogWriter) Write(p []byte) (int, error) {
	prefix := time.Now().In(services.CurrentLocation()).Format("2006/01/02 15:04:05 ")
	buffer := logLineBufferPool.Get().(*[]byte)
	line := append((*buffer)[:0], prefix...)
	line = append(line, p...)
	_, err := t.w.Write(line)
	if cap(line) > maxPooledLogLineBytes {
		// 偶发超长行不长期占住池容量（池只服务常规行）。
		*buffer = nil
	} else {
		*buffer = line[:0]
	}
	logLineBufferPool.Put(buffer)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// maxPooledLogLineBytes 是回池行的容量上限：超过它的缓冲不留在池里，
// 避免一条异常长日志把整池内存抬高。
const maxPooledLogLineBytes = 64 * 1024

var logLineBufferPool = sync.Pool{
	New: func() any {
		buffer := make([]byte, 0, 256)
		return &buffer
	},
}
