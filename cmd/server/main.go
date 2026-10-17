package main

import (
	"context"
	"crypto/tls"
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
	"syscall"
	"time"

	"lazy-balancer-v2/internal/acme"
	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/middleware"

	"lazy-balancer-v2/internal/services"
)

// 版本经 config(APP_VERSION env / Dockerfile ARG 兜底)进入 cfg.Version——
// 启动日志与 branding API 同源(此前独立 ldflags 变量无注入链,恒 "dev")。

func main() {
	if err := run(); err != nil {
		services.Logf("error", "HTTP server stopped unexpectedly: %v", err)
		os.Exit(1)
	}
}

func run() error {
	// Parse flags
	configPath := flag.String("config", "", "Config file path")
	initDB := flag.Bool("init", false, "Initialize database")
	flag.Parse()

	// Load configuration
	cfg := config.Load(*configPath)

	// F-SYSR-5（第 71 轮·声明）：SetFlags(0) 是下方 services.NewApplicationLogWriter
	// 日志级别过滤的隐式契约——过滤按行首 "WARNING:"/"ERROR:" 前缀判定（tz.go
	// applicationLogWriter），标准 log 前缀会破坏该判定。此处改 flags 须同步
	// applicationLogWriter 的前缀剥离逻辑（同注释互指）。
	log.SetFlags(0)
	var logWriter io.Writer = os.Stdout
	var runtimeLogFile string
	// SYSRENDER24-3:LogFileEnabled 已恒 true(2026-09-14 裁定)——恒真条件移除。
	if w, err := services.NewRotatingFileWriter(cfg.LogFile); err == nil {
		logWriter = io.MultiWriter(os.Stdout, w)
		defer w.Close()
		runtimeLogFile = cfg.LogFile
	} else {
		// S-3：显式配置了 LOG_FILE 但打开失败必须可见——静默回落仅 stdout 会让
		// 「配置了日志文件却是空的」无从排查。
		log.Printf("log file %s could not be opened, falling back to stdout only: %v", cfg.LogFile, err)
	}
	log.SetOutput(services.NewApplicationLogWriter(&tzLogWriter{w: logWriter}))

	// Initialize database（前置设施——非任务，不入 task_runs）
	if err := db.Initialize(cfg.DataDir); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			services.Logf("error", "close databases during shutdown: %v", err)
		}
	}()
	services.ApplyLogLevel()
	// F49-P5-16：独立 module 边界包（acme/ownership 不得回依赖 services）的
	// 日志接缝在此装配——装配后其告警进入统一日志级别链（services.Logf）。
	acme.SetLogf(services.Logf)
	ownership.SetLogf(services.Logf)
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

	var tz string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err == nil && tz != "" {
		if err := os.Setenv("TZ", tz); err != nil {
			services.Logf("error", "failed to set TZ environment: %v", err)
		} else if loc, err := services.ConfigureLocation(tz); err != nil {
			services.Logf("error", "failed to load timezone %s: %v", tz, err)
		} else {
			time.Local = loc
			log.Printf("Timezone set to %s", tz)
		}
	}

	// Initialize services
	caddyService := services.NewCaddyService(cfg.CaddyAdminURL)
	// 2026-09-06 裁定 ③：每次成功下发后落盘最后已知正确配置，启动 DB 渲染
	// 被拒时回退应用（负载均衡可用性兜底）。
	// 2026-09-06 裁定 ④'：任意 Caddy 修改三层校验的 Caddy 层——写路径在事务内
	// 应用前用 caddy CLI（真 validate-only）校验最终渲染；二进制缺失/超时自动
	// 放行（事务内应用仍门控）。
	caddyService.EnableCLIValidation()
	caddyService.SetLastGoodPath(filepath.Join(cfg.DataDir, "last_good_caddy_config.json"))
	// R72 二十五次：数据类更新（xdb/CRS/CA 证书文件）后的重载必须强制——配置
	// JSON 不变时 Caddy 会跳过 provision（errSameConfig 短路），插件内存停留
	// 旧库而更新流程报成功。三个消费方（IP 库/CRS/CA 队列）全是数据更新入口。
	caddyReloader := func() error {
		return caddyService.GenerateAndApplyConfigForce()
	}
	services.InitCAQueueManager(caddyReloader, cfg.DataDir)
	services.InitCRSUpdateManager(caddyReloader)
	services.InitIP2Region()
	services.InitIP2RegionUpdateManager(caddyReloader)
	metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
	syncService := services.NewSyncService(db.DB, cfg, caddyService)
	lifecycle := newRuntimeLifecycle(syncService, func() certificateWorker {
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
	// SECLB23-P1-1(第 23 轮审计):审计日志目录必须在首次 ApplyConfigOnStartup
	// 前保证存在——coraza NewWAF 时 OpenFile 不建父目录,缺失=/load 拒收。
	// INFRA-71-5（第 71 轮）：告警改走 services.Logf("warn")——绕过日志
	// 级别门（ApplyLogLevel 已在上方装配）会让 warn 级过滤对它失效。
	if err := services.EnsureWafAuditDir(); err != nil {
		services.Logf("warn", "create waf audit dir failed: %v", err)
	}
	// WAF 文件目录按 data_dir 派生（容器 /app/data → /app/waf 恒等；本地开发
	// 落到数据目录同级）。须在首个渲染（ApplyConfigOnStartup）之前。
	services.ConfigureWafDirs(cfg.DataDir)
	// @ipListFast 名单投影目录（v2.3.x）：渲染期 fail-closed 依赖目录可写。
	if err := services.EnsureIPListDir(); err != nil {
		services.Logf("error", "初始化 IP 名单目录失败: %v", err)
	}
	// 系统配置载入（单一 oneshot 任务：规则库→证书→Caddy 渲染三段；完成于
	// 面板监听之前——载入完成前系统不可达（强于只读））
	// runConfigLoad 为共享执行体——启动与任务监控手动触发走同一函数
	// （2026-09-29 用户裁定：任务逻辑迁入任务后，手动执行与系统启动触发
	// 效果必须一致，含「载入」审计与全部前置物化步骤）。
	// L1-66-03：operator 透传——手动重载载入审计归因操作者，启动（空）归 system。
	runConfigLoad := func(operator string) error {
		services.SeedCRSRules()
		services.ReconcileCRSState()
		services.TaskLogf("startup:config-load", "libs", "规则库载入完成（CRS %s 对账）", services.CurrentCRSVersionForLog())
		// 归一 R50 前落库的安全策略枚举空串行（发射端零产出 + Update 拒修的
		// 遗留状态），有实际变更时主节点递增集群版本让从节点收敛。
		services.NormalizeLegacySecurityPolicyEnums(context.Background())
		services.MaterializeAllCertsFromDB()
		return h.ApplyConfigOnStartup(operator)
	}
	// B1（第 65 轮后裁定）：启动执行移入引擎 BootSync（下方 InitTaskEngine 尾部
	// 同步触发 startup:config-load——面板监听前完成不变量保持；失败语义同旧：
	// 仅记录不退出）。
	// F62-28:Caddy 重启监听——监督器触发后走与启动相同的 DB 渲染→应用流程
	// (修正 last_good 快照可能滞后于 DB 的窗口)。
	h.StartCaddyRestartWatcher()
	// 配置一致性看门狗：周期比对 DB 规则与 Caddy 运行配置，不一致时三通道告知
	// （系统日志/操作日志/前端横幅），恢复由用户手动重启完成。
	// M2 统一任务引擎：看门狗/安全事件摄取/运行日志清理三常驻族迁入
	// （单轮体+引擎节拍；原生自循环与 TaskRuntime 注册表退役）。
	services.SetConfigLoadRerun(runConfigLoad) // 启动 BootSync 与手动重载=同一执行体（含载入审计）
	// B 完全标准化：常驻服务真实生命周期挂钩（daemon Run start→阻塞→stop；
	// 幂等守卫吸收 lifecycle 直调与 daemon 挂钩的双调用）
	services.SetCertIssuanceLifecycleHooks(lifecycle.StartACME, lifecycle.StopACME)
	services.SetSyncLifecycleHooks(syncService.Start, syncService.Stop)
	// 自动备份执行器必须先于 InitTaskEngine：启用且存在补跑槽时，
	// 引擎首轮可能在毫秒内到期，不得在 nil executor 下记录成功。
	services.SetAutoBackupExecutor(func(trigger, operator string, engineRunID int64) error {
		_, err := h.RunAutoBackupOnce(trigger, operator, engineRunID)
		return err
	})
	// L01-01：威胁库依赖（reloader/投影回调/manager 单例）必须先于
	// InitTaskEngine 装配——引擎启动即按 due 槽调度 threat，manager nil 曾让
	// Run 落 success（威胁库永不更新且缺陷不可见）。与 auto-backup executor
	// 同型：任务体依赖的运行期钩子一律前置。
	services.SetThreatReloader(caddyReloader)
	// 投影热路径（2026-10-15 用户裁定：威胁库重载门退役）——名单内容变化的
	// 引用面收敛改走投影重写（零 /load，@ipListFast 匹配器与受信代理网段
	// tp.txt/lb_file ≤1s stat 热感知）；threatReloader 仅残留热路径未证实
	// 收敛时的 fail-safe 回退。
	services.SetThreatProjectionRefresher(func() (services.IPListProjectionOutcome, error) { return caddyService.RefreshIPListProjections() })
	services.InitThreatUpdateManager()
	services.InitTaskEngine(cfg.CaddyAdminURL, runtimeLogFile) // 前置设施——非任务
	// 引擎收尾统一交由下方 tail defer（StopTaskEngine 幂等）；此处不再重复
	// defer（INFRA-1 第 73 轮：双 defer 依赖幂等，收敛单点收尾）。

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
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		services.Logf("error", "failed to read cluster role: %v", err)
		isMaster = true
	}
	// F73-A：自动封禁名单变化后的收敛。投影热路径优先（2026-10-15 用户裁定）：
	// 资格门（被启用策略引用；受信代理引用面已随 tp.txt/lb_file 热路径化
	// 退役）命中 → RefreshIPListProjectionsInLock 零 /load 收敛（@ipListFast
	// 匹配器 ≤1s stat 热感知）；资格未命中/不可判定/未证实收敛 →
	// autobanReloader 全量重载回退（60s 节流暂存合并）。AU-1（第 74 轮）：
	// merge 读改写+收敛全程持 CaddyOpLock，两个注入必须为 InLock 变体（自取
	// 锁变体在临界区内重入=死锁）。
	services.SetAutobanReloader(func() error { return caddyService.GenerateAndApplyConfigForceInLock() })
	services.SetAutobanProjectionRefresher(func() (services.IPListProjectionOutcome, error) { return caddyService.RefreshIPListProjectionsInLock() })
	if isMaster {
		if err := services.GetCrawlerUpdateManager().Prime(); err != nil {
			services.Logf("error", "crawlerbot-update: 内置首版名单预载失败: %v", err)
		}
	}
	// 审计日志轮转由事件摄入循环驱动（先采集后轮转），此处无需独立启动器
	// 安全事件采集已由任务引擎接管（InitTaskEngine 注册 2s 循环）
	defer func() {
		// 审计 A5-S2：事件摄入与其余 worker 同生命周期——db.Close 前 cancel，
		// 否则退出窗口内每 2s 对已关闭 MetricsDB 刷 "database is closed" 告警。
		services.StopTaskEngine() // M2:引擎统一收尾(摄取/看门狗/清理)
		metricsService.Stop()
		<-metricsDone
		services.StopTimezoneRefresh()
		services.StopLogRotate()
		lifecycle.Shutdown()
	}()

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	// 版本单一事实源=config(APP_VERSION env/Dockerfile ARG 兜底)——此前打印
	// ldflags 变量 version(无注入链恒 "dev"),与 branding API 版本分叉
	// (v2.3.0 首发漏注入,记忆在案)。ldflags 变量保留给 go 直编场景。
	log.Printf("Starting lazy-balancer-v2 %s on %s", cfg.Version, addr)
	server := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	tlsCfg := services.LoadAdminTLSConfig()
	services.RecordRuntimeAdminTLS(tlsCfg)
	serverErrors := make(chan error, 1)
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(quit)
	if tlsCfg.Enabled {
		cert, err := tlsCfg.ResolveCertificate(cfg.DataDir)
		if err != nil {
			return fmt.Errorf("管理面板 HTTPS 启用失败: %w", err)
		}
		log.Printf("管理面板 HTTPS 监听 %s（证书来源：%s，HTTP 明文请求 301 跳转）", addr, tlsCfg.Mode)
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("HTTPS 监听失败: %w", err)
		}
		go func() { serverErrors <- server.ServeTLS(newHTTPRedirectMux(ln), "", "") }()
	} else {
		go func() { serverErrors <- server.ListenAndServe() }()
	}

	serverErr := waitForServerStop(server, serverStopSignals{quit: quit, restart: restart, serverErrors: serverErrors, caddyAdminURL: cfg.CaddyAdminURL})
	if serverErr != nil && !errors.Is(serverErr, http.ErrServerClosed) {
		return fmt.Errorf("serve HTTP: %w", serverErr)
	}
	return nil
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

type serverStopSignals struct {
	quit         chan os.Signal
	restart      <-chan struct{}
	serverErrors <-chan error
	// caddyAdminURL Caddy admin 端点（INFRA-U5，第 69 轮：退出前排水用）。
	caddyAdminURL string
}

func waitForServerStop(server *http.Server, signals serverStopSignals) error {
	select {
	case <-signals.quit:
	case <-signals.restart:
	case err := <-signals.serverErrors:
		return err
	}
	// S-4 + N-3：无论由 quit 还是 restart 触发，都在进入关停流程前统一停
	// 信号通道（先于 "Shutting down..." 与 ≤10s 的 HTTP Shutdown 窗口）。
	// 此前仅 quit 分支停通道：restart 分支的关停窗口内第二个信号会被通道
	// 缓冲，随后被 run() 返回后的 defer signal.Stop 冲刷丢弃，无法触发默认
	// 终止（用户第二次 Ctrl-C / SIGTERM 应能强制结束卡顿的关停）。
	// serverErrors 分支直接返回：服务已异常、进程随即退出，由 run() 的
	// defer signal.Stop 收尾。
	signal.Stop(signals.quit)

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		services.Logf("error", "HTTP server shutdown failed: %v", err)
		if closeErr := server.Close(); closeErr != nil {
			services.Logf("error", "HTTP server forced close failed: %v", closeErr)
		}
	}
	// INFRA-U5（第 69 轮）：进程退出前给 Caddy 排水窗口——此前 PID1 退出后
	// 容器 teardown 直接 SIGKILL 残存进程（含监督器与 Caddy），每次升级/重启
	// 硬断全部在途代理连接。POST /stop 让 Caddy 优雅关停；best-effort：
	// admin 不可达（已停/独立部署）静默略过。restart 路径同理（进程退出由
	// 容器编排重建，Caddy 排水后由新容器监督器重拉）。
	drainCaddy(signals.caddyAdminURL)
	return nil
}

// caddyPauseFilePath 与 handlers 包的 caddyPauseFile（internal/handlers/caddy.go）
// 及 docker-entrypoint.sh 的 CADDY_PAUSE_FILE 同值 "/tmp/lazy-balancer-caddy-paused"
// ——main 包不 import handlers 的未导出变量，自持常量并以注释互指；任一侧
// 改路径须三处同步（handlers 侧为测试注入缝用 var，本侧停机路径无注入需求用 const）。
const caddyPauseFilePath = "/tmp/lazy-balancer-caddy-paused"

// writeDrainPauseFile INFRA-A1（第 70 轮）：排水前建 pause 标记，让监督器把
// 本次优雅停机按「admin 停止」分支处理（docker-entrypoint.sh 见文件不重启、
// CRASHES 不 +1）——此前 drainCaddy 直接 POST /stop，监督器一律按崩溃重拉，
// 排水窗口内 1s 退避重绑 80/443，伪 Crash 噪音+排水语义被消解。
// 与 stopCaddy（handlers/caddy.go）刻意不同：仅当文件不存在时写（不覆盖
// stopCaddy 用户意图停机的在场标记）；写后即使排水请求失败也不回滚——本
// 函数只在整个进程退出路径上调用，而 stopCaddy 是长驻运行期操作，停失败
// 必须回滚让监督器继续看护。
// pause 生命周期=容器运行期。注意：docker stop/start、restart 复用同一容器
// 可写层，/tmp 并不清空（INFRA-A1-R1 事故：曾误假设「随容器重建清空」，导致
// 重启后监督器开机 standby、Caddy 永不拉起）——跨重启残留由监督器启动首行
// 清残兜底（docker-entrypoint.sh INFRA-A1-R1）；非容器部署下次 startCaddy
// 亦会删标记。此处粘滞因此安全。
func writeDrainPauseFile() {
	if _, err := os.Stat(caddyPauseFilePath); err == nil {
		return
	}
	_ = os.WriteFile(caddyPauseFilePath, nil, 0o644)
}

// drainCaddy best-effort 请求 Caddy admin /stop（2s 上限，错误只记日志）。
func drainCaddy(adminURL string) {
	if adminURL == "" {
		return
	}
	writeDrainPauseFile()
	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodPost, strings.TrimSuffix(adminURL, "/")+"/stop", nil)
	if err != nil {
		return
	}
	resp, err := client.Do(req)
	if err != nil {
		services.Logf("info", "Caddy 排水请求未达（可能已停止）: %v", err)
		return
	}
	_ = resp.Body.Close()
}

type tzLogWriter struct {
	w io.Writer
}

func (t *tzLogWriter) Write(p []byte) (int, error) {
	prefix := time.Now().In(services.CurrentLocation()).Format("2006/01/02 15:04:05 ")
	return t.w.Write(append([]byte(prefix), p...))
}
