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
	"syscall"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/handlers"
	"lazy-balancer-v2/internal/middleware"

	"lazy-balancer-v2/internal/services"
)

var (
	version = "dev"
)

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

	log.SetFlags(0)
	var logWriter io.Writer = os.Stdout
	var runtimeLogFile string
	if cfg.LogFileEnabled {
		if w, err := services.NewRotatingFileWriter(cfg.LogFile); err == nil {
			logWriter = io.MultiWriter(os.Stdout, w)
			defer w.Close()
			runtimeLogFile = cfg.LogFile
		} else {
			// S-3：显式配置了 LOG_FILE 但打开失败必须可见——静默回落仅 stdout 会让
			// 「配置了日志文件却是空的」无从排查。
			log.Printf("log file %s could not be opened, falling back to stdout only: %v", cfg.LogFile, err)
		}
	}
	log.SetOutput(services.NewApplicationLogWriter(&tzLogWriter{w: logWriter}))

	// Initialize database
	if err := db.Initialize(cfg.DataDir); err != nil {
		return fmt.Errorf("initialize database: %w", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			services.Logf("error", "close databases during shutdown: %v", err)
		}
	}()
	services.ApplyLogLevel()
	if err := handlers.SeedBrandingTemplate(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to seed branding template: %v", err)
	}
	if _, err := handlers.SeedDefaultBlockPage(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to seed default block page: %v", err)
	}
	if runtimeLogFile != "" {
		services.StartRuntimeLogCleanup(runtimeLogFile)
	}

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
	clusterService := services.NewClusterService(db.DB, lifecycle)
	caProviderService := services.NewCAProviderService(cfg.DataDir)

	h := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddyService, MetricsService: metricsService,
		SyncService: syncService, ClusterService: clusterService, CAProviderService: caProviderService,
	})

	// Seed the CRS rules tree into a fresh /app/waf bind mount (a persisted
	// snapshot with user-updated rules wins over the pristine image copy),
	// then materialize cert files from DB, then apply Caddy config on startup
	services.SeedCRSRules()
	services.ReconcileCRSState()
	// 归一 R50 前落库的安全策略枚举空串行（发射端零产出 + Update 拒修的
	// 遗留状态），有实际变更时主节点递增集群版本让从节点收敛。
	services.NormalizeLegacySecurityPolicyEnums(context.Background())
	services.MaterializeAllCertsFromDB()
	if err := h.ApplyConfigOnStartup(); err != nil {
		services.Logf("error", "failed to apply Caddy config on startup: %v", err)
	}
	// 配置一致性看门狗：周期比对 DB 规则与 Caddy 运行配置，不一致时三通道告知
	// （系统日志/操作日志/前端横幅），恢复由用户手动重启完成。
	services.StartConfigWatchdog(cfg.CaddyAdminURL)

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
	crsManager := services.GetCRSUpdateManager()
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		services.Logf("error", "failed to read cluster role: %v", err)
		isMaster = true
	}
	crsManager.SetMasterRole(isMaster)
	if ip2RegionManager := services.GetIP2RegionUpdateManager(); ip2RegionManager != nil {
		ip2RegionManager.SetMasterRole(isMaster)
	}
	// 事件保留清理针对本节点本地表，与集群角色无关（从节点也摄入事件）
	services.StartSecurityEventsRetention(context.Background())
	// 审计日志轮转由事件摄入循环驱动（先采集后轮转），此处无需独立启动器
	go services.StartSecurityEventsIngestion(context.Background())
	if isMaster {
		lifecycle.StartACME()
	} else {
		lifecycle.StopACME()
		lifecycle.StartSync()
	}
	defer func() {
		metricsService.Stop()
		<-metricsDone
		crsManager.StopScheduler()
		if ip2RegionManager := services.GetIP2RegionUpdateManager(); ip2RegionManager != nil {
			ip2RegionManager.StopScheduler()
		}
		services.StopConfigWatchdog()
		services.StopSecurityEventsRetention()
		services.StopAuditCleanup()
		services.StopTimezoneRefresh()
		services.StopLogRotate()
		services.StopRuntimeLogCleanup()
		lifecycle.Shutdown()
	}()

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Starting lazy-balancer-v2 %s on %s", version, addr)
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

	serverErr := waitForServerStop(server, serverStopSignals{quit: quit, restart: restart, serverErrors: serverErrors})
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
}

func waitForServerStop(server *http.Server, signals serverStopSignals) error {
	select {
	case <-signals.quit:
		// S-4：消费到首个关停信号后立即停信号通道（先于 server.Shutdown）。
		// 此前 signal.Stop 延迟到 run() 返回后的 defer 才执行，关停窗口内
		// （Shutdown 最多 10s + 服务停止）到达的第二个信号会被通道缓冲吞掉、
		// 随后被 Stop 丢弃，无法触发默认终止。
		signal.Stop(signals.quit)
	case <-signals.restart:
	case err := <-signals.serverErrors:
		return err
	}

	log.Println("Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		services.Logf("error", "HTTP server shutdown failed: %v", err)
		if closeErr := server.Close(); closeErr != nil {
			services.Logf("error", "HTTP server forced close failed: %v", closeErr)
		}
	}
	return nil
}

type tzLogWriter struct {
	w io.Writer
}

func (t *tzLogWriter) Write(p []byte) (int, error) {
	prefix := time.Now().In(services.CurrentLocation()).Format("2006/01/02 15:04:05 ")
	return t.w.Write(append([]byte(prefix), p...))
}
