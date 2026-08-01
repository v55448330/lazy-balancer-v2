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
	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		if w, err := services.NewRotatingFileWriter(logFile); err == nil {
			logWriter = io.MultiWriter(os.Stdout, w)
			defer w.Close()
			runtimeLogFile = logFile
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
	if err := handlers.SeedDefaultBranding(cfg.DataDir); err != nil {
		services.Logf("warn", "failed to seed default branding: %v", err)
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
	caddyReloader := func() error {
		return caddyService.GenerateAndApplyConfig()
	}
	services.InitCAQueueManager(caddyReloader, cfg.DataDir)
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

	// Materialize cert files from DB, then apply Caddy config on startup
	services.MaterializeAllCertsFromDB()
	if err := h.ApplyConfigOnStartup(); err != nil {
		services.Logf("error", "failed to apply Caddy config on startup: %v", err)
	}

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
	if isMaster {
		lifecycle.StartACME()
	} else {
		lifecycle.StopACME()
		lifecycle.StartSync()
	}
	defer func() {
		metricsService.Stop()
		<-metricsDone
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
	quit         <-chan os.Signal
	restart      <-chan struct{}
	serverErrors <-chan error
}

func waitForServerStop(server *http.Server, signals serverStopSignals) error {
	select {
	case <-signals.quit:
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
