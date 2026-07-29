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
	log.SetOutput(&tzLogWriter{w: logWriter})

	// Initialize database
	if err := db.Initialize(cfg.DataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	if runtimeLogFile != "" {
		services.StartRuntimeLogCleanup(runtimeLogFile)
	}

	if *initDB {
		log.Println("Database initialized successfully")
		return
	}

	var tz string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err == nil && tz != "" {
		if err := os.Setenv("TZ", tz); err != nil {
			log.Printf("Failed to set TZ environment: %v", err)
		} else if loc, err := services.ConfigureLocation(tz); err != nil {
			log.Printf("Failed to load timezone %s: %v", tz, err)
		} else {
			time.Local = loc
			log.Printf("Timezone set to %s", tz)
		}
	}

	// Initialize services
	caddyService := services.NewCaddyService(cfg.CaddyAdminURL)
	caddyReloader := func() error {
		return caddyService.ApplyConfig(services.GenerateCaddyConfig(cfg))
	}
	services.InitCAQueueManager(caddyReloader)
	metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
	syncService := services.NewSyncService(db.DB, cfg, caddyService)
	lifecycle := newRuntimeLifecycle(syncService, func() certificateWorker {
		return services.NewCertificateService()
	})
	clusterService := services.NewClusterService(db.DB, lifecycle)
	caProviderService := services.NewCAProviderService()

	h := handlers.NewHandlers(handlers.Dependencies{
		Config: cfg, CaddyService: caddyService, MetricsService: metricsService,
		SyncService: syncService, ClusterService: clusterService, CAProviderService: caProviderService,
	})

	// Materialize cert files from DB, then apply Caddy config on startup
	services.MaterializeAllCertsFromDB()
	if err := h.ApplyConfigOnStartup(); err != nil {
		log.Printf("Warning: Failed to apply Caddy config on startup: %v", err)
	}

	// Setup router
	router := middleware.SetupRouter(h, cfg)

	// Start services
	metricsDone := make(chan struct{})
	go func() {
		defer close(metricsDone)
		metricsService.Start()
	}()
	var isMaster bool
	if err := db.DB.QueryRow("SELECT is_master FROM global_config WHERE id=1").Scan(&isMaster); err != nil {
		log.Printf("Warning: failed to read cluster role: %v", err)
		isMaster = true
	}
	if isMaster {
		lifecycle.StartACME()
	} else {
		lifecycle.StopACME()
		lifecycle.StartSync()
	}

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Starting lazy-balancer-v2 %s on %s", version, addr)
	server := &http.Server{
		Addr:    addr,
		Handler: router,
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
			log.Fatalf("管理面板 HTTPS 启用失败: %v", err)
		}
		log.Printf("管理面板 HTTPS 监听 %s（证书来源：%s，HTTP 明文请求 301 跳转）", addr, tlsCfg.Mode)
		server.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		server.ReadHeaderTimeout = 10 * time.Second
		server.ReadTimeout = 30 * time.Second
		server.WriteTimeout = 60 * time.Second
		server.IdleTimeout = 120 * time.Second
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS 监听失败: %v", err)
		}
		go func() { serverErrors <- server.ServeTLS(newHTTPRedirectMux(ln), "", "") }()
	} else {
		go func() { serverErrors <- server.ListenAndServe() }()
	}

	select {
	case <-quit:
		log.Println("Shutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP server shutdown failed: %v", err)
			if closeErr := server.Close(); closeErr != nil {
				log.Printf("HTTP server forced close failed: %v", closeErr)
			}
		}
		cancel()
	case err := <-serverErrors:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("HTTP server stopped unexpectedly: %v", err)
		}
	}
	metricsService.Stop()
	<-metricsDone
	services.StopAuditCleanup()
	lifecycle.Shutdown()
}

type tzLogWriter struct {
	w io.Writer
}

func (t *tzLogWriter) Write(p []byte) (int, error) {
	prefix := time.Now().In(services.CurrentLocation()).Format("2006/01/02 15:04:05 ")
	return t.w.Write(append([]byte(prefix), p...))
}
