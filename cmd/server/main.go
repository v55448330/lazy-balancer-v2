package main

import (
	"flag"
	"fmt"
	"io"
	"log"
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
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	// Parse flags
	configPath := flag.String("config", "", "Config file path")
	initDB := flag.Bool("init", false, "Initialize database")
	flag.Parse()

	// Load configuration
	cfg := config.Load(*configPath)

	if logFile := os.Getenv("LOG_FILE"); logFile != "" {
		if file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644); err == nil {
			log.SetOutput(io.MultiWriter(os.Stdout, file))
			defer file.Close()
		}
	}

	// Initialize database
	if err := db.Initialize(cfg.DataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	if *initDB {
		log.Println("Database initialized successfully")
		os.Exit(0)
	}

	var tz string
	if err := db.DB.QueryRow("SELECT COALESCE(timezone,'Asia/Shanghai') FROM global_config WHERE id=1").Scan(&tz); err == nil && tz != "" {
		os.Setenv("TZ", tz)
		time.LoadLocation(tz)
		log.Printf("Timezone set to %s", tz)
	}

	// Initialize services
	caddyService := services.NewCaddyService(cfg.CaddyAdminURL)
	caddyReloader := func() error {
		return caddyService.ApplyConfig(services.GenerateCaddyConfig(cfg))
	}
	services.InitCAQueueManager(caddyReloader)
	metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
	syncService := services.NewSyncService(db.DB, cfg, caddyService)
	lifecycle := services.NewRuntimeLifecycle(syncService, func() *services.CertificateService {
		return services.NewCertificateService(cfg.CaddyAdminURL, caddyReloader)
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
	go metricsService.Start()
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

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down...")
		metricsService.Stop()
		lifecycle.Shutdown()
		os.Exit(0)
	}()

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Starting lazy-balancer-v2 %s on %s", version, addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
