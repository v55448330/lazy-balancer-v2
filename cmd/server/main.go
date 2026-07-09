package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

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

	// Initialize database
	if err := db.Initialize(cfg.DataDir); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	if *initDB {
		log.Println("Database initialized successfully")
		os.Exit(0)
	}

	// Initialize services
	caddyService := services.NewCaddyService(cfg.CaddyAdminURL)
	caddyReloader := func() error {
		return caddyService.ApplyConfig(services.GenerateCaddyConfig(cfg))
	}
	services.InitCAQueueManager(caddyReloader)
	certService := services.NewCertificateService(cfg.CaddyAdminURL, caddyReloader)
	metricsService := services.NewMetricsService(cfg.CaddyMetricsURL, cfg.MetricsInterval)
	nodeService := services.NewNodeService()
	syncService := services.NewSyncService()
	caProviderService := services.NewCAProviderService()

	// Initialize handlers
	h := handlers.NewHandlers(cfg, caddyService, metricsService, nodeService, syncService, certService, caProviderService)

	// Materialize cert files from DB, then apply Caddy config on startup
	services.MaterializeAllCertsFromDB()
	if err := h.ApplyConfigOnStartup(); err != nil {
		log.Printf("Warning: Failed to apply Caddy config on startup: %v", err)
	}

	// Setup router
	router := middleware.SetupRouter(h, cfg)

	// Start services
	go certService.Start()
	go metricsService.Start()
	go nodeService.StartHeartbeat(cfg)
	go syncService.Start()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-quit
		log.Println("Shutting down...")
		certService.Stop()
		metricsService.Stop()
		nodeService.Stop()
		syncService.Stop()
		os.Exit(0)
	}()

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("Starting lazy-balancer-v2 %s on %s", version, addr)
	if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
