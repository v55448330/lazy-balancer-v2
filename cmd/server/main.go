package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
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

	tlsCfg := services.LoadAdminTLSConfig()
	services.RecordRuntimeAdminTLS(tlsCfg)
	if tlsCfg.Enabled {
		cert, err := tlsCfg.ResolveCertificate(cfg.DataDir)
		if err != nil {
			log.Fatalf("管理面板 HTTPS 启用失败: %v", err)
		}
		log.Printf("管理面板 HTTPS 监听 %s（证书来源：%s，HTTP 明文请求 301 跳转）", addr, tlsCfg.Mode)
		tlsServer := &http.Server{
			Addr:              addr,
			Handler:           router,
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       30 * time.Second,
			WriteTimeout:      60 * time.Second,
			IdleTimeout:       120 * time.Second,
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
			},
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			log.Fatalf("HTTPS 监听失败: %v", err)
		}
		if err := tlsServer.ServeTLS(newHTTPRedirectMux(ln), "", ""); err != nil {
			log.Fatalf("HTTPS 服务启动失败: %v", err)
		}
	} else if err := router.Run(addr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

type tzLogWriter struct {
	w io.Writer
}

func (t *tzLogWriter) Write(p []byte) (int, error) {
	prefix := time.Now().In(services.CurrentLocation()).Format("2006/01/02 15:04:05 ")
	return t.w.Write(append([]byte(prefix), p...))
}

// prefixConn replays the bytes Peek consumed so the TLS handshake is intact.
type prefixConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// httpRedirectMux sniffs the first byte of each connection: TLS handshakes
// (0x16) go to the HTTPS server, plain HTTP gets a 301 to the HTTPS URL. It
// only activates when admin TLS is enabled, so misdirected plain-HTTP clients
// are redirected instead of producing TLS handshake errors.
type httpRedirectMux struct {
	net.Listener
}

func newHTTPRedirectMux(ln net.Listener) *httpRedirectMux {
	return &httpRedirectMux{Listener: ln}
}

func (m *httpRedirectMux) Accept() (net.Conn, error) {
	for {
		c, err := m.Listener.Accept()
		if err != nil {
			return nil, err
		}
		// The sniff must be time-bounded: a silent client that never sends a
		// byte would otherwise stall the entire accept loop.
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		br := bufio.NewReader(c)
		b, err := br.Peek(1)
		if err != nil {
			c.Close()
			continue
		}
		_ = c.SetReadDeadline(time.Time{})
		if b[0] == 0x16 {
			return &prefixConn{Conn: c, r: br}, nil
		}
		redirectHTTP(br, c)
	}
}

func redirectHTTP(br *bufio.Reader, c net.Conn) {
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
	head, _ := br.ReadString('\n')
	host := ""
	var location string
	parts := strings.Fields(head)
	if len(parts) >= 2 {
		location = parts[1]
	}
	for {
		line, err := br.ReadString('\n')
		if err != nil || line == "\r\n" || line == "\n" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host = strings.TrimSpace(line[len("host:"):])
		}
	}
	if host == "" {
		host = c.LocalAddr().String()
	}
	resp := fmt.Sprintf("HTTP/1.1 301 Moved Permanently\r\nContent-Length: 0\r\nConnection: close\r\nLocation: https://%s%s\r\n\r\n", host, location)
	_, _ = c.Write([]byte(resp))
}
