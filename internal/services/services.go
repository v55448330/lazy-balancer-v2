package services

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// MetricsService collects and stores metrics from Caddy
type MetricsService struct {
	metricsURL         string
	interval           int
	client             *http.Client
	stopCh             chan struct{}
	overview           models.MetricsOverview
	certificateService *CertificateService
	mu                 sync.RWMutex
}

func NewMetricsService(metricsURL string, interval int) *MetricsService {
	return &MetricsService{
		metricsURL: metricsURL,
		interval:   interval,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
		stopCh:   make(chan struct{}),
		overview: models.MetricsOverview{},
	}
}

func (m *MetricsService) Start() {
	ticker := time.NewTicker(time.Duration(m.interval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.collect()
		case <-m.stopCh:
			return
		}
	}
}

func (m *MetricsService) Stop() {
	close(m.stopCh)
}

func (m *MetricsService) SetCertificateService(s *CertificateService) {
	m.certificateService = s
}

func (m *MetricsService) collect() {
	resp, err := m.client.Get(m.metricsURL)
	if err != nil {
		log.Printf("Failed to collect metrics: %v", err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	metrics := m.parsePrometheusMetrics(string(body))
	m.storeMetrics(metrics)
	m.updateOverview(metrics)

	// Check TLS certificate expiration
	m.checkTLSCertificateExpiration()

	// Check ACME certificate expiration
	if m.certificateService != nil {
		expired := m.certificateService.CheckExpiration()
		for _, job := range expired {
			log.Printf("Certificate %s expires at %v", job.Domain, job.ExpiresAt.Time)
		}
	}
}

type parsedMetrics struct {
	requestsTotal int64
	requests2xx   int64
	requests3xx   int64
	requests4xx   int64
	requests5xx   int64
	bytesIn       int64
	bytesOut      int64
	latencyP50    int
	latencyP95    int
	latencyP99    int
}

func (m *MetricsService) parsePrometheusMetrics(text string) parsedMetrics {
	metrics := parsedMetrics{}

	// Parse request counters
	// caddy_http_requests_total{code="200",...}
	re := regexp.MustCompile(`caddy_http_requests_total\{[^}]*code="(\d+)".*?\} (\d+)`)
	matches := re.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 3 {
			code, _ := strconv.ParseInt(match[1], 10, 64)
			value, _ := strconv.ParseInt(match[2], 10, 64)
			metrics.requestsTotal += value
			if code >= 200 && code < 300 {
				metrics.requests2xx += value
			} else if code >= 300 && code < 400 {
				metrics.requests3xx += value
			} else if code >= 400 && code < 500 {
				metrics.requests4xx += value
			} else if code >= 500 {
				metrics.requests5xx += value
			}
		}
	}

	// Parse response size
	// caddy_http_response_size_bytes_sum{...}
	reSize := regexp.MustCompile(`caddy_http_response_size_bytes_sum.*?\} (\d+\.?\d*)`)
	matches = reSize.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, _ := strconv.ParseInt(match[1], 10, 64)
			metrics.bytesOut += value
		}
	}

	// Parse request size
	reReqSize := regexp.MustCompile(`caddy_http_request_size_bytes_sum.*?\} (\d+\.?\d*)`)
	matches = reReqSize.FindAllStringSubmatch(text, -1)
	for _, match := range matches {
		if len(match) >= 2 {
			value, _ := strconv.ParseInt(match[1], 10, 64)
			metrics.bytesIn += value
		}
	}

	// Parse latency buckets (simplified - use last bucket as rough estimate)
	// This is a simplified version
	metrics.latencyP50 = 10 // Default ms
	metrics.latencyP95 = 50
	metrics.latencyP99 = 100

	return metrics
}

func (m *MetricsService) storeMetrics(metrics parsedMetrics) {
	// Store global metrics
	_, err := db.DB.Exec(`
		INSERT INTO metrics_history 
		(rule_id, timestamp, requests_total, requests_2xx, requests_3xx, 
		 requests_4xx, requests_5xx, bytes_in, bytes_out, 
		 latency_p50, latency_p95, latency_p99)
		VALUES (NULL, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
		metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
		metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)

	if err != nil {
		log.Printf("Failed to store metrics: %v, values: %d,%d,%d,%d,%d,%d,%d,%d,%d,%d",
			err, metrics.requestsTotal, metrics.requests2xx, metrics.requests3xx,
			metrics.requests4xx, metrics.requests5xx, metrics.bytesIn, metrics.bytesOut,
			metrics.latencyP50, metrics.latencyP95, metrics.latencyP99)
	}
}

func (m *MetricsService) updateOverview(metrics parsedMetrics) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Get active rules count
	var activeRules, totalRules int
	db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE enabled = 1").Scan(&activeRules)
	db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules").Scan(&totalRules)

	// Get online nodes count
	var onlineNodes int
	db.DB.QueryRow("SELECT COUNT(*) FROM nodes WHERE status = 'online'").Scan(&onlineNodes)

	m.overview = models.MetricsOverview{
		TotalRequests:  metrics.requestsTotal,
		RequestsPerSec: float64(metrics.requestsTotal) / 3600, // Approximate
		BytesIn:        metrics.bytesIn,
		BytesOut:       metrics.bytesOut,
		Status2xx:      metrics.requests2xx,
		Status3xx:      metrics.requests3xx,
		Status4xx:      metrics.requests4xx,
		Status5xx:      metrics.requests5xx,
		LatencyP50:     metrics.latencyP50,
		LatencyP95:     metrics.latencyP95,
		LatencyP99:     metrics.latencyP99,
		ActiveRules:    activeRules,
		TotalRules:     totalRules,
		OnlineNodes:    onlineNodes,
	}
}

func (m *MetricsService) GetOverview() models.MetricsOverview {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.overview
}

// NodeService manages node registration and heartbeat
type NodeService struct {
	mode     string
	masterID int
	mu       sync.RWMutex
}

func NewNodeService() *NodeService {
	return &NodeService{
		mode: "master",
	}
}

func (n *NodeService) SetMode(mode string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.mode = mode
}

func (n *NodeService) GetMode() string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.mode
}

func (n *NodeService) StartHeartbeat(cfg *config.Config) {
	if cfg.NodeMode == "slave" && cfg.MasterURL != "" {
		// Start heartbeat to master
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for range ticker.C {
			n.sendHeartbeat(cfg)
		}
	}
}

func (n *NodeService) sendHeartbeat(cfg *config.Config) {
	// Get local node ID
	var nodeID int
	err := db.DB.QueryRow("SELECT id FROM nodes WHERE ip_address = ? AND mode = 'slave'",
		getOutboundIP()).Scan(&nodeID)

	if err != nil {
		return
	}

	resp, err := http.Post(fmt.Sprintf("%s/api/nodes/%d/heartbeat", cfg.MasterURL, nodeID),
		"application/json", nil)
	if err != nil {
		log.Printf("Failed to send heartbeat: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (n *NodeService) Stop() {
	// Cleanup if needed
}

func getOutboundIP() string {
	// Simple approach - in production, use more robust method
	resp, err := http.Get("https://api.ipify.org?format=text")
	if err != nil {
		return "127.0.0.1"
	}
	defer resp.Body.Close()
	ip, _ := io.ReadAll(resp.Body)
	return strings.TrimSpace(string(ip))
}

// SyncService handles configuration synchronization between master and slave
type SyncService struct {
	masterURL  string
	syncConfig struct {
		enabled  bool
		interval int
		scope    string
	}
	client *http.Client
	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewSyncService() *SyncService {
	return &SyncService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		stopCh: make(chan struct{}),
	}
}

func (s *SyncService) Start() {
	// Get sync config from database
	var masterURL string
	var syncEnabled bool
	var syncInterval int

	db.DB.QueryRow("SELECT master_url, is_master, sync_interval FROM global_config WHERE id = 1").
		Scan(&masterURL, &syncEnabled, &syncInterval)

	// If this is a slave node and master URL is set, start sync
	if !syncEnabled && masterURL != "" {
		s.mu.Lock()
		s.masterURL = masterURL
		s.syncConfig.enabled = true
		s.syncConfig.interval = syncInterval
		s.syncConfig.scope = "all"
		s.mu.Unlock()

		ticker := time.NewTicker(time.Duration(syncInterval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				s.SyncFromMaster()
			case <-s.stopCh:
				return
			}
		}
	}
}

func (s *SyncService) Stop() {
	close(s.stopCh)
}

func (s *SyncService) SyncFromMaster() error {
	s.mu.RLock()
	masterURL := s.masterURL
	scope := s.syncConfig.scope
	s.mu.RUnlock()

	if masterURL == "" {
		return fmt.Errorf("no master URL configured")
	}

	// Get config from master
	resp, err := s.client.Get(fmt.Sprintf("%s/api/sync/config?scope=%s", masterURL, scope))
	if err != nil {
		return fmt.Errorf("failed to fetch config: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 304 {
		log.Println("No config changes from master")
		return nil
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("master returned error: %d", resp.StatusCode)
	}

	var syncData models.SyncData
	if err := json.NewDecoder(resp.Body).Decode(&syncData); err != nil {
		return fmt.Errorf("failed to decode sync data: %w", err)
	}

	// Apply sync data to local database
	if err := s.applySyncData(syncData); err != nil {
		return fmt.Errorf("failed to apply sync data: %w", err)
	}

	// Update last sync time
	db.DB.Exec("UPDATE global_config SET last_sync = datetime('now') WHERE id = 1")

	log.Println("Sync completed successfully")
	return nil
}

func (s *SyncService) applySyncData(data models.SyncData) error {
	// Begin transaction
	tx, err := db.DB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Clear and re-insert rules
	if len(data.Rules) > 0 {
		tx.Exec("DELETE FROM lb_rules")
		tx.Exec("DELETE FROM upstreams")

		for _, rule := range data.Rules {
			tx.Exec(`
				INSERT INTO lb_rules (id, name, protocol, domain, listen_port, strategy, 
					dynamic_dns, health_check_path, health_check_interval, health_check_timeout,
					health_check_unhealthy_threshold, health_check_healthy_threshold,
					enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email, tls_http_redirect, 
					enabled)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, 			rule.ID, rule.Name, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
				rule.DynamicDNS, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
				rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
				rule.EnableTLS, rule.TLSCert, rule.TLSKey, rule.TLSAutoCert, rule.TLSEmail,
				rule.TLSHTTPRedirect, rule.Enabled)

			for _, u := range rule.Upstreams {
				tx.Exec(`
					INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				`, rule.ID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled)
			}
		}
	}

	// Update global config
	tx.Exec(`
		UPDATE global_config SET 
			dns_provider = ?,
			log_level = ?,
			access_log_enabled = ?,
			updated_at = datetime('now')
		WHERE id = 1
	`, data.Config.DNSProvider, data.Config.LogLevel, data.Config.AccessLogEnabled)

	// Record config version
	tx.Exec(`
		INSERT INTO config_versions (version, change_type, description)
		VALUES (?, 'sync', 'Synced from master')
	`, data.Version)

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}

// checkTLSCertificateExpiration checks all manual TLS certificates for expiration
func (m *MetricsService) checkTLSCertificateExpiration() {
	rows, err := db.DB.Query(`
		SELECT caddy_id, name, domain, tls_cert 
		FROM lb_rules 
		WHERE enable_tls = 1 AND tls_auto_cert = 0 AND tls_cert != ''
	`)
	if err != nil {
		log.Printf("Failed to query TLS certificates for expiration check: %v", err)
		return
	}
	defer rows.Close()

	now := time.Now()
	var expiredCount, expiringSoonCount int

	for rows.Next() {
		var caddyID, name, domain, certPEM string
		if err := rows.Scan(&caddyID, &name, &domain, &certPEM); err != nil {
			continue
		}

		// Parse certificate
		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			log.Printf("Warning: Invalid certificate PEM for rule %s (%s)", caddyID, name)
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Warning: Failed to parse certificate for rule %s (%s): %v", caddyID, name, err)
			continue
		}

		// Check expiration
		daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

		if now.After(cert.NotAfter) {
			log.Printf("⚠️ CRITICAL: TLS certificate expired for rule '%s' (domain: %s, caddy_id: %s). Expired on %s", 
				name, domain, caddyID, cert.NotAfter.Format("2006-01-02"))
			expiredCount++
		} else if daysUntilExpiry <= 30 {
			log.Printf("⚠️ WARNING: TLS certificate expiring soon for rule '%s' (domain: %s, caddy_id: %s). Expires in %d days (%s)", 
				name, domain, caddyID, daysUntilExpiry, cert.NotAfter.Format("2006-01-02"))
			expiringSoonCount++
		}
	}

	if expiredCount > 0 || expiringSoonCount > 0 {
		log.Printf("TLS Certificate Check: %d expired, %d expiring within 30 days", expiredCount, expiringSoonCount)
	}
}
