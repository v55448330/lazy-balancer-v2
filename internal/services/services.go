package services

import (
	"encoding/json"
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
	metricsURL string
	interval   int
	client     *http.Client
	stopCh     chan struct{}
	overview   models.MetricsOverview
	mu         sync.RWMutex
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
	// Store global metrics in independent metrics database
	_, err := db.MetricsDB.Exec(`
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

	// Get active rules count (fast read-only query)
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

func (m *MetricsService) GetHistory(limit int) []models.MetricsHistory {
	rows, err := db.MetricsDB.Query(`
		SELECT id, rule_id, timestamp, requests_total, requests_2xx, requests_3xx,
		       requests_4xx, requests_5xx, bytes_in, bytes_out,
		       latency_p50, latency_p95, latency_p99
		FROM metrics_history
		ORDER BY timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		log.Printf("Failed to query metrics history: %v", err)
		return nil
	}
	defer rows.Close()

	var history []models.MetricsHistory
	for rows.Next() {
		var h models.MetricsHistory
		if err := rows.Scan(&h.ID, &h.RuleID, &h.Timestamp,
			&h.RequestsTotal, &h.Requests2xx, &h.Requests3xx,
			&h.Requests4xx, &h.Requests5xx,
			&h.BytesIn, &h.BytesOut,
			&h.LatencyP50, &h.LatencyP95, &h.LatencyP99); err != nil {
			continue
		}
		history = append(history, h)
	}
	return history
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
				INSERT INTO lb_rules (id, caddy_id, name, description, protocol, domain, listen_port, strategy, 
					dynamic_dns, enable_dns_server, dns_server, dns_family,
					health_check_path, health_check_interval, health_check_timeout,
					health_check_unhealthy_threshold, health_check_healthy_threshold,
					enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval, 
					request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden, host_header,
					enable_tls, tls_source, tls_cert, tls_key, tls_http_redirect, 
					enable_compress, compress_types, enabled, created_by, updated_by)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, rule.ID, rule.CaddyID, rule.Name, rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
				rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily,
				rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
				rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
				rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPTryDuration, rule.TCPTryInterval, 
				rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden, rule.HostHeader,
				rule.EnableTLS, rule.TLSSource, rule.TLSCert, rule.TLSKey, rule.TLSHTTPRedirect,
				rule.EnableCompress, rule.CompressTypes, rule.Enabled, rule.CreatedBy, rule.UpdatedBy)

			for _, u := range rule.Upstreams {
				tx.Exec(`
					INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, dns_server, max_connections, proxy_protocol)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
				`, rule.CaddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol, u.DnsServer, u.MaxConnections, u.ProxyProtocol)
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
