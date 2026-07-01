package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"lazy-balancer-v2/internal/config"
	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

type Handlers struct {
	cfg                *config.Config
	caddyService       *services.CaddyService
	metricsService     *services.MetricsService
	nodeService        *services.NodeService
	syncService        *services.SyncService
	certificateService *services.CertificateService
	caProviderService  *services.CAProviderService
}

func NewHandlers(cfg *config.Config, caddy *services.CaddyService, metrics *services.MetricsService, node *services.NodeService, sync *services.SyncService, cert *services.CertificateService, ca *services.CAProviderService) *Handlers {
	h := &Handlers{
		cfg:                cfg,
		caddyService:       caddy,
		metricsService:     metrics,
		nodeService:        node,
		syncService:        sync,
		certificateService: cert,
		caProviderService:  ca,
	}

	// Initialize default admin user
	h.initDefaultAdmin()

	// Initialize default config
	h.initDefaultConfig()

	return h
}


func (h *Handlers) initDefaultAdmin() {
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM users WHERE username = ?", h.cfg.InitialAdminUser).Scan(&count)

	if count == 0 {
		hash, _ := bcrypt.GenerateFromPassword([]byte(h.cfg.InitialAdminPassword), bcrypt.DefaultCost)
		db.DB.Exec("INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
			h.cfg.InitialAdminUser, string(hash))
		log.Printf("Created default admin user: %s", h.cfg.InitialAdminUser)
	}
}


func (h *Handlers) initDefaultConfig() {
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM global_config WHERE id = 1").Scan(&count)

	if count == 0 {
		defaultConfig, _ := json.Marshal(map[string]interface{}{})
		db.DB.Exec("INSERT INTO global_config (id, caddy_config, dns_provider, is_master) VALUES (1, ?, 'dnspod', 1)",
			string(defaultConfig))
	}
}


func (h *Handlers) applyCaddyConfig() {
	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)
	}
}


func (h *Handlers) applyCaddyConfigWithRollback() error {
	// Backup current Caddy config before applying
	if err := h.caddyService.BackupConfig(); err != nil {
		log.Printf("Warning: Failed to backup Caddy config: %v", err)
	}

	// Generate Caddy config from DB
	config := services.GenerateCaddyConfig(h.cfg)

	configJSON, _ := json.Marshal(config)
	log.Printf("Generated Caddy config: %s", string(configJSON))

	// Push to Caddy
	if err := h.caddyService.ApplyConfig(config); err != nil {
		log.Printf("Failed to apply Caddy config: %v", err)

		// Attempt rollback
		if rollbackErr := h.caddyService.Rollback(); rollbackErr != nil {
			log.Printf("CRITICAL: Failed to rollback Caddy config: %v", rollbackErr)
			return fmt.Errorf("config apply failed and rollback also failed: %v (rollback error: %v)", err, rollbackErr)
		}

		return fmt.Errorf("config apply failed, rolled back to previous config: %v", err)
	}

	// Clear backup after successful apply
	h.caddyService.ClearBackup()
	return nil
}


func (h *Handlers) validateCaddyConfigBeforeSave(req interface{}, uniqueID string, serverName string) error {
	type requestUpstream struct {
		Host       string
		Port       int
		Weight     int
		Domain     string
		DynamicDNS bool
		Enabled    bool
		Protocol   string
	}

	type requestData struct {
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSSource                     string
		ACMEConfigID                  int
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		Upstreams                     []requestUpstream
	}

	var data requestData
	var upstreams []requestUpstream

	switch r := req.(type) {
	case models.CreateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
			})
		}
		data.Upstreams = upstreams
	case models.UpdateRuleRequest:
		data.Protocol = r.Protocol
		data.Domain = r.Domain
		data.ListenPort = r.ListenPort
		data.Strategy = r.Strategy
		data.DynamicDNS = r.DynamicDNS
		data.DnsServer = r.DnsServer
		data.DnsFamily = r.DnsFamily
		data.HealthCheckPath = r.HealthCheckPath
		data.HealthCheckInterval = r.HealthCheckInterval
		data.HealthCheckTimeout = r.HealthCheckTimeout
		data.HealthCheckUnhealthyThreshold = r.HealthCheckUnhealthyThreshold
		data.HealthCheckHealthyThreshold = r.HealthCheckHealthyThreshold
		data.EnableTLS = r.EnableTLS
		data.TLSSource = r.TLSSource
		data.ACMEConfigID = r.ACMEConfigID
		data.TLSCert = r.TLSCert
		data.TLSKey = r.TLSKey
		data.TLSHTTPRedirect = r.TLSHTTPRedirect
		data.EnableCompress = r.EnableCompress
		data.CompressTypes = r.CompressTypes
		data.EnableActiveHealthCheck = r.EnableActiveHealthCheck
		data.HostHeader = r.HostHeader
		for _, u := range r.Upstreams {
			upstreams = append(upstreams, requestUpstream{
				Host: u.Host, Port: u.Port, Weight: u.Weight, Domain: u.Domain,
				DynamicDNS: u.DynamicDNS, Enabled: u.Enabled, Protocol: u.Protocol,
			})
		}
		data.Upstreams = upstreams
	default:
		return nil
	}

	if data.Strategy == "" {
		data.Strategy = "round_robin"
	}
	if data.HealthCheckInterval == 0 {
		data.HealthCheckInterval = 10
	}
	if data.HealthCheckTimeout == 0 {
		data.HealthCheckTimeout = 5
	}
	if data.HealthCheckUnhealthyThreshold == 0 {
		data.HealthCheckUnhealthyThreshold = 3
	}
	if data.HealthCheckHealthyThreshold == 0 {
		data.HealthCheckHealthyThreshold = 2
	}
	if data.CompressTypes == "" {
		data.CompressTypes = "gzip"
	}

	if data.Protocol != "http" && data.Protocol != "tcp" {
		return fmt.Errorf("invalid protocol: must be http or tcp")
	}

	if data.ListenPort < 1 || data.ListenPort > 65535 {
		return fmt.Errorf("invalid listen port: must be between 1 and 65535")
	}

	validStrategies := map[string]bool{
		"round_robin": true, "ip_hash": true, "least_conn": true,
		"random": true, "first": true, "least_time": true,
	}
	if !validStrategies[data.Strategy] {
		return fmt.Errorf("invalid strategy: must be round_robin, ip_hash, least_conn, random, first, or least_time")
	}

	if data.Domain != "" && (data.Protocol == "http" || data.Protocol == "https") {
		domains := strings.Split(data.Domain, ",")
		for _, d := range domains {
			d = strings.TrimSpace(d)
			if d == "" {
				continue
			}
			if !isValidDomain(d) {
				return fmt.Errorf("invalid domain format: '%s'", d)
			}
		}
	}

	if len(data.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	enabledUpstreamCount := 0
	hostPortSeen := make(map[string]bool)
	for i, u := range data.Upstreams {
		if u.Host == "" {
			return fmt.Errorf("upstream #%d: host is required", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("upstream #%d: invalid port %d (must be 1-65535)", i+1, u.Port)
		}
		if u.Weight < 0 {
			return fmt.Errorf("upstream #%d: weight cannot be negative", i+1)
		}

		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("upstream %s:%d is duplicated", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		if !isValidHost(u.Host) {
			return fmt.Errorf("upstream #%d: invalid host '%s'", i+1, u.Host)
		}

		if u.Enabled {
			enabledUpstreamCount++
		}
	}

	if enabledUpstreamCount == 0 {
		return fmt.Errorf("at least one enabled upstream is required")
	}

	if data.EnableTLS && data.TLSSource == "acme_dns" {
		if data.ACMEConfigID == 0 {
			return fmt.Errorf("ACME DNS provider is required")
		}
	}

	if data.HealthCheckInterval < 1 {
		return fmt.Errorf("health check interval must be >= 1 second")
	}

	if data.HealthCheckTimeout < 1 {
		return fmt.Errorf("health check timeout must be >= 1 second")
	}

	tempCaddyID := "validate_" + uniqueID

		ruleConfig := services.SingleRuleConfig{
		Protocol:                data.Protocol,
		Domain:                  data.Domain,
		ListenPort:              data.ListenPort,
		Strategy:                data.Strategy,
		DynamicDNS:              data.DynamicDNS,
		DnsServer:               data.DnsServer,
		DnsFamily:               data.DnsFamily,
		HealthCheckPath:         data.HealthCheckPath,
		HealthCheckInterval:     data.HealthCheckInterval,
		HealthCheckTimeout:      data.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: data.HealthCheckUnhealthyThreshold,
		EnableTLS:               data.EnableTLS,
		TLSCert:                 data.TLSCert,
		TLSKey:                  data.TLSKey,
		TLSHTTPRedirect:         data.TLSHTTPRedirect,
		EnableCompress:          data.EnableCompress,
		CompressTypes:           data.CompressTypes,
		EnableActiveHealthCheck: data.EnableActiveHealthCheck,
		HostHeader:              data.HostHeader,
		CaddyID:                 tempCaddyID,
	}

	for _, u := range data.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if data.Protocol == "tcp" {
				protocol = "tcp"
			} else {
				protocol = "http"
			}
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	if data.Protocol == "tcp" {
		return h.caddyService.ValidateConfig(services.GenerateSingleRuleCaddyConfig(ruleConfig), uniqueID+"_l4")
	}

	routeConfig, routeErr := services.GenerateRouteObject(ruleConfig)
	if routeErr != nil {
		return fmt.Errorf("route config generation failed: %v", routeErr)
	}
	if mergeErr := h.caddyService.ValidateRouteMergedConfig(serverName, routeConfig, uniqueID+"_merge"); mergeErr != nil {
		return fmt.Errorf("Caddy configuration validation failed: %v", mergeErr)
	}

	if delErr := h.caddyService.DeleteRouteByID(serverName, tempCaddyID); delErr != nil {
		log.Printf("Warning: failed to delete validation temp route %s: %v (continuing anyway)", tempCaddyID, delErr)
	}

	return nil
}


func (h *Handlers) ApplyConfigOnStartup() error {
	// Wait for Caddy to be ready (up to 10 seconds)
	maxRetries := 20
	retryDelay := 500 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		client := &http.Client{Timeout: 2 * time.Second}
		resp, err := client.Get("http://localhost:2019/config/")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				break
			}
		}
		time.Sleep(retryDelay)
	}

	rows, err := db.DB.Query(`SELECT caddy_id FROM lb_rules WHERE enabled = 1`)
	if err != nil {
		return err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var caddyID string
		if err := rows.Scan(&caddyID); err != nil {
			continue
		}
		count++
	}

	log.Printf("Applying Caddy config on startup (enabled rules: %d)", count)
	h.applyCaddyConfig()

	return nil
}


func (h *Handlers) validatePort(protocol string, port int, excludeCaddyID string) error {
	adminPorts := []int{8000, 2019}
	httpReservedPorts := []int{80, 443}

	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}

	for _, p := range adminPorts {
		if port == p {
			return fmt.Errorf("port %d is reserved for admin", port)
		}
	}

	if protocol == "tcp" {
		for _, p := range httpReservedPorts {
			if port == p {
				return fmt.Errorf("port %d is reserved for HTTP/HTTPS", p)
			}
		}
	}

	return h.validatePortFromDB(protocol, port, excludeCaddyID)
}


func (h *Handlers) validatePortFromDB(protocol string, port int, excludeCaddyID string) error {
	// Check conflict with existing rules:
	// - HTTP rules may share a port (Caddy routes by host), but cannot share with TCP.
	// - TCP rules are L4 and cannot share a port with any other rule (HTTP or TCP).
	var count int
	var err error
	if excludeCaddyID != "" {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ?", port, excludeCaddyID).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND caddy_id != ? AND protocol = 'tcp'", port, excludeCaddyID).Scan(&count)
		}
	} else {
		if protocol == "tcp" {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ?", port).Scan(&count)
		} else {
			err = db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE listen_port = ? AND protocol = 'tcp'", port).Scan(&count)
		}
	}
	if err != nil {
		return fmt.Errorf("database error while validating port: %v", err)
	}

	if count > 0 {
		return fmt.Errorf("port %d is already in use by another rule", port)
	}

	return nil
}


func (h *Handlers) validateUpstreams(upstreams []models.Upstream) error {
	if len(upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	hostPortSeen := make(map[string]bool)
	for i, u := range upstreams {
		if u.Host == "" {
			return fmt.Errorf("upstream #%d: host is required", i+1)
		}
		if u.Port < 1 || u.Port > 65535 {
			return fmt.Errorf("upstream %s:%d: invalid port", u.Host, u.Port)
		}

		// Check for duplicate host:port
		key := fmt.Sprintf("%s:%d", u.Host, u.Port)
		if hostPortSeen[key] {
			return fmt.Errorf("upstream %s:%d is duplicated", u.Host, u.Port)
		}
		hostPortSeen[key] = true

		// Validate host format - must be valid IP or domain
		if !isValidHost(u.Host) {
			return fmt.Errorf("upstream %s:%d: invalid host format '%s' (must be IP address or domain name)", u.Host, u.Port, u.Host)
		}
	}

	return nil
}

