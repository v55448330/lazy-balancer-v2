package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func (h *Handlers) ListRules(c *gin.Context) {
	rows, err := db.DB.Query(`
		SELECT COALESCE(caddy_id,'') AS caddy_id, name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_auto_cert,0), COALESCE(tls_http_redirect,0),
		       COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), enabled, created_by, created_at, updated_at, updated_by,
		       COALESCE(host_header,'')
		FROM lb_rules ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Database error"})
		return
	}
	defer rows.Close()

	var rules []models.LbRule
	for rows.Next() {
		var r models.LbRule
		var domain, strategy, description, compressTypes, hostHeader, dnsFamily, tlsSource string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect, enableCompress bool
		var acmeConfigID int
		var createdBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		var updatedBy sql.NullInt64
		err := rows.Scan(&r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval,
			&enableActiveHealthCheck, &enableTLS, &tlsSource, &acmeConfigID, &tlsAutoCert, &tlsHTTPRedirect,
			&enableCompress, &compressTypes, &r.Enabled, &createdBy, &createdAt, &updatedAt, &updatedBy,
			&hostHeader)
		if err != nil {
			continue
		}
		if createdBy.Valid {
			r.CreatedBy = int(createdBy.Int64)
		}
		if createdAt.Valid {
			r.CreatedAt = createdAt.Time
		}
		if updatedAt.Valid {
			r.UpdatedAt = updatedAt
		}
		if updatedBy.Valid {
			r.UpdatedBy = int(updatedBy.Int64)
		}
		r.Description = description
		r.Domain = domain
		r.Strategy = strategy
		if r.Strategy == "" {
			r.Strategy = "round_robin"
		}
		r.DynamicDNS = dynamicDNS
		r.EnableDnsServer = enableDnsServer
		r.DnsFamily = dnsFamily
		r.EnableActiveHealthCheck = enableActiveHealthCheck
		r.EnableTLS = enableTLS
		r.TLSSource = tlsSource
		r.ACMEConfigID = acmeConfigID
		r.TLSAutoCert = tlsAutoCert
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.EnableCompress = enableCompress
		r.CompressTypes = compressTypes
		r.HostHeader = hostHeader

		upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?`, r.CaddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				r.Upstreams = append(r.Upstreams, u)
			}
			upstreamRows.Close()
		}

		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}


func (h *Handlers) GetRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r models.LbRule
	var domain, strategy, hostHeader, dnsFamily, tlsSource string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect bool
	var acmeConfigID int
	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       enabled, created_at, updated_at, COALESCE(host_header,''), caddy_id
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
		&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
		&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &enableTLS, &tlsSource, &acmeConfigID, &r.TLSCert, &r.TLSKey, &tlsAutoCert, &r.TLSEmail, &tlsHTTPRedirect,
		&r.Enabled, &r.CreatedAt, &r.UpdatedAt, &hostHeader, &r.CaddyID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}
	if err != nil {
		log.Printf("GetRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to read rule"})
		return
	}

	r.Domain = domain
	r.Strategy = strategy
	if r.Strategy == "" {
		r.Strategy = "round_robin"
	}
	r.DynamicDNS = dynamicDNS
	r.EnableDnsServer = enableDnsServer
	r.DnsFamily = dnsFamily
	r.EnableActiveHealthCheck = enableActiveHealthCheck
	r.EnableTLS = enableTLS
	r.TLSSource = tlsSource
	r.ACMEConfigID = acmeConfigID
	r.TLSAutoCert = tlsAutoCert
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.HostHeader = hostHeader

	upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?`, caddyID)
	if upstreamRows != nil {
		for upstreamRows.Next() {
			var u models.Upstream
			upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			r.Upstreams = append(r.Upstreams, u)
		}
		upstreamRows.Close()
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: r})
}


func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		Name                          string
		Protocol                      string
		Domain                        string
		ListenPort                    int
		Strategy                      string
		DynamicDNS                    bool
		EnableDnsServer               bool
		DnsServer                     string
		DnsFamily                     string
		HealthCheckPath               string
		HealthCheckInterval           int
		HealthCheckTimeout            int
		HealthCheckUnhealthyThreshold int
		HealthCheckHealthyThreshold   int
		EnableTLS                     bool
		TLSCert                       string
		TLSKey                        string
		TLSAutoCert                   bool
		TLSEmail                      string
		TLSHTTPRedirect               bool
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		EnableActiveHealthCheck       bool
		HostHeader                    string
		CaddyID                       string
	}

	var domain, strategy, hostHeader, compressTypes, tlsCert, tlsKey, tlsEmail string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect, enableCompress bool

	log.Printf("GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''),
		       COALESCE(dns_family,'ipv4'), health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       enabled, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		       COALESCE(enable_active_health_check,0), COALESCE(host_header,''), COALESCE(caddy_id,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
		&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableTLS, &tlsCert, &tlsKey, &tlsAutoCert, &tlsEmail, &tlsHTTPRedirect,
		&r.Enabled, &enableCompress, &compressTypes,
		&enableActiveHealthCheck, &hostHeader, &r.CaddyID)

	if err != nil {
		log.Printf("GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
	}

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get rule: " + err.Error()})
		return
	}

	r.Domain = domain
	r.Strategy = strategy
	if r.Strategy == "" {
		r.Strategy = "round_robin"
	}
	r.DynamicDNS = dynamicDNS
	r.EnableActiveHealthCheck = enableActiveHealthCheck
	r.EnableTLS = enableTLS
	r.TLSCert = tlsCert
	r.TLSKey = tlsKey
	r.TLSAutoCert = tlsAutoCert
	r.TLSEmail = tlsEmail
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.EnableCompress = enableCompress
	r.CompressTypes = compressTypes
	r.HostHeader = hostHeader

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(protocol,'http'), enabled
		FROM upstreams WHERE rule_id = ? AND enabled = 1
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get upstreams"})
		return
	}
	defer upstreamRows.Close()

	var ups []services.UpstreamConfig
	for upstreamRows.Next() {
		var u services.UpstreamConfig
		var protocol string
		var enabled bool
		upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &protocol, &enabled)
		u.Protocol = protocol
		u.Enabled = enabled
		ups = append(ups, u)
	}

	log.Printf("GetRuleCaddyConfig: caddyID=%s, protocol=%s, domain=%s, port=%d, upstreams=%d, enabled=%v",
		r.CaddyID, r.Protocol, r.Domain, r.ListenPort, len(ups), r.Enabled)

	responseData := map[string]interface{}{
		"caddy_id": r.CaddyID,
		"enabled":  r.Enabled,
	}

	if r.CaddyID == "" || !r.Enabled {
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// Get the actual route object from Caddy via @id
	caddyActualConfig, err := h.caddyService.GetConfigByID(r.CaddyID)
	if err != nil {
		log.Printf("GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	// Build the surrounding server/TLS context so the dialog shows certificates and policies
	fullConfig := services.GenerateCaddyConfig(h.cfg)
	ruleContext := buildRuleCaddyContext(fullConfig, r.CaddyID, r.ListenPort)

	responseData["config"] = map[string]interface{}{
		"route":               caddyActualConfig,
		"server_context":      ruleContext["server"],
		"tls_certificates":    ruleContext["tls_certificates"],
		"tls_connection_policies": ruleContext["tls_connection_policies"],
		"automation_policies": ruleContext["automation_policies"],
	}
	responseData["config_not_exists"] = false
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

// buildRuleCaddyContext extracts the server and TLS context relevant to a rule from the full Caddy config.
func buildRuleCaddyContext(fullConfig map[string]interface{}, caddyID string, listenPort int) map[string]interface{} {
	result := map[string]interface{}{
		"server":                    nil,
		"tls_certificates":          []interface{}{},
		"tls_connection_policies":   []interface{}{},
		"automation_policies":       []interface{}{},
	}

	apps, _ := fullConfig["apps"].(map[string]interface{})
	if apps == nil {
		return result
	}

	httpApp, _ := apps["http"].(map[string]interface{})
	if httpApp == nil {
		return result
	}

	servers, _ := httpApp["servers"].(map[string]interface{})
	if servers == nil {
		return result
	}

	// Find server containing this rule's route
	for serverName, serverVal := range servers {
		server, _ := serverVal.(map[string]interface{})
		if server == nil {
			continue
		}
		routes, _ := server["routes"].([]interface{})
		for _, routeVal := range routes {
			route, _ := routeVal.(map[string]interface{})
			if route == nil {
				continue
			}
			if route["@id"] == caddyID {
				result["server"] = map[string]interface{}{
					"server_name":             serverName,
					"listen":                  server["listen"],
					"tls_connection_policies": server["tls_connection_policies"],
				}
				if policies, ok := server["tls_connection_policies"].([]interface{}); ok {
					result["tls_connection_policies"] = policies
				}
				break
			}
		}
	}

	tlsApp, _ := apps["tls"].(map[string]interface{})
	if tlsApp == nil {
		return result
	}

	if certs, ok := tlsApp["certificates"].(map[string]interface{}); ok {
		var certList []interface{}
		switch v := certs["load_pem"].(type) {
		case []interface{}:
			certList = v
		case []map[string]interface{}:
			for _, c := range v {
				certList = append(certList, c)
			}
		}
		for _, certVal := range certList {
			cert, _ := certVal.(map[string]interface{})
			if cert == nil {
				continue
			}
			matched := false
			switch tags := cert["tags"].(type) {
			case []interface{}:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			case []string:
				for _, tag := range tags {
					if tag == caddyID {
						matched = true
						break
					}
				}
			}
			if matched {
				result["tls_certificates"] = append(result["tls_certificates"].([]interface{}), cert)
			}
		}
	}

	if automation, ok := tlsApp["automation"].(map[string]interface{}); ok {
		if policies, ok := automation["policies"].([]interface{}); ok {
			result["automation_policies"] = policies
		}
	}

	return result
}


func (h *Handlers) CreateRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot create rules on slave node"})
		return
	}

	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		body, _ := io.ReadAll(c.Request.Body)
		log.Printf("CreateRule bind error: %v, body: %s", err, string(body))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}
	log.Printf("CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Name is required"})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Protocol is required"})
		return
	}
	// When TLS is enabled for HTTP, default the listen port to 443 unless the user explicitly set another port.
	if req.Protocol == "http" && req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	if req.ListenPort <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Listen port must be greater than 0"})
		return
	}

	if len(req.Upstreams) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "At least one upstream required"})
		return
	}

	if err := h.validatePort(req.Protocol, req.ListenPort, ""); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Set defaults before validation
	if req.Strategy == "" {
		req.Strategy = "round_robin"
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = 10
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = 5
	}
	// Validate TLS certificate if provided (manual source only)
	if req.EnableTLS && req.TLSSource == "manual" {
		if err := validateTLSCertificate(req.TLSCert, req.TLSKey); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS certificate validation failed: " + err.Error()})
			return
		}
	}

	if req.CompressTypes == "" {
		req.CompressTypes = "gzip"
	}

	// Determine server name based on port, protocol and TLS status
	var serverName string
	var listenPort int
	if req.Protocol == "http" {
		if req.EnableTLS && req.ListenPort == 443 {
			serverName = "https_443"
		} else if req.ListenPort == 80 {
			serverName = "http_80"
		} else if req.EnableTLS {
			serverName = fmt.Sprintf("https_%d", req.ListenPort)
		} else {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
		}
		listenPort = req.ListenPort
	} else {
		serverName = fmt.Sprintf("tcp_%d", req.ListenPort)
		listenPort = req.ListenPort
	}

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}

	// Generate caddy_id for @id-based management
	caddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to generate caddy ID"})
		return
	}

	// Build route config for Caddy validation (using request data before DB write)
		ruleConfig := services.SingleRuleConfig{
			Protocol:                req.Protocol,
			Domain:                  req.Domain,
			ListenPort:              req.ListenPort,
			Strategy:                req.Strategy,
			DynamicDNS:              req.DynamicDNS,
			EnableDnsServer:         req.EnableDnsServer,
			DnsServer:               req.DnsServer,
			DnsFamily:               req.DnsFamily,
			HealthCheckPath:         req.HealthCheckPath,
			HealthCheckInterval:     req.HealthCheckInterval,
			HealthCheckTimeout:      req.HealthCheckTimeout,
			EnableTLS:               req.EnableTLS,
			TLSSource:               req.TLSSource,
			ACMEConfigID:            req.ACMEConfigID,
			TLSHTTPRedirect:         req.TLSHTTPRedirect,
			EnableCompress:          req.EnableCompress,
			CompressTypes:           req.CompressTypes,
			EnableActiveHealthCheck: req.EnableActiveHealthCheck,
			HostHeader:              req.HostHeader,
			CaddyID:                 caddyID,
		}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, "new_"+generateRandomString(8), serverName); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Start DB transaction: persist validated config before applying to Caddy
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to start database transaction"})
		return
	}

	_, err = tx.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, host_header, enable_tls, tls_source, acme_config_id, tls_cert, tls_key, tls_auto_cert, tls_email, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_at, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.HostHeader, req.EnableTLS, req.TLSSource, req.ACMEConfigID, req.TLSCert, req.TLSKey, req.TLSAutoCert, req.TLSEmail,
		req.TLSHTTPRedirect, req.EnableCompress, req.CompressTypes, 1, userIDInt, time.Now().Format("2006-01-02 15:04:05"), caddyID)

	if err != nil {
		tx.Rollback()
		log.Printf("CreateRule database error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create rule"})
		return
	}

	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			u.Protocol = "http"
		}
		_, err = tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
		if err != nil {
			tx.Rollback()
			log.Printf("CreateRule upstream insert error: %v", err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create upstreams"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("CreateRule transaction commit error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to commit rule"})
		return
	}

	// Apply Caddy config after DB commit; rollback DB on Caddy failure
	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		log.Printf("CreateRule failed to generate route config for caddy_id=%s: %v, rolling back database", caddyID, err)
		db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
		db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	applyCaddy := func() error {
		if err := h.caddyService.CreateServerIfNotExists(serverName, listenPort); err != nil {
			return fmt.Errorf("failed to create server: %w", err)
		}

		if err := h.caddyService.PrependRouteToServer(serverName, routeConfig); err != nil {
			return fmt.Errorf("failed to add route to Caddy: %w", err)
		}

		if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
			return fmt.Errorf("Caddy write verification failed: %w", err)
		}
		return nil
	}

	if err := applyCaddy(); err != nil {
		log.Printf("CreateRule Caddy apply failed for caddy_id=%s: %v, rolling back database", caddyID, err)
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
		db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
		db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Reload full Caddy config to apply TLS certificates or ACME automation policies
	if req.EnableTLS {
		log.Printf("Reloading full Caddy config to apply TLS/ACME for caddy_id=%s", caddyID)
		if req.TLSSource == "acme_dns" {
			h.certificateService.CreateJobsForRule(caddyID, req.Domain)
		}
		fullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
			log.Printf("Failed to reload Caddy config after rule creation: %v", err)
			// Don't fail the request since the rule is already created and route applied
		}
	}

	log.Printf("Rule created with caddy_id=%s, applied via @id mechanism", caddyID)
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Rule created", Data: gin.H{"caddy_id": caddyID}})
}


func (h *Handlers) UpdateRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot update rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("UpdateRule bind error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Invalid request: " + err.Error()})
		return
	}
	log.Printf("UpdateRule request for caddy_id=%s: enable_tls=%v, tls_auto_cert=%v, cert_len=%d, key_len=%d",
		caddyID, req.EnableTLS, req.TLSAutoCert, len(req.TLSCert), len(req.TLSKey))

	// When TLS is enabled on HTTP, default the port to 443 if the user didn't explicitly set one.
	// For updates the port is fixed, so we only apply the default when an explicit port was not supplied.
	if req.Protocol == "http" && req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	if req.ListenPort > 0 {
		var currentPort int
		err := db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&currentPort)
		if err != nil {
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
			return
		}
		if currentPort != req.ListenPort {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Port cannot be changed after rule creation"})
			return
		}
	}

	// Determine server name for validation - port can't change so use req.ListenPort or query existing
	var validationServerName string
	validationPort := req.ListenPort
	if validationPort == 0 {
		db.DB.QueryRow("SELECT listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&validationPort)
	}
	validationProtocol := req.Protocol
	validationEnableTLS := req.EnableTLS
	if validationProtocol == "" {
		db.DB.QueryRow("SELECT COALESCE(protocol,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&validationProtocol)
	}
	if !validationEnableTLS {
		db.DB.QueryRow("SELECT COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&validationEnableTLS)
	}
	if validationProtocol == "http" {
		if validationEnableTLS && validationPort == 443 {
			validationServerName = "https_443"
		} else if validationPort == 80 {
			validationServerName = "http_80"
		} else if validationEnableTLS {
			validationServerName = fmt.Sprintf("https_%d", validationPort)
		} else {
			validationServerName = fmt.Sprintf("http_%d", validationPort)
		}
	} else {
		validationServerName = fmt.Sprintf("tcp_%d", validationPort)
	}

	// Fill in missing fields from database so validation and the update use complete data.
	var existingRule models.LbRule
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0), COALESCE(tls_auto_cert,0), COALESCE(tls_email,''),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(host_header,''), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
			COALESCE(enabled,1), name, description
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey, &existingRule.TLSSource, &existingRule.ACMEConfigID,
		&existingRule.EnableTLS, &existingRule.TLSHTTPRedirect, &existingRule.TLSAutoCert, &existingRule.TLSEmail,
		&existingRule.DynamicDNS, &existingRule.EnableDnsServer, &existingRule.DnsServer, &existingRule.DnsFamily,
		&existingRule.HealthCheckPath, &existingRule.HealthCheckInterval, &existingRule.HealthCheckTimeout,
		&existingRule.HealthCheckUnhealthyThreshold, &existingRule.HealthCheckHealthyThreshold,
		&existingRule.EnableActiveHealthCheck, &existingRule.HostHeader, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	// Capture old upstreams for potential DB rollback
	var oldUpstreams []models.Upstream
	oldUpstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
	if oldUpstreamRows != nil {
		for oldUpstreamRows.Next() {
			var u models.Upstream
			oldUpstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			oldUpstreams = append(oldUpstreams, u)
		}
		oldUpstreamRows.Close()
	}

	// Use existing values for fields not provided in request
	if req.Protocol == "" {
		req.Protocol = existingRule.Protocol
	}
	if req.Domain == "" {
		req.Domain = existingRule.Domain
	}
	if req.ListenPort == 0 {
		req.ListenPort = existingRule.ListenPort
	}
	if req.Strategy == "" {
		req.Strategy = existingRule.Strategy
	}
	if req.TLSSource == "" {
		req.TLSSource = existingRule.TLSSource
	}
	if req.ACMEConfigID == 0 {
		req.ACMEConfigID = existingRule.ACMEConfigID
	}
	if req.TLSEmail == "" {
		req.TLSEmail = existingRule.TLSEmail
	}
	if req.HealthCheckPath == "" {
		req.HealthCheckPath = existingRule.HealthCheckPath
	}
	if req.HealthCheckInterval == 0 {
		req.HealthCheckInterval = existingRule.HealthCheckInterval
	}
	if req.HealthCheckTimeout == 0 {
		req.HealthCheckTimeout = existingRule.HealthCheckTimeout
	}
	if req.HealthCheckUnhealthyThreshold == 0 {
		req.HealthCheckUnhealthyThreshold = existingRule.HealthCheckUnhealthyThreshold
	}
	if req.HealthCheckHealthyThreshold == 0 {
		req.HealthCheckHealthyThreshold = existingRule.HealthCheckHealthyThreshold
	}
	if req.CompressTypes == "" {
		req.CompressTypes = existingRule.CompressTypes
	}
	if req.Name == "" {
		req.Name = existingRule.Name
	}
	if req.Description == "" {
		req.Description = existingRule.Description
	}

	// Load existing upstreams if not provided in request
	if len(req.Upstreams) == 0 {
		req.Upstreams = oldUpstreams
	}

	// Validate TLS certificate if provided (manual source only)
	if (req.EnableTLS || req.TLSCert != "" || req.TLSKey != "") && req.TLSSource == "manual" {
		tlsCert := req.TLSCert
		tlsKey := req.TLSKey
		// If cert/key not provided in request, get from DB
		if tlsCert == "" {
			tlsCert = existingRule.TLSCert
		}
		if tlsKey == "" {
			tlsKey = existingRule.TLSKey
		}
		if tlsCert != "" && tlsKey != "" {
			if err := validateTLSCertificate(tlsCert, tlsKey); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS certificate validation failed: " + err.Error()})
				return
			}
		}
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, fmt.Sprintf("update_%s_%s", caddyID, generateRandomString(8)), validationServerName); err != nil {
		log.Printf("UpdateRule validation failed for caddy_id=%s, server_name=%s: %v", caddyID, validationServerName, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Build dynamic update for lb_rules table
	query := "UPDATE lb_rules SET "
	var args []interface{}

	query += "name = ?, "
	args = append(args, req.Name)
	query += "description = ?, "
	args = append(args, req.Description)
	query += "protocol = ?, "
	args = append(args, req.Protocol)
	query += "domain = ?, "
	args = append(args, req.Domain)
	query += "listen_port = ?, "
	args = append(args, req.ListenPort)
	if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	query += "strategy = ?, "
	args = append(args, req.Strategy)
	query += "dynamic_dns = ?, "
	args = append(args, req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, req.DnsServer)
	query += "dns_family = ?, "
	args = append(args, req.DnsFamily)
	query += "health_check_path = ?, "
	args = append(args, req.HealthCheckPath)
	query += "health_check_interval = ?, "
	args = append(args, req.HealthCheckInterval)
	query += "health_check_timeout = ?, "
	args = append(args, req.HealthCheckTimeout)
	query += "health_check_unhealthy_threshold = ?, "
	args = append(args, req.HealthCheckUnhealthyThreshold)
	query += "health_check_healthy_threshold = ?, "
	args = append(args, req.HealthCheckHealthyThreshold)
	query += "enable_active_health_check = ?, "
	args = append(args, req.EnableActiveHealthCheck)
	query += "host_header = ?, "
	args = append(args, req.HostHeader)
	query += "enable_tls = ?, "
	args = append(args, req.EnableTLS)
	query += "tls_source = ?, "
	args = append(args, req.TLSSource)
	query += "acme_config_id = ?, "
	args = append(args, req.ACMEConfigID)
	if req.TLSCert != "" {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" {
		query += "tls_key = ?, "
		args = append(args, req.TLSKey)
	}
	query += "tls_auto_cert = ?, "
	args = append(args, req.TLSAutoCert)
	query += "tls_email = ?, "
	args = append(args, req.TLSEmail)
	query += "tls_http_redirect = ?, "
	args = append(args, req.TLSHTTPRedirect)
	query += "enable_compress = ?, "
	args = append(args, req.EnableCompress)
	query += "compress_types = ?, "
	args = append(args, req.CompressTypes)
	query += "enabled = ?, "
	args = append(args, req.Enabled)

	// Build full rule config for route generation
	domain := req.Domain
	listenPort := req.ListenPort
	strategy := req.Strategy
	if strategy == "" {
		strategy = "round_robin"
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                req.Protocol,
		Domain:                  domain,
		ListenPort:              listenPort,
		Strategy:                strategy,
		DynamicDNS:              req.DynamicDNS,
		EnableDnsServer:         req.EnableDnsServer,
		DnsServer:               req.DnsServer,
		DnsFamily:               req.DnsFamily,
		HealthCheckPath:         req.HealthCheckPath,
		HealthCheckInterval:     req.HealthCheckInterval,
		HealthCheckTimeout:      req.HealthCheckTimeout,
		EnableTLS:               req.EnableTLS,
		TLSSource:               req.TLSSource,
		ACMEConfigID:            req.ACMEConfigID,
		TLSHTTPRedirect:         req.TLSHTTPRedirect,
		EnableCompress:          req.EnableCompress,
		CompressTypes:           req.CompressTypes,
		EnableActiveHealthCheck: req.EnableActiveHealthCheck,
		HostHeader:              req.HostHeader,
		CaddyID:                 caddyID,
	}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			protocol = "http"
		}
		weight := u.Weight
		if weight == 0 {
			weight = 1
		}
		ruleConfig.Upstreams = append(ruleConfig.Upstreams, services.UpstreamConfig{
			Host: u.Host, Port: u.Port, Weight: weight, Protocol: protocol, Enabled: u.Enabled,
		})
	}

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	// Backup current Caddy route config for rollback
	oldRouteConfig, _ := h.caddyService.GetConfigByID(caddyID)

	// Start DB transaction: write validated config and commit first
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to start database transaction"})
		return
	}

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?"
	args = append(args, userIDInt, caddyID)

	if _, err := tx.Exec(query, args...); err != nil {
		tx.Rollback()
		log.Printf("UpdateRule database error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update rule"})
		return
	}

	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("UpdateRule upstream delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update upstreams"})
		return
	}
	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			u.Protocol = "http"
		}
		if _, err := tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol); err != nil {
			tx.Rollback()
			log.Printf("UpdateRule upstream insert error for caddy_id=%s: %v", caddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update upstreams"})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		log.Printf("UpdateRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to commit rule update"})
		return
	}

	// Apply Caddy changes after DB commit; restore previous Caddy route on failure
	if err := h.caddyService.SetConfigByID(caddyID, routeConfig); err != nil {
		if oldRouteConfig != nil {
			h.caddyService.SetConfigByID(caddyID, oldRouteConfig)
		}
		log.Printf("UpdateRule Caddy update failed for caddy_id=%s: %v, restored previous route", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy update failed: " + err.Error()})
		return
	}

	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		if oldRouteConfig != nil {
			h.caddyService.SetConfigByID(caddyID, oldRouteConfig)
		}
		log.Printf("UpdateRule Caddy verification failed for caddy_id=%s: %v, restored previous route", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	// Reload full Caddy config to apply TLS certificates or ACME automation policies
	if req.EnableTLS || req.TLSCert != "" || req.TLSKey != "" || req.TLSSource == "acme_dns" {
		log.Printf("Reloading full Caddy config after rule update for caddy_id=%s", caddyID)
		if req.TLSSource == "acme_dns" && req.EnableTLS {
			h.certificateService.CreateJobsForRule(caddyID, domain)
		}
		fullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
			log.Printf("Failed to reload Caddy config after rule update: %v", err)
			// Don't fail the request since the rule is already updated
		}
	}

	log.Printf("Rule %s updated, applied via @id mechanism", caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule updated"})
}


func (h *Handlers) DeleteRule(c *gin.Context) {
	// Check if slave mode
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot delete rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	var domain string
	var enableTLS bool
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), COALESCE(protocol,''), listen_port, COALESCE(domain,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &protocol, &listenPort, &domain, &enableTLS)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	var serverPort int
	if protocol == "http" {
		if enableTLS && listenPort == 443 {
			serverName = "https_443"
			serverPort = 443
		} else if listenPort == 80 {
			serverName = "http_80"
			serverPort = 80
		} else if enableTLS {
			serverName = fmt.Sprintf("https_%d", listenPort)
			serverPort = listenPort
		} else {
			serverName = fmt.Sprintf("http_%d", listenPort)
			serverPort = listenPort
		}
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
		serverPort = listenPort
	}

	// Remove route from server
	if caddyID != "" {
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
	}

	// HTTP port 80 and HTTPS port 443 servers should never be deleted (default site)
	keepServer := (protocol == "http" && listenPort == 80) || (protocol == "http" && enableTLS && listenPort == 443)

	if !keepServer {
		// Check if there are other enabled rules using this server
		var otherEnabledCount int
		db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE caddy_id != ? AND listen_port = ? AND enabled = 1", caddyID, serverPort).Scan(&otherEnabledCount)

		if otherEnabledCount == 0 {
			h.caddyService.DeleteServer(serverName)
			log.Printf("Rule %s deleted, server %s removed", caddyID, serverName)
		} else {
			log.Printf("Rule %s deleted, server %s kept (%d other enabled rules)", caddyID, serverName, otherEnabledCount)
		}
	} else {
		log.Printf("Rule %s deleted, server %s kept (reserved port)", caddyID, serverName)
	}

	// Delete upstreams first
	db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
	db.DB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID)
	// Delete the rule
	db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)

	// Reload full Caddy config to clean up TLS certificates
	log.Printf("Reloading full Caddy config after rule deletion for caddy_id=%s", caddyID)
	fullConfig := services.GenerateCaddyConfig(h.cfg)
	if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
		log.Printf("Failed to reload Caddy config after rule deletion: %v", err)
		// Don't fail the request since the rule is already deleted
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule deleted"})
}


func (h *Handlers) DuplicateRule(c *gin.Context) {
	nodeMode, _ := c.Get("node_mode")
	if nodeMode != nil && nodeMode.(string) == "slave" {
		c.JSON(http.StatusForbidden, models.APIResponse{Code: 403, Message: "Cannot duplicate rules on slave node"})
		return
	}

	caddyID := c.Param("caddy_id")

	var rule models.LbRule
	err := db.DB.QueryRow(`
		SELECT caddy_id, name, protocol, domain, listen_port, strategy, dynamic_dns,
		       health_check_path, health_check_interval, health_check_timeout,
		       health_check_unhealthy_threshold, health_check_healthy_threshold,
		       enable_tls, COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), tls_cert, tls_key, tls_auto_cert, tls_email,
		       tls_http_redirect, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip,zstd'), enabled, created_by,
		       COALESCE(host_header,''), COALESCE(dns_server,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.TLSCert, &rule.TLSKey, &rule.TLSAutoCert, &rule.TLSEmail,
		&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.CreatedBy,
		&rule.HostHeader, &rule.DnsServer,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	userID, _ := c.Get("user_id")

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to generate caddy ID"})
		return
	}

	result, err := db.DB.Exec(`
		INSERT INTO lb_rules (name, protocol, domain, listen_port, strategy, dynamic_dns, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_tls, tls_source, acme_config_id, tls_cert, tls_key, tls_auto_cert, tls_email,
			tls_http_redirect, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?)
	`, rule.Name+" (Copy)", rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.DnsServer, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.TLSCert, rule.TLSKey, rule.TLSAutoCert, rule.TLSEmail,
		rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, 0, userID, userID,
		rule.HostHeader, newCaddyID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to duplicate rule"})
		return
	}

	_ = result

	db.DB.Exec("UPDATE lb_rules SET updated_by = ? WHERE caddy_id = ?", userID, newCaddyID)

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, weight, domain, dynamic_dns, enabled, COALESCE(protocol,'http')
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err == nil {
		for upstreamRows.Next() {
			var u struct {
				Host       string
				Port       int
				Weight     int
				Domain     string
				DynamicDNS bool
				Enabled    bool
				Protocol   string
			}
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			db.DB.Exec(`
				INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			`, newCaddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
		}
		upstreamRows.Close()
	}

	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "Rule duplicated", Data: gin.H{"caddy_id": newCaddyID}})
}


func (h *Handlers) EnableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enable rule"})
		return
	}

	if err := h.applyCaddyConfigWithRollback(); err != nil {
		// Revert DB state on Caddy failure
		db.DB.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to apply Caddy config: %v", err)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule enabled"})
}


func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now') WHERE caddy_id = ?", caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to disable rule"})
		return
	}

	if err := h.applyCaddyConfigWithRollback(); err != nil {
		// Revert DB state on Caddy failure
		db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to apply Caddy config: %v", err)})
		return
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule disabled"})
}

