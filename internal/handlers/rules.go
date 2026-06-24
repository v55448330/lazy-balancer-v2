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
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_auto_cert,0), COALESCE(tls_http_redirect,0),
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
		var domain, strategy, description, compressTypes, hostHeader, dnsFamily string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect, enableCompress bool
		var createdBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		var updatedBy sql.NullInt64
		err := rows.Scan(&r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval,
			&enableActiveHealthCheck, &enableTLS, &tlsAutoCert, &tlsHTTPRedirect,
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
	var domain, strategy, hostHeader, dnsFamily string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsAutoCert, tlsHTTPRedirect bool
	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       enabled, created_at, updated_at, COALESCE(host_header,''), caddy_id
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
		&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
		&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &enableTLS, &r.TLSCert, &r.TLSKey, &tlsAutoCert, &r.TLSEmail, &tlsHTTPRedirect,
		&r.Enabled, &r.CreatedAt, &r.UpdatedAt, &hostHeader, &r.CaddyID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
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

	caddyActualConfig, err := h.caddyService.GetConfigByID(r.CaddyID)
	if err != nil {
		log.Printf("GetRuleCaddyConfig: failed to get config from Caddy for caddy_id=%s: %v", r.CaddyID, err)
		responseData["config"] = nil
		responseData["config_not_exists"] = true
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
		return
	}

	responseData["config"] = caddyActualConfig
	responseData["config_not_exists"] = false
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
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
	// Validate TLS certificate if provided
	if req.EnableTLS && !req.TLSAutoCert {
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

	if err := h.caddyService.CreateServerIfNotExists(serverName, listenPort); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to create server: " + err.Error()})
		return
	}

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	if err := h.caddyService.PrependRouteToServer(serverName, routeConfig); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to add route to Caddy: " + err.Error()})
		return
	}

	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	_, err = db.DB.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, host_header, enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_at, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.HostHeader, req.EnableTLS, req.TLSCert, req.TLSKey, req.TLSAutoCert, req.TLSEmail,
		req.TLSHTTPRedirect, req.EnableCompress, req.CompressTypes, 1, userIDInt, time.Now().Format("2006-01-02 15:04:05"), caddyID)

	if err != nil {
		log.Printf("CreateRule database error: %v, rolling back Caddy", err)
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to create rule, Caddy route rolled back"})
		return
	}

	for _, u := range req.Upstreams {
		if u.Weight == 0 {
			u.Weight = 1
		}
		if u.Protocol == "" {
			u.Protocol = "http"
		}
		db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
	}

	// Reload full Caddy config to apply TLS certificates
	if req.EnableTLS && !req.TLSAutoCert && req.TLSCert != "" && req.TLSKey != "" {
		log.Printf("Reloading full Caddy config to apply TLS certificate for caddy_id=%s", caddyID)
		fullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
			log.Printf("Failed to reload Caddy config after rule creation: %v", err)
			// Don't fail the request since the rule is already created
		}
	}

	log.Printf("Rule created with caddy_id=%s, applied via @id mechanism (no full reload)", caddyID)
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

	// Prevent port change - get current rule's port
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

	// Fill in missing fields from database for validation
	var existingRule models.LbRule
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,'')
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
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

	// Validate TLS certificate if provided
	if req.EnableTLS || req.TLSCert != "" || req.TLSKey != "" {
		tlsCert := req.TLSCert
		tlsKey := req.TLSKey
		// If cert/key not provided in request, get from DB
		if tlsCert == "" || tlsKey == "" {
			if tlsCert == "" {
				tlsCert = existingRule.TLSCert
			}
			if tlsKey == "" {
				tlsKey = existingRule.TLSKey
			}
		}
		if tlsCert != "" && tlsKey != "" {
			if err := validateTLSCertificate(tlsCert, tlsKey); err != nil {
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS certificate validation failed: " + err.Error()})
				return
			}
		}
	}

	// Load existing upstreams if not provided in request
	if len(req.Upstreams) == 0 {
		upstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				req.Upstreams = append(req.Upstreams, u)
			}
			upstreamRows.Close()
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

	if req.Name != "" {
		query += "name = ?, "
		args = append(args, req.Name)
	}
	if req.Protocol != "" {
		query += "protocol = ?, "
		args = append(args, req.Protocol)
	}
	if req.Domain != "" {
		query += "domain = ?, "
		args = append(args, req.Domain)
	}
	if req.ListenPort > 0 {
		query += "listen_port = ?, "
		args = append(args, req.ListenPort)

		if err := h.validatePortFromDB(req.Protocol, req.ListenPort, caddyID); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}
	if req.Strategy != "" {
		query += "strategy = ?, "
		args = append(args, req.Strategy)
	}
	query += "dynamic_dns = ?, "
	args = append(args, req.DynamicDNS)
	query += "enable_dns_server = ?, "
	args = append(args, req.EnableDnsServer)
	query += "dns_server = ?, "
	args = append(args, req.DnsServer)
	if req.HealthCheckPath != "" {
		query += "health_check_path = ?, "
		args = append(args, req.HealthCheckPath)
	}
	if req.HealthCheckInterval > 0 {
		query += "health_check_interval = ?, "
		args = append(args, req.HealthCheckInterval)
	}
	if req.HealthCheckTimeout > 0 {
		query += "health_check_timeout = ?, "
		args = append(args, req.HealthCheckTimeout)
	}
	if req.HealthCheckUnhealthyThreshold > 0 {
		query += "health_check_unhealthy_threshold = ?, "
		args = append(args, req.HealthCheckUnhealthyThreshold)
	}
	if req.HealthCheckHealthyThreshold > 0 {
		query += "health_check_healthy_threshold = ?, "
		args = append(args, req.HealthCheckHealthyThreshold)
	}
	query += "enable_active_health_check = ?, "
	args = append(args, req.EnableActiveHealthCheck)
	if req.HostHeader != "" {
		query += "host_header = ?, "
		args = append(args, req.HostHeader)
	}
	query += "enable_tls = ?, "
	args = append(args, req.EnableTLS)
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
	if req.TLSEmail != "" {
		query += "tls_email = ?, "
		args = append(args, req.TLSEmail)
	}
	query += "tls_http_redirect = ?, "
	args = append(args, req.TLSHTTPRedirect)
	query += "enable_compress = ?, "
	args = append(args, req.EnableCompress)
	if req.CompressTypes != "" {
		query += "compress_types = ?, "
		args = append(args, req.CompressTypes)
	}
	query += "enabled = ?, "
	args = append(args, req.Enabled)

	// Get existing rule's caddy_id for @id-based update
	var existingProtocol, existingDomain string
	var existingListenPort int
	err = db.DB.QueryRow("SELECT COALESCE(caddy_id,''), protocol, COALESCE(domain,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &existingProtocol, &existingDomain, &existingListenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	if caddyID == "" {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Rule has no caddy_id, cannot use @id-based update"})
		return
	}

	// Build full rule config for route generation
	protocol := req.Protocol
	if protocol == "" {
		protocol = existingProtocol
	}
	domain := req.Domain
	if domain == "" {
		domain = existingDomain
	}
	listenPort := req.ListenPort
	if listenPort == 0 {
		listenPort = existingListenPort
	}

	strategy := req.Strategy
	if strategy == "" {
		db.DB.QueryRow("SELECT COALESCE(strategy,'') FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&strategy)
		if strategy == "" {
			strategy = "round_robin"
		}
	}

	upstreams := req.Upstreams
	if len(upstreams) == 0 {
		upstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
				upstreams = append(upstreams, u)
			}
			upstreamRows.Close()
		}
	}

		ruleConfig := services.SingleRuleConfig{
			Protocol:                protocol,
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
			TLSHTTPRedirect:         req.TLSHTTPRedirect,
			EnableCompress:          req.EnableCompress,
			CompressTypes:           req.CompressTypes,
			EnableActiveHealthCheck: req.EnableActiveHealthCheck,
			HostHeader:              req.HostHeader,
			CaddyID:                 caddyID,
		}
	for _, u := range upstreams {
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

	if err := h.caddyService.SetConfigByID(caddyID, routeConfig); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy update failed: " + err.Error()})
		return
	}

	// Verify the route was actually written to Caddy
	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ?"
	args = append(args, userIDInt, caddyID)

	db.DB.Exec(query, args...)

	if len(req.Upstreams) > 0 {
		db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
		for _, u := range req.Upstreams {
			if u.Weight == 0 {
				u.Weight = 1
			}
			if u.Protocol == "" {
				u.Protocol = "http"
			}
			db.DB.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol) 
				VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol)
		}
	}

	// Reload full Caddy config to apply TLS certificates if changed
	if req.EnableTLS || req.TLSCert != "" || req.TLSKey != "" {
		log.Printf("Reloading full Caddy config after rule update for caddy_id=%s", caddyID)
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
		       enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email,
		       tls_http_redirect, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip,zstd'), enabled, created_by,
		       COALESCE(host_header,''), COALESCE(dns_server,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&rule.EnableTLS, &rule.TLSCert, &rule.TLSKey, &rule.TLSAutoCert, &rule.TLSEmail,
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
			enable_tls, tls_cert, tls_key, tls_auto_cert, tls_email,
			tls_http_redirect, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'), ?, ?)
	`, rule.Name+" (Copy)", rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.DnsServer, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableTLS, rule.TLSCert, rule.TLSKey, rule.TLSAutoCert, rule.TLSEmail,
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

	var protocol string
	var listenPort int
	err := db.DB.QueryRow("SELECT COALESCE(protocol,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol, &listenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	if protocol == "http" && listenPort == 80 {
		serverName = "http_80"
	} else if protocol == "https" && listenPort == 443 {
		serverName = "https_443"
	} else if protocol == "http" {
		serverName = fmt.Sprintf("http_%d", listenPort)
	} else if protocol == "https" {
		serverName = fmt.Sprintf("https_%d", listenPort)
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
	}

	if h.caddyService.RouteExistsInServer(serverName, caddyID) {
		db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule enabled"})
		return
	}

	var rule models.LbRule
	err = db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		       COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_auto_cert,0), COALESCE(tls_email,''), COALESCE(tls_http_redirect,0),
		       enabled, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		       COALESCE(enable_active_health_check,0), COALESCE(host_header,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsServer, &rule.DnsFamily, &rule.HealthCheckPath, &rule.HealthCheckInterval,
		&rule.HealthCheckTimeout, &rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&rule.EnableTLS, &rule.TLSCert, &rule.TLSKey, &rule.TLSAutoCert, &rule.TLSEmail,
		&rule.TLSHTTPRedirect, &rule.Enabled, &rule.EnableCompress, &rule.CompressTypes,
		&rule.EnableActiveHealthCheck, &rule.HostHeader,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to get rule"})
		return
	}

	upstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http') FROM upstreams WHERE rule_id = ?", caddyID)
	if upstreamRows != nil {
		for upstreamRows.Next() {
			var u models.Upstream
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol)
			rule.Upstreams = append(rule.Upstreams, u)
		}
		upstreamRows.Close()
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                rule.Protocol,
		Domain:                  rule.Domain,
		ListenPort:              rule.ListenPort,
		Strategy:                rule.Strategy,
		DynamicDNS:              rule.DynamicDNS,
		DnsServer:               rule.DnsServer,
		DnsFamily:               rule.DnsFamily,
		HealthCheckPath:         rule.HealthCheckPath,
		HealthCheckInterval:     rule.HealthCheckInterval,
		HealthCheckTimeout:      rule.HealthCheckTimeout,
		EnableTLS:               rule.EnableTLS,
		TLSHTTPRedirect:         rule.TLSHTTPRedirect,
		EnableCompress:          rule.EnableCompress,
		CompressTypes:           rule.CompressTypes,
		EnableActiveHealthCheck: rule.EnableActiveHealthCheck,
		HostHeader:              rule.HostHeader,
		CaddyID:                 rule.CaddyID,
	}
	for _, u := range rule.Upstreams {
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

	h.caddyService.CreateServerIfNotExists(serverName, listenPort)

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	if err := h.caddyService.PrependRouteToServer(serverName, routeConfig); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to add route to Caddy: %v", err)})
		return
	}

	if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Caddy write verification failed: %v", err)})
		return
	}

	db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule enabled"})
}


func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	err := db.DB.QueryRow("SELECT COALESCE(protocol,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&protocol, &listenPort)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	var serverName string
	if protocol == "http" && listenPort == 80 {
		serverName = "http_80"
	} else if protocol == "https" && listenPort == 443 {
		serverName = "https_443"
	} else if protocol == "http" {
		serverName = fmt.Sprintf("http_%d", listenPort)
	} else if protocol == "https" {
		serverName = fmt.Sprintf("https_%d", listenPort)
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
	}

	db.DB.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)

	if caddyID != "" {
		h.caddyService.RemoveRouteFromServer(serverName, caddyID)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Rule disabled"})
}

