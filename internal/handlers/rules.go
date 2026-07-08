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
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_http_redirect,0),
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
		var tlsCert, tlsKey string
		var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect, enableCompress bool
		var acmeConfigID, caProviderID int
		var createdBy sql.NullInt64
		var createdAt sql.NullTime
		var updatedAt sql.NullTime
		var updatedBy sql.NullInt64
		var tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
		var requestBodyMaxSizeMB, upstreamKeepaliveTimeout, serverTokensHidden int
		err := rows.Scan(&r.CaddyID, &r.Name, &description, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
			&r.HealthCheckPath, &r.HealthCheckInterval,
			&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
			&requestBodyMaxSizeMB, &upstreamKeepaliveTimeout, &serverTokensHidden,
			&enableTLS, &tlsSource, &acmeConfigID, &caProviderID, &tlsCert, &tlsKey, &tlsHTTPRedirect,
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
		r.TCPHealthCheckPort = tcpHealthCheckPort
		r.TCPTryDuration = tcpTryDuration
		r.TCPTryInterval = tcpTryInterval
		r.RequestBodyMaxSizeMB = requestBodyMaxSizeMB
		r.UpstreamKeepaliveTimeout = upstreamKeepaliveTimeout
		r.ServerTokensHidden = serverTokensHidden
		r.EnableTLS = enableTLS
		r.TLSSource = tlsSource
		r.ACMEConfigID = acmeConfigID
		r.TLSCert = tlsCert
		r.TLSKey = tlsKey
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.EnableCompress = enableCompress
		r.CompressTypes = compressTypes
		r.HostHeader = hostHeader
		r.CAProviderID = caProviderID

		upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'') FROM upstreams WHERE rule_id = ?`, r.CaddyID)
		if upstreamRows != nil {
			for upstreamRows.Next() {
				var u models.Upstream
				upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol)
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
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect bool
	var acmeConfigID int
	var tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
	var requestBodyMaxSizeMB, upstreamKeepaliveTimeout, serverTokensHidden int
	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_http_redirect,0),
		       enabled, created_at, updated_at, COALESCE(host_header,''), caddy_id
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
		&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
		&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
		&requestBodyMaxSizeMB, &upstreamKeepaliveTimeout, &serverTokensHidden,
		&enableTLS, &tlsSource, &acmeConfigID, &r.TLSCert, &r.TLSKey, &tlsHTTPRedirect,
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
	r.TCPHealthCheckPort = tcpHealthCheckPort
	r.TCPTryDuration = tcpTryDuration
	r.TCPTryInterval = tcpTryInterval
	r.RequestBodyMaxSizeMB = requestBodyMaxSizeMB
	r.UpstreamKeepaliveTimeout = upstreamKeepaliveTimeout
	r.ServerTokensHidden = serverTokensHidden
	r.EnableTLS = enableTLS
	r.TLSSource = tlsSource
	r.ACMEConfigID = acmeConfigID
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.HostHeader = hostHeader

	upstreamRows, _ := db.DB.Query(`SELECT id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'') FROM upstreams WHERE rule_id = ?`, caddyID)
	if upstreamRows != nil {
		for upstreamRows.Next() {
			var u models.Upstream
			upstreamRows.Scan(&u.ID, &u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol)
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
		EnableActiveHealthCheck       bool
		TCPHealthCheckPort            int
		TCPTryDuration                int
		TCPTryInterval                int
		RequestBodyMaxSizeMB          int
		UpstreamKeepaliveTimeout      int
		ServerTokensHidden            int
		EnableTLS                     bool
		TLSCert                       string
		TLSKey                        string
		TLSHTTPRedirect               bool
		Enabled                       bool
		EnableCompress                bool
		CompressTypes                 string
		HostHeader                    string
		CaddyID                       string
	}

	var domain, strategy, hostHeader, compressTypes, tlsCert, tlsKey string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect, enableCompress bool

	log.Printf("GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''),
		       COALESCE(dns_family,'ipv4'), health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       COALESCE(enable_tls,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		       COALESCE(tls_http_redirect,0),
		       enabled, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
		       COALESCE(host_header,''), COALESCE(caddy_id,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &r.DnsFamily, &r.HealthCheckPath, &r.HealthCheckInterval,
		&r.HealthCheckTimeout, &r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &r.TCPHealthCheckPort, &r.TCPTryDuration, &r.TCPTryInterval,
		&r.RequestBodyMaxSizeMB, &r.UpstreamKeepaliveTimeout, &r.ServerTokensHidden,
		&enableTLS, &tlsCert, &tlsKey, &tlsHTTPRedirect,
		&r.Enabled, &enableCompress, &compressTypes,
		&hostHeader, &r.CaddyID)

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
	r.EnableDnsServer = enableDnsServer
	r.EnableActiveHealthCheck = enableActiveHealthCheck
	r.EnableTLS = enableTLS
	r.TLSCert = tlsCert
	r.TLSKey = tlsKey
	r.TLSHTTPRedirect = tlsHTTPRedirect
	r.EnableCompress = enableCompress
	r.CompressTypes = compressTypes
	r.HostHeader = hostHeader

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(protocol,'http'), enabled, COALESCE(max_connections,0), COALESCE(proxy_protocol,'')
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
		upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &protocol, &enabled, &u.MaxConnections, &u.ProxyProtocol)
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
		"route":                   caddyActualConfig,
		"server_context":          ruleContext["server"],
		"tls_certificates":        ruleContext["tls_certificates"],
		"tls_connection_policies": ruleContext["tls_connection_policies"],
		"automation_policies":     ruleContext["automation_policies"],
	}
	responseData["config_not_exists"] = false
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: responseData})
}

// buildRuleCaddyContext extracts the server and TLS context relevant to a rule from the full Caddy config.
func buildRuleCaddyContext(fullConfig map[string]interface{}, caddyID string, listenPort int) map[string]interface{} {
	result := map[string]interface{}{
		"server":                  nil,
		"tls_certificates":        []interface{}{},
		"tls_connection_policies": []interface{}{},
		"automation_policies":     []interface{}{},
	}

	apps, _ := fullConfig["apps"].(map[string]interface{})
	if apps == nil {
		return result
	}

	// Search HTTP servers first
	if httpApp, ok := apps["http"].(map[string]interface{}); ok {
		if servers, ok := httpApp["servers"].(map[string]interface{}); ok {
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
		}
	}

	// If not found in HTTP app, search the layer4 app for TCP rules
	if result["server"] == nil {
		if layer4App, ok := apps["layer4"].(map[string]interface{}); ok {
			if servers, ok := layer4App["servers"].(map[string]interface{}); ok {
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
								"server_name": serverName,
								"listen":      server["listen"],
							}
							break
						}
					}
				}
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

	// Validate ACME domain restrictions
	if req.EnableTLS && req.TLSSource == "acme_dns" && req.Domain != "" {
		if err := services.ValidateACMEDomains(req.Domain); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	if err := h.validatePort(req.Protocol, req.ListenPort, ""); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Domain uniqueness: HTTP/HTTPS rules cannot share the same domain.
	if req.Protocol == "http" && req.Domain != "" {
		var existing int
		err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE protocol = 'http' AND domain = ?", req.Domain).Scan(&existing)
		if err == nil && existing > 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
			return
		}
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
			serverName = "http_443"
		} else if req.ListenPort == 80 {
			serverName = "http_80"
		} else if req.EnableTLS {
			serverName = fmt.Sprintf("http_%d", req.ListenPort)
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
		Protocol:                      req.Protocol,
		Domain:                        req.Domain,
		ListenPort:                    listenPort,
		Strategy:                      req.Strategy,
		DynamicDNS:                    req.DynamicDNS,
		EnableDnsServer:               req.EnableDnsServer,
		DnsServer:                     req.DnsServer,
		DnsFamily:                     req.DnsFamily,
		HealthCheckPath:               req.HealthCheckPath,
		HealthCheckInterval:           req.HealthCheckInterval,
		HealthCheckTimeout:            req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:       req.EnableActiveHealthCheck,
		TCPHealthCheckPort:            req.TCPHealthCheckPort,
		TCPTryDuration:                req.TCPTryDuration,
		TCPTryInterval:                req.TCPTryInterval,
		RequestBodyMaxSizeMB:          req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:      req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:            req.ServerTokensHidden,
		EnableTLS:                     req.EnableTLS,
		TLSSource:                     req.TLSSource,
		ACMEConfigID:                  req.ACMEConfigID,
		TLSHTTPRedirect:               req.TLSHTTPRedirect,
		EnableCompress:                req.EnableCompress,
		CompressTypes:                 req.CompressTypes,
		HostHeader:                    req.HostHeader,
		CaddyID:                       caddyID,
	}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if req.Protocol == "tcp" {
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
			MaxConnections: u.MaxConnections, ProxyProtocol: u.ProxyProtocol,
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
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_at, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.TCPHealthCheckPort, req.TCPTryDuration, req.TCPTryInterval,
		req.RequestBodyMaxSizeMB, req.UpstreamKeepaliveTimeout, req.ServerTokensHidden,
		req.HostHeader, req.EnableTLS, req.TLSSource, req.ACMEConfigID, req.CAProviderID, req.TLSCert, req.TLSKey,
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
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		_, err = tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, max_connections, proxy_protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections, u.ProxyProtocol)
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
	if req.Protocol == "tcp" {
		fullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
			log.Printf("CreateRule Caddy apply failed for TCP rule caddy_id=%s: %v, rolling back database", caddyID, err)
			db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
			db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy apply failed: " + err.Error()})
			return
		}
	} else {
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

		// Reload full Caddy config to apply TLS certificates
		if req.EnableTLS {
			log.Printf("Reloading full Caddy config to apply TLS for caddy_id=%s", caddyID)
			go func() {
				fullConfig := services.GenerateCaddyConfig(h.cfg)
				if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
					log.Printf("Failed to reload Caddy config after rule creation: %v", err)
				}
			}()
			// Trigger ACME issuance synchronously so failures are surfaced
			if req.TLSSource == "acme_dns" && req.Domain != "" {
				qm := services.GetCAQueueManager()
				if qm == nil {
					log.Printf("Auto cert enqueue failed for %s: CA queue manager not initialized", req.Domain)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA queue manager not initialized"})
					return
				}
				log.Printf("CreateRule enqueueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, req.Domain, req.CAProviderID)
				if err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
					log.Printf("Auto cert enqueue failed for %s: %v", req.Domain, err)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to enqueue certificate job: " + err.Error()})
					return
				}
			}
		}
	}

	log.Printf("Rule created with caddy_id=%s", caddyID)
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

	// Validate ACME domain restrictions
	if req.EnableTLS && req.TLSSource == "acme_dns" && req.Domain != "" {
		if err := services.ValidateACMEDomains(req.Domain); err != nil {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
			return
		}
	}

	// Domain uniqueness: HTTP/HTTPS rules cannot share the same domain (excluding current rule).
	if req.Protocol == "http" && req.Domain != "" {
		var existing int
		err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE protocol = 'http' AND domain = ? AND caddy_id != ?", req.Domain, caddyID).Scan(&existing)
		if err == nil && existing > 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "域名已被其他 HTTP/HTTPS 规则使用"})
			return
		}
	}

	log.Printf("UpdateRule request for caddy_id=%s: enable_tls=%v, tls_source=%s, ca_provider_id=%v, cert_len=%d, key_len=%d",
		caddyID, req.EnableTLS, req.TLSSource, func() interface{} {
			if req.CAProviderID == nil {
				return "<nil>"
			}
			return *req.CAProviderID
		}(), len(req.TLSCert), len(req.TLSKey))

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
		// Allow HTTP (80) -> HTTPS (443) upgrade when enabling TLS.
		isHTTPUpgrade := currentPort == 80 && req.ListenPort == 443 && req.EnableTLS
		if currentPort != req.ListenPort && !isHTTPUpgrade {
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
			validationServerName = "http_443"
		} else if validationPort == 80 {
			validationServerName = "http_80"
		} else if validationEnableTLS {
			validationServerName = fmt.Sprintf("http_%d", validationPort)
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
			COALESCE(ca_provider_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
			COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
			COALESCE(host_header,''), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'),
			COALESCE(enabled,1), name, description
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(
		&existingRule.Protocol, &existingRule.Domain, &existingRule.ListenPort, &existingRule.Strategy,
		&existingRule.TLSCert, &existingRule.TLSKey, &existingRule.TLSSource, &existingRule.ACMEConfigID,
		&existingRule.CAProviderID,
		&existingRule.EnableTLS, &existingRule.TLSHTTPRedirect,
		&existingRule.DynamicDNS, &existingRule.EnableDnsServer, &existingRule.DnsServer, &existingRule.DnsFamily,
		&existingRule.HealthCheckPath, &existingRule.HealthCheckInterval, &existingRule.HealthCheckTimeout,
		&existingRule.HealthCheckUnhealthyThreshold, &existingRule.HealthCheckHealthyThreshold,
		&existingRule.EnableActiveHealthCheck, &existingRule.TCPHealthCheckPort, &existingRule.TCPTryDuration, &existingRule.TCPTryInterval,
		&existingRule.RequestBodyMaxSizeMB, &existingRule.UpstreamKeepaliveTimeout, &existingRule.ServerTokensHidden,
		&existingRule.HostHeader, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	// Capture old upstreams for potential DB rollback
	var oldUpstreams []models.Upstream
	oldUpstreamRows, _ := db.DB.Query("SELECT host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'') FROM upstreams WHERE rule_id = ?", caddyID)
	if oldUpstreamRows != nil {
		for oldUpstreamRows.Next() {
			var u models.Upstream
			oldUpstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol)
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
	if req.TCPHealthCheckPort == 0 {
		req.TCPHealthCheckPort = existingRule.TCPHealthCheckPort
	}
	if req.TCPTryDuration == 0 {
		req.TCPTryDuration = existingRule.TCPTryDuration
	}
	if req.TCPTryInterval == 0 {
		req.TCPTryInterval = existingRule.TCPTryInterval
	}
	if req.RequestBodyMaxSizeMB == 0 {
		req.RequestBodyMaxSizeMB = existingRule.RequestBodyMaxSizeMB
	}
	if req.UpstreamKeepaliveTimeout == 0 {
		req.UpstreamKeepaliveTimeout = existingRule.UpstreamKeepaliveTimeout
	}
	if req.ServerTokensHidden == 0 {
		req.ServerTokensHidden = existingRule.ServerTokensHidden
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
	if err := h.validatePort(req.Protocol, req.ListenPort, caddyID); err != nil {
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
	query += "tcp_health_check_port = ?, "
	args = append(args, req.TCPHealthCheckPort)
	query += "tcp_try_duration = ?, "
	args = append(args, req.TCPTryDuration)
	query += "tcp_try_interval = ?, "
	args = append(args, req.TCPTryInterval)
	query += "request_body_max_size_mb = ?, "
	args = append(args, req.RequestBodyMaxSizeMB)
	query += "upstream_keepalive_timeout = ?, "
	args = append(args, req.UpstreamKeepaliveTimeout)
	query += "server_tokens_hidden = ?, "
	args = append(args, req.ServerTokensHidden)
	query += "host_header = ?, "
	args = append(args, req.HostHeader)
	query += "enable_tls = ?, "
	args = append(args, req.EnableTLS)
	query += "tls_source = ?, "
	args = append(args, req.TLSSource)
	query += "acme_config_id = ?, "
	args = append(args, req.ACMEConfigID)
	if req.CAProviderID != nil {
		query += "ca_provider_id = ?, "
		args = append(args, *req.CAProviderID)
	}
	if req.TLSCert != "" {
		query += "tls_cert = ?, "
		args = append(args, req.TLSCert)
	}
	if req.TLSKey != "" {
		query += "tls_key = ?, "
		args = append(args, req.TLSKey)
	}
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
		Protocol:                      req.Protocol,
		Domain:                        domain,
		ListenPort:                    listenPort,
		Strategy:                      strategy,
		DynamicDNS:                    req.DynamicDNS,
		EnableDnsServer:               req.EnableDnsServer,
		DnsServer:                     req.DnsServer,
		DnsFamily:                     req.DnsFamily,
		HealthCheckPath:               req.HealthCheckPath,
		HealthCheckInterval:           req.HealthCheckInterval,
		HealthCheckTimeout:            req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold: req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:       req.EnableActiveHealthCheck,
		TCPHealthCheckPort:            req.TCPHealthCheckPort,
		TCPTryDuration:                req.TCPTryDuration,
		TCPTryInterval:                req.TCPTryInterval,
		RequestBodyMaxSizeMB:          req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:      req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:            req.ServerTokensHidden,
		EnableTLS:                     req.EnableTLS,
		TLSSource:                     req.TLSSource,
		ACMEConfigID:                  req.ACMEConfigID,
		TLSHTTPRedirect:               req.TLSHTTPRedirect,
		EnableCompress:                req.EnableCompress,
		CompressTypes:                 req.CompressTypes,
		HostHeader:                    req.HostHeader,
		CaddyID:                       caddyID,
	}
	for _, u := range req.Upstreams {
		protocol := u.Protocol
		if protocol == "" {
			if req.Protocol == "tcp" {
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
			MaxConnections: u.MaxConnections, ProxyProtocol: u.ProxyProtocol,
		})
	}

	routeConfig, err := services.GenerateRouteObject(ruleConfig)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Failed to generate route config: " + err.Error()})
		return
	}

	// Backup current full Caddy config for rollback (used for TCP rules; HTTP rules use @id-based rollback)
	oldFullConfig := services.GenerateCaddyConfig(h.cfg)

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
	query += "updated_at = datetime('now'), updated_by = ? WHERE caddy_id = ? AND NOT EXISTS (SELECT 1 FROM cert_jobs WHERE rule_id = ? AND status NOT IN ('issued','failed'))"
	args = append(args, userIDInt, caddyID, caddyID)

	res, err := tx.Exec(query, args...)
	if err != nil {
		tx.Rollback()
		log.Printf("UpdateRule database error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to update rule"})
		return
	}
	rowsAffected, _ := res.RowsAffected()
	log.Printf("UpdateRule executed for caddy_id=%s: rows_affected=%d ca_provider_id_included=%v", caddyID, rowsAffected, req.CAProviderID != nil)
	if rowsAffected == 0 {
		tx.Rollback()
		c.JSON(http.StatusConflict, models.APIResponse{Code: 409, Message: "证书申请中，请等待完成或失败后再修改规则"})
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
			if req.Protocol == "tcp" {
				u.Protocol = "tcp"
			} else {
				u.Protocol = "http"
			}
		}
		if _, err := tx.Exec(`INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, max_connections, proxy_protocol) 
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			caddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections, u.ProxyProtocol); err != nil {
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

	// If the domain or CA provider changed for an ACME rule, re-queue issuance.
	// We do NOT delete the existing cert_job row: cert_pem/key_pem are kept so
	// Caddy can continue serving the old certificate until the new one is issued.
	caProviderID := existingRule.CAProviderID
	if req.CAProviderID != nil {
		caProviderID = *req.CAProviderID
	}
	domainChanged := req.EnableTLS && req.TLSSource == "acme_dns" && domain != "" && domain != existingRule.Domain
	caProviderChanged := req.EnableTLS && req.TLSSource == "acme_dns" && domain != "" && caProviderID != existingRule.CAProviderID
	if domainChanged || caProviderChanged {
		log.Printf("UpdateRule ACME change for caddy_id=%s: domainChanged=%v caProviderChanged=%v oldCA=%d newCA=%d", caddyID, domainChanged, caProviderChanged, existingRule.CAProviderID, caProviderID)
		go func() {
			qm := services.GetCAQueueManager()
			if qm == nil {
				log.Printf("Auto cert enqueue failed for %s: CA queue manager not initialized", domain)
				return
			}
			log.Printf("UpdateRule re-queueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, domain, caProviderID)
			if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
				log.Printf("Auto cert re-queue failed for %s: %v", domain, err)
			}
		}()
	}

	// Apply Caddy changes after DB commit; restore previous Caddy config on failure
	if req.Protocol == "tcp" {
		newFullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(newFullConfig); err != nil {
			if oldFullConfig != nil {
				if restoreErr := h.caddyService.ApplyConfig(oldFullConfig); restoreErr != nil {
					log.Printf("UpdateRule failed to restore previous Caddy config for caddy_id=%s: %v", caddyID, restoreErr)
				}
			}
			log.Printf("UpdateRule Caddy update failed for TCP rule caddy_id=%s: %v, restored previous config", caddyID, err)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy update failed: " + err.Error()})
			return
		}
	} else {
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

		// Reload full Caddy config to apply TLS certificates
		if req.EnableTLS || req.TLSCert != "" || req.TLSKey != "" || req.TLSSource == "acme_dns" {
			log.Printf("Reloading full Caddy config after rule update for caddy_id=%s", caddyID)
			fullConfig := services.GenerateCaddyConfig(h.cfg)
			if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
				log.Printf("Failed to reload Caddy config after rule update: %v", err)
			}
			// Trigger ACME issuance if needed
			if req.TLSSource == "acme_dns" && req.EnableTLS && domain != "" {
				if !services.IsACMECertIssued(caddyID, domain) {
					go func() {
						qm := services.GetCAQueueManager()
						if qm == nil {
							log.Printf("Auto cert enqueue failed for %s: CA queue manager not initialized", domain)
							return
						}
						caProviderID := existingRule.CAProviderID
						if req.CAProviderID != nil {
							caProviderID = *req.CAProviderID
						}
						if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
							log.Printf("Auto cert enqueue failed for %s: %v", domain, err)
						}
					}()
				}
			}
		}

		// Handle re-enabling an ACME rule or switching its TLS source to ACME DNS
		// when no cert job row exists yet (any status). Existing rows are left
		// alone since the ON CONFLICT and queue/renewal logic handle the rest.
		wasReEnabled := !existingRule.Enabled && req.Enabled
		tlsSourceChangedToACME := existingRule.TLSSource != "acme_dns" && req.TLSSource == "acme_dns"
		if (wasReEnabled || tlsSourceChangedToACME) && req.EnableTLS && req.TLSSource == "acme_dns" && domain != "" {
			if !services.HasCertJob(caddyID, domain) {
				go func() {
					qm := services.GetCAQueueManager()
					if qm == nil {
						log.Printf("Auto cert enqueue failed for %s: CA queue manager not initialized", domain)
						return
					}
					caProviderID := existingRule.CAProviderID
					if req.CAProviderID != nil {
						caProviderID = *req.CAProviderID
					}
					if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
						log.Printf("Auto cert enqueue failed for %s: %v", domain, err)
					}
				}()
			}
		}
	}

	log.Printf("Rule %s updated", caddyID)
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

	// Delete all related rows in a single transaction so that certificate jobs
	// and their logs are never left as orphans.
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to start database transaction"})
		return
	}

	if _, err := tx.Exec("DELETE FROM cert_job_logs WHERE job_id IN (SELECT id FROM cert_jobs WHERE rule_id = ?)", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule cert_job_logs delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete certificate job logs"})
		return
	}
	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule cert_jobs delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete certificate jobs"})
		return
	}
	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule upstreams delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete upstreams"})
		return
	}
	if _, err := tx.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule metrics_history delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete metrics history"})
		return
	}
	if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule lb_rules delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to delete rule"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("DeleteRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to commit rule deletion"})
		return
	}

	var serverName string
	var serverPort int
	if protocol == "http" {
		if enableTLS && listenPort == 443 {
			serverName = "http_443"
			serverPort = 443
		} else if listenPort == 80 {
			serverName = "http_80"
			serverPort = 80
		} else if enableTLS {
			serverName = fmt.Sprintf("http_%d", listenPort)
			serverPort = listenPort
		} else {
			serverName = fmt.Sprintf("http_%d", listenPort)
			serverPort = listenPort
		}
	} else {
		serverName = fmt.Sprintf("tcp_%d", listenPort)
		serverPort = listenPort
	}

	// Remove route from HTTP server and clean up empty HTTP servers. TCP rules are managed
	// by full config regeneration because they live in the layer4 app.
	if protocol == "http" {
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
	}

	// Reload full Caddy config to clean up TLS certificates and layer4 servers
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
	var enableActiveHealthCheck bool
	var tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
	err := db.DB.QueryRow(`
		SELECT caddy_id, name, protocol, domain, listen_port, strategy, dynamic_dns,
		       health_check_path, health_check_interval, health_check_timeout,
		       health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       enable_tls, COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), tls_cert, tls_key,
		       tls_http_redirect, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip,zstd'), enabled, created_by,
		       COALESCE(host_header,''), COALESCE(dns_server,'')
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout,
		&rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
		&rule.RequestBodyMaxSizeMB, &rule.UpstreamKeepaliveTimeout, &rule.ServerTokensHidden,
		&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.TLSCert, &rule.TLSKey,
		&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.CreatedBy,
		&rule.HostHeader, &rule.DnsServer,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "Rule not found"})
		return
	}

	rule.EnableActiveHealthCheck = enableActiveHealthCheck
	rule.TCPHealthCheckPort = tcpHealthCheckPort
	rule.TCPTryDuration = tcpTryDuration
	rule.TCPTryInterval = tcpTryInterval

	userID, _ := c.Get("user_id")

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to generate caddy ID"})
		return
	}

	now := time.Now()
	result, err := db.DB.Exec(`
		INSERT INTO lb_rules (name, protocol, domain, listen_port, strategy, dynamic_dns, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			enable_tls, tls_source, acme_config_id, tls_cert, tls_key,
			tls_http_redirect, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, caddy_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.Name+" (Copy)", rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.DnsServer, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPTryDuration, rule.TCPTryInterval,
		rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden,
		rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.TLSCert, rule.TLSKey,
		rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, 0, userID, userID,
		now, now, rule.HostHeader, newCaddyID,
	)
	if err != nil {
		log.Printf("Failed to duplicate rule %s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "Failed to duplicate rule: " + err.Error()})
		return
	}

	_ = result

	db.DB.Exec("UPDATE lb_rules SET updated_by = ? WHERE caddy_id = ?", userID, newCaddyID)

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, weight, domain, dynamic_dns, enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'')
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err == nil {
		for upstreamRows.Next() {
			var u struct {
				Host           string
				Port           int
				Weight         int
				Domain         string
				DynamicDNS     bool
				Enabled        bool
				Protocol       string
				MaxConnections int
				ProxyProtocol  string
			}
			upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol)
			db.DB.Exec(`
				INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, max_connections, proxy_protocol)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			`, newCaddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections, u.ProxyProtocol)
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

	// Queue an ACME certificate job if the rule uses ACME DNS TLS and no
	// cert job row exists yet for it (any status). Existing rows are left
	// alone since the ON CONFLICT and queue/renewal logic handle the rest.
	var domain, tlsSource string
	var enableTLS bool
	var caProviderID int
	if err := db.DB.QueryRow(`
		SELECT COALESCE(domain,''), COALESCE(tls_source,''), COALESCE(enable_tls,0), COALESCE(ca_provider_id,0)
		FROM lb_rules WHERE caddy_id = ?`, caddyID).Scan(&domain, &tlsSource, &enableTLS, &caProviderID); err == nil {
		log.Printf("EnableRule TLS state for caddy_id=%s: enableTLS=%v tlsSource=%s domain=%s caProviderID=%d", caddyID, enableTLS, tlsSource, domain, caProviderID)
		hasCertJob := services.HasCertJob(caddyID, domain)
		log.Printf("EnableRule HasCertJob for caddy_id=%s domain=%s: %v", caddyID, domain, hasCertJob)
		if enableTLS && tlsSource == "acme_dns" && domain != "" && !hasCertJob {
			qm := services.GetCAQueueManager()
			log.Printf("EnableRule GetCAQueueManager for caddy_id=%s: nil=%v", caddyID, qm == nil)
			if qm == nil {
				log.Printf("Auto cert enqueue failed for %s after enable: CA queue manager not initialized", domain)
			} else if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
				log.Printf("EnableRule CreateOrRequeueCertJob for caddy_id=%s domain=%s caProviderID=%d error: %v", caddyID, domain, caProviderID, err)
			} else {
				log.Printf("EnableRule CreateOrRequeueCertJob for caddy_id=%s domain=%s caProviderID=%d succeeded", caddyID, domain, caProviderID)
			}
		}
	} else {
		log.Printf("EnableRule failed to read rule TLS state for caddy_id=%s: %v", caddyID, err)
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
