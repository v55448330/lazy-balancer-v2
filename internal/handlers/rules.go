package handlers

import (
	"database/sql"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
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
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
		       COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
		       COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_http_redirect,0),
		       COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), enabled, created_by, created_at, updated_at, updated_by,
		       COALESCE(host_header,''),
		       COALESCE(log_enabled,0)
		FROM lb_rules ORDER BY id
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "数据库错误"})
		return
	}
	defer rows.Close()

	var rules []models.LbRule
	for rows.Next() {
		var r models.LbRule
		var domain, strategy, description, compressTypes, hostHeader, dnsFamily, tlsSource, ipACLListJSON string
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
			&r.IPACLMode, &ipACLListJSON, &r.CustomRoutesEnabled,
			&r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout, &r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout,
			&enableTLS, &tlsSource, &acmeConfigID, &caProviderID, &tlsCert, &tlsKey, &tlsHTTPRedirect,
			&enableCompress, &compressTypes, &r.Enabled, &createdBy, &createdAt, &updatedAt, &updatedBy,
			&hostHeader, &r.LogEnabled)
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
			r.Strategy = "weighted_round_robin"
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
		ipACLList, err := decodeIPACLList(ipACLListJSON)
		if err != nil {
			log.Printf("ListRules invalid ip_acl_list for caddy_id=%s: %v", r.CaddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 IP 访问控制列表失败"})
			return
		}
		r.IPACLList = ipACLList
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
		pathRules, err := loadPathRules(c.Request.Context(), db.DB, r.CaddyID)
		if err != nil {
			log.Printf("ListRules failed to load path_rules for caddy_id=%s: %v", r.CaddyID, err)
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
			return
		}
		r.PathRules = pathRules

		rules = append(rules, r)
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: rules})
}

func (h *Handlers) GetRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r models.LbRule
	var domain, strategy, hostHeader, dnsFamily, tlsSource, ipACLListJSON string
	var dynamicDNS, enableDnsServer, enableActiveHealthCheck, enableTLS, tlsHTTPRedirect bool
	var acmeConfigID, caProviderID int
	var tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
	var requestBodyMaxSizeMB, upstreamKeepaliveTimeout, serverTokensHidden int
	err := db.DB.QueryRow(`
		SELECT name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
		       COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
	       COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
	       COALESCE(tls_http_redirect,0),
	       enabled, created_at, updated_at, COALESCE(host_header,''), caddy_id
	FROM lb_rules WHERE caddy_id = ?
`, caddyID).Scan(&r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
		&dynamicDNS, &enableDnsServer, &r.DnsServer, &dnsFamily,
		&r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
		&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
		&requestBodyMaxSizeMB, &upstreamKeepaliveTimeout, &serverTokensHidden,
		&r.IPACLMode, &ipACLListJSON, &r.CustomRoutesEnabled,
		&r.ProxyDialTimeout, &r.ProxyResponseHeaderTimeout, &r.ProxyReadTimeout, &r.ProxyWriteTimeout, &r.ProxyStreamTimeout,
		&enableTLS, &tlsSource, &acmeConfigID, &caProviderID, &r.TLSCert, &r.TLSKey, &tlsHTTPRedirect,
		&r.Enabled, &r.CreatedAt, &r.UpdatedAt, &hostHeader, &r.CaddyID)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	if err != nil {
		log.Printf("GetRule scan error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}

	r.Domain = domain
	r.Strategy = strategy
	if r.Strategy == "" {
		r.Strategy = "weighted_round_robin"
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
	ipACLList, err := decodeIPACLList(ipACLListJSON)
	if err != nil {
		log.Printf("GetRule invalid ip_acl_list for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 IP 访问控制列表失败"})
		return
	}
	r.IPACLList = ipACLList
	r.EnableTLS = enableTLS
	r.TLSSource = tlsSource
	r.ACMEConfigID = acmeConfigID
	r.CAProviderID = caProviderID
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
	pathRules, err := loadPathRules(c.Request.Context(), db.DB, caddyID)
	if err != nil {
		log.Printf("GetRule failed to load path_rules for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
		return
	}
	r.PathRules = pathRules

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: r})
}

func (h *Handlers) GetRuleCaddyConfig(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var r struct {
		CaddyID    string
		ListenPort int
		Enabled    bool
	}

	log.Printf("GetRuleCaddyConfig: querying rule caddy_id=%s", caddyID)

	err := db.DB.QueryRow(`
		SELECT COALESCE(caddy_id,''), listen_port, COALESCE(enabled,0)
		FROM lb_rules WHERE caddy_id = ?
	`, caddyID).Scan(&r.CaddyID, &r.ListenPort, &r.Enabled)

	if err == sql.ErrNoRows {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	if err != nil {
		log.Printf("GetRuleCaddyConfig: query/scan error for rule caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取规则失败: " + err.Error()})
		return
	}

	upstreamRows, err := db.DB.Query(`
		SELECT host, port, COALESCE(weight,1), COALESCE(protocol,'http'), enabled, COALESCE(max_connections,0), COALESCE(proxy_protocol,'')
		FROM upstreams WHERE rule_id = ? AND enabled = 1
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "获取上游服务器失败"})
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

	log.Printf("GetRuleCaddyConfig: caddyID=%s, port=%d, upstreams=%d, enabled=%v",
		r.CaddyID, r.ListenPort, len(ups), r.Enabled)

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
		switch v := certs["load_files"].(type) {
		case []interface{}:
			certList = v
		case []map[string]interface{}:
			for _, c := range v {
				certList = append(certList, c)
			}
		}
		if certList == nil {
			switch v := certs["load_pem"].(type) {
			case []interface{}:
				certList = v
			case []map[string]interface{}:
				for _, c := range v {
					certList = append(certList, c)
				}
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

	var req models.CreateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		body, _ := io.ReadAll(c.Request.Body)
		log.Printf("CreateRule bind error: %v, body: %s", err, string(body))
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("Invalid request: %v", err)})
		return
	}
	log.Printf("CreateRule bind success: name=%s, protocol=%s, port=%d, upstreams=%d", req.Name, req.Protocol, req.ListenPort, len(req.Upstreams))

	if req.Name == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "名称不能为空"})
		return
	}
	if req.Protocol == "" {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "协议不能为空"})
		return
	}
	// When TLS is enabled for HTTP, default the listen port to 443 unless the user explicitly set another port.
	if req.Protocol == "http" && req.EnableTLS && req.ListenPort == 0 {
		req.ListenPort = 443
	}

	if req.ListenPort <= 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "监听端口必须大于 0"})
		return
	}

	if len(req.Upstreams) == 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "至少需要一个上游服务器"})
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
		req.Strategy = "weighted_round_robin"
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
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
			return
		}
	}

	if req.CompressTypes == "" {
		req.CompressTypes = "gzip"
	}

	if req.RequestBodyMaxSizeMB < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体大小限制不能为负数"})
		return
	}
	if req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden < 0 || req.ServerTokensHidden > 2 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := createRuleFeatures(req)
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	ipACLListJSON, err := encodeIPACLList(features.IPACLList)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	var global struct {
		requestBodyMaxSizeMB, upstreamKeepaliveTimeout                                                        int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		serverTokensHidden                                                                                    bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout,
		&global.serverTokensHidden); err != nil {
		log.Printf("CreateRule failed to load global config: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取全局配置失败"})
		return
	}

	// Build route config for Caddy validation (using request data before DB write)
	ruleConfig := services.SingleRuleConfig{
		Protocol:                         req.Protocol,
		Domain:                           req.Domain,
		ListenPort:                       listenPort,
		Strategy:                         req.Strategy,
		DynamicDNS:                       req.DynamicDNS,
		EnableDnsServer:                  req.EnableDnsServer,
		DnsServer:                        req.DnsServer,
		DnsFamily:                        req.DnsFamily,
		HealthCheckPath:                  req.HealthCheckPath,
		HealthCheckInterval:              req.HealthCheckInterval,
		HealthCheckTimeout:               req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold:    req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:          req.EnableActiveHealthCheck,
		TCPHealthCheckPort:               req.TCPHealthCheckPort,
		TCPTryDuration:                   req.TCPTryDuration,
		TCPTryInterval:                   req.TCPTryInterval,
		RequestBodyMaxSizeMB:             req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:         req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:               req.ServerTokensHidden,
		GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
		GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
		GlobalServerTokensHidden:         global.serverTokensHidden,
		IPACLMode:                        features.IPACLMode,
		IPACLList:                        features.IPACLList,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
		EnableTLS:                        req.EnableTLS,
		TLSSource:                        req.TLSSource,
		ACMEConfigID:                     req.ACMEConfigID,
		TLSHTTPRedirect:                  req.TLSHTTPRedirect,
		EnableCompress:                   req.EnableCompress,
		CompressTypes:                    req.CompressTypes,
		HostHeader:                       req.HostHeader,
		CaddyID:                          caddyID,
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
	if err := h.validateCaddyConfigBeforeSave(req, features, "new_"+generateRandomString(8), serverName); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}

	// Start DB transaction: persist validated config before applying to Caddy
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}

	_, err = tx.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			ip_acl_mode, ip_acl_list, custom_routes_enabled,
			proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout,
			host_header, enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key, tls_http_redirect,
			enable_compress, compress_types, enabled, created_by, updated_at, caddy_id, log_enabled)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.Name, req.Description, req.Protocol, req.Domain, req.ListenPort, req.Strategy, req.DynamicDNS, req.EnableDnsServer, req.DnsServer,
		req.HealthCheckPath, req.HealthCheckInterval, req.HealthCheckTimeout,
		req.HealthCheckUnhealthyThreshold, req.HealthCheckHealthyThreshold,
		req.EnableActiveHealthCheck, req.TCPHealthCheckPort, req.TCPTryDuration, req.TCPTryInterval,
		req.RequestBodyMaxSizeMB, req.UpstreamKeepaliveTimeout, req.ServerTokensHidden,
		features.IPACLMode, ipACLListJSON, features.CustomRoutesEnabled,
		features.ProxyDialTimeout, features.ProxyResponseHeaderTimeout, features.ProxyReadTimeout, features.ProxyWriteTimeout, features.ProxyStreamTimeout,
		req.HostHeader, req.EnableTLS, req.TLSSource, req.ACMEConfigID, req.CAProviderID, req.TLSCert, req.TLSKey,
		req.TLSHTTPRedirect, req.EnableCompress, req.CompressTypes, 1, userIDInt, time.Now().UTC().Format("2006-01-02 15:04:05"), caddyID, req.LogEnabled)

	if err != nil {
		tx.Rollback()
		log.Printf("CreateRule database error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建规则失败"})
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
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建上游服务器失败"})
			return
		}
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		log.Printf("CreateRule path_rules replace error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建自定义路径规则失败"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("CreateRule transaction commit error: %v", err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则失败"})
		return
	}

	// Apply Caddy config after DB commit; rollback DB on Caddy failure
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if req.Protocol == "tcp" {
		fullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(fullConfig); err != nil {
			log.Printf("CreateRule Caddy apply failed for TCP rule caddy_id=%s: %v, rolling back database", caddyID, err)
			db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
			db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置应用失败: " + err.Error()})
			return
		}
	} else {
		routeConfig, err := services.GenerateRouteObject(ruleConfig)
		if err != nil {
			log.Printf("CreateRule failed to generate route config for caddy_id=%s: %v, rolling back database", caddyID, err)
			db.DB.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID)
			db.DB.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID)
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "路由配置生成失败: " + err.Error()})
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
			if req.TLSSource == "acme_dns" && req.Protocol == "http" && req.Domain != "" {
				qm := services.GetCAQueueManager()
				if qm == nil {
					log.Printf("Auto cert enqueue failed for %s: CA queue manager not initialized", req.Domain)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化"})
					return
				}
				log.Printf("CreateRule enqueueing cert job for caddy_id=%s domain=%s ca_provider_id=%d", caddyID, req.Domain, req.CAProviderID)
				if err := services.CreateOrRequeueCertJob(caddyID, req.Domain, req.CAProviderID, qm); err != nil {
					log.Printf("Auto cert enqueue failed for %s: %v", req.Domain, err)
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建证书签发任务失败: " + err.Error()})
					return
				}
			}
		}
	}

	log.Printf("Rule created with caddy_id=%s", caddyID)
	recordAudit(c, "创建", "负载均衡规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), fmt.Sprintf("端口：%d", req.ListenPort), req.Domain))
	recordAudit(c, "重载", "Caddy配置", services.FormatAuditDetail(services.AuditSourcePart("rule_create"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "规则已创建", Data: gin.H{"caddy_id": caddyID}})
}

func (h *Handlers) UpdateRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	var req models.UpdateRuleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		log.Printf("UpdateRule bind error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "无效的请求: " + err.Error()})
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
			c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
			return
		}
		// Allow HTTP (80) -> HTTPS (443) upgrade when enabling TLS.
		isHTTPUpgrade := currentPort == 80 && req.ListenPort == 443 && req.EnableTLS
		if currentPort != req.ListenPort && !isHTTPUpgrade {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口创建后不能修改"})
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
	var existingIPACLListJSON string
	err := db.DB.QueryRow(`
		SELECT COALESCE(protocol,''), COALESCE(domain,''), listen_port, COALESCE(strategy,'weighted_round_robin'),
			COALESCE(tls_cert,''), COALESCE(tls_key,''), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0),
			COALESCE(ca_provider_id,0),
			COALESCE(enable_tls,0), COALESCE(tls_http_redirect,0),
			COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
			COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5),
			COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
			COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
			COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
			COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
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
		&existingRule.IPACLMode, &existingIPACLListJSON, &existingRule.CustomRoutesEnabled,
		&existingRule.ProxyDialTimeout, &existingRule.ProxyResponseHeaderTimeout, &existingRule.ProxyReadTimeout, &existingRule.ProxyWriteTimeout, &existingRule.ProxyStreamTimeout,
		&existingRule.HostHeader, &existingRule.EnableCompress, &existingRule.CompressTypes,
		&existingRule.Enabled, &existingRule.Name, &existingRule.Description)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}
	existingRule.IPACLList, err = decodeIPACLList(existingIPACLListJSON)
	if err != nil {
		log.Printf("UpdateRule invalid ip_acl_list for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取 IP 访问控制列表失败"})
		return
	}
	existingRule.PathRules, err = loadPathRules(c.Request.Context(), db.DB, caddyID)
	if err != nil {
		log.Printf("UpdateRule failed to load path_rules for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取自定义路径规则失败"})
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
	if req.RequestBodyMaxSizeMB == nil {
		req.RequestBodyMaxSizeMB = &existingRule.RequestBodyMaxSizeMB
	}
	if req.UpstreamKeepaliveTimeout == nil {
		req.UpstreamKeepaliveTimeout = &existingRule.UpstreamKeepaliveTimeout
	}
	if req.ServerTokensHidden == nil {
		req.ServerTokensHidden = &existingRule.ServerTokensHidden
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

	if req.RequestBodyMaxSizeMB != nil && *req.RequestBodyMaxSizeMB < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "请求体大小限制不能为负数"})
		return
	}
	if req.UpstreamKeepaliveTimeout != nil && *req.UpstreamKeepaliveTimeout < 0 {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "上游 keepalive 超时不能为负数"})
		return
	}
	if req.ServerTokensHidden != nil && (*req.ServerTokensHidden < 0 || *req.ServerTokensHidden > 2) {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "server_tokens_hidden 必须为 0、1 或 2"})
		return
	}
	features := updateRuleFeatures(req, existingRule)
	if err := validateRuleFeatures(features); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
	}
	ipACLListJSON, err := encodeIPACLList(features.IPACLList)
	if err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: err.Error()})
		return
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
				c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "TLS 证书校验失败: " + err.Error()})
				return
			}
		}
	}

	// Validate Caddy config BEFORE writing to database
	if err := h.validateCaddyConfigBeforeSave(req, features, fmt.Sprintf("update_%s_%s", caddyID, generateRandomString(8)), validationServerName); err != nil {
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
	args = append(args, *req.RequestBodyMaxSizeMB)
	query += "upstream_keepalive_timeout = ?, "
	args = append(args, *req.UpstreamKeepaliveTimeout)
	query += "server_tokens_hidden = ?, "
	args = append(args, *req.ServerTokensHidden)
	query += "ip_acl_mode = ?, "
	args = append(args, features.IPACLMode)
	query += "ip_acl_list = ?, "
	args = append(args, ipACLListJSON)
	query += "custom_routes_enabled = ?, "
	args = append(args, features.CustomRoutesEnabled)
	query += "proxy_dial_timeout = ?, "
	args = append(args, features.ProxyDialTimeout)
	query += "proxy_response_header_timeout = ?, "
	args = append(args, features.ProxyResponseHeaderTimeout)
	query += "proxy_read_timeout = ?, "
	args = append(args, features.ProxyReadTimeout)
	query += "proxy_write_timeout = ?, "
	args = append(args, features.ProxyWriteTimeout)
	query += "proxy_stream_timeout = ?, "
	args = append(args, features.ProxyStreamTimeout)
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
	query += "log_enabled = ?, "
	args = append(args, req.LogEnabled)

	// Build full rule config for route generation
	domain := req.Domain
	listenPort := req.ListenPort
	strategy := req.Strategy
	if strategy == "" {
		strategy = "weighted_round_robin"
	}

	var global struct {
		requestBodyMaxSizeMB, upstreamKeepaliveTimeout                                                        int
		proxyDialTimeout, proxyResponseHeaderTimeout, proxyReadTimeout, proxyWriteTimeout, proxyStreamTimeout int
		serverTokensHidden                                                                                    bool
	}
	if err := db.DB.QueryRow(`
		SELECT COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
			COALESCE(server_tokens_hidden,FALSE)
		FROM global_config WHERE id = 1
	`).Scan(
		&global.requestBodyMaxSizeMB, &global.upstreamKeepaliveTimeout,
		&global.proxyDialTimeout, &global.proxyResponseHeaderTimeout, &global.proxyReadTimeout, &global.proxyWriteTimeout, &global.proxyStreamTimeout,
		&global.serverTokensHidden); err != nil {
		log.Printf("UpdateRule failed to load global config for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取全局配置失败"})
		return
	}

	ruleConfig := services.SingleRuleConfig{
		Protocol:                         req.Protocol,
		Domain:                           domain,
		ListenPort:                       listenPort,
		Strategy:                         strategy,
		DynamicDNS:                       req.DynamicDNS,
		EnableDnsServer:                  req.EnableDnsServer,
		DnsServer:                        req.DnsServer,
		DnsFamily:                        req.DnsFamily,
		HealthCheckPath:                  req.HealthCheckPath,
		HealthCheckInterval:              req.HealthCheckInterval,
		HealthCheckTimeout:               req.HealthCheckTimeout,
		HealthCheckUnhealthyThreshold:    req.HealthCheckUnhealthyThreshold,
		EnableActiveHealthCheck:          req.EnableActiveHealthCheck,
		TCPHealthCheckPort:               req.TCPHealthCheckPort,
		TCPTryDuration:                   req.TCPTryDuration,
		TCPTryInterval:                   req.TCPTryInterval,
		RequestBodyMaxSizeMB:             *req.RequestBodyMaxSizeMB,
		UpstreamKeepaliveTimeout:         *req.UpstreamKeepaliveTimeout,
		ServerTokensHidden:               *req.ServerTokensHidden,
		GlobalRequestBodyMaxSizeMB:       global.requestBodyMaxSizeMB,
		GlobalUpstreamKeepaliveTimeout:   global.upstreamKeepaliveTimeout,
		GlobalServerTokensHidden:         global.serverTokensHidden,
		IPACLMode:                        features.IPACLMode,
		IPACLList:                        features.IPACLList,
		CustomRoutesEnabled:              features.CustomRoutesEnabled,
		PathRules:                        toPathRuleConfigs(features.PathRules),
		ProxyDialTimeout:                 features.ProxyDialTimeout,
		ProxyResponseHeaderTimeout:       features.ProxyResponseHeaderTimeout,
		ProxyReadTimeout:                 features.ProxyReadTimeout,
		ProxyWriteTimeout:                features.ProxyWriteTimeout,
		ProxyStreamTimeout:               features.ProxyStreamTimeout,
		GlobalProxyDialTimeout:           global.proxyDialTimeout,
		GlobalProxyResponseHeaderTimeout: global.proxyResponseHeaderTimeout,
		GlobalProxyReadTimeout:           global.proxyReadTimeout,
		GlobalProxyWriteTimeout:          global.proxyWriteTimeout,
		GlobalProxyStreamTimeout:         global.proxyStreamTimeout,
		EnableTLS:                        req.EnableTLS,
		TLSSource:                        req.TLSSource,
		ACMEConfigID:                     req.ACMEConfigID,
		TLSHTTPRedirect:                  req.TLSHTTPRedirect,
		EnableCompress:                   req.EnableCompress,
		CompressTypes:                    req.CompressTypes,
		HostHeader:                       req.HostHeader,
		CaddyID:                          caddyID,
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
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "路由配置生成失败: " + err.Error()})
		return
	}

	// Backup current full Caddy config for rollback (used for TCP rules; HTTP rules use @id-based rollback)
	oldFullConfig := services.GenerateCaddyConfig(h.cfg)

	// Backup current Caddy route config for rollback
	oldRouteConfig, _ := h.caddyService.GetConfigByID(caddyID)

	// Caddy 应用失败时需要用这些快照把已提交的 DB 更新恢复回去
	oldRuleRow, oldRuleRowErr := dumpRowByKey(c.Request.Context(), "lb_rules", "caddy_id", caddyID)
	if oldRuleRowErr != nil {
		log.Printf("UpdateRule failed to snapshot lb_rules row for caddy_id=%s: %v", caddyID, oldRuleRowErr)
	}
	oldUpstreamRowsMap, oldUpstreamRowsErr := dumpRowsByKey(c.Request.Context(), "upstreams", "rule_id", caddyID)
	if oldUpstreamRowsErr != nil {
		log.Printf("UpdateRule failed to snapshot upstreams for caddy_id=%s: %v", caddyID, oldUpstreamRowsErr)
	}
	restoreRuleDBSnapshot := func() {
		if oldRuleRowErr != nil || oldUpstreamRowsErr != nil {
			log.Printf("UpdateRule skip DB restore for caddy_id=%s: snapshot unavailable", caddyID)
			return
		}
		if err := restoreRuleSnapshot(c.Request.Context(), caddyID, oldRuleRow, oldUpstreamRowsMap, existingRule.PathRules); err != nil {
			log.Printf("CRITICAL: UpdateRule DB restore failed for caddy_id=%s: %v", caddyID, err)
		}
	}

	// Start DB transaction: write validated config and commit first
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新规则失败"})
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
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新上游服务器失败"})
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
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新上游服务器失败"})
			return
		}
	}
	if err := replacePathRulesTx(c.Request.Context(), tx, caddyID, features.PathRules); err != nil {
		tx.Rollback()
		log.Printf("UpdateRule path_rules replace error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "更新自定义路径规则失败"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("UpdateRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则更新失败"})
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
	h.caddyOpMu.Lock()
	defer h.caddyOpMu.Unlock()
	if req.Protocol == "tcp" {
		newFullConfig := services.GenerateCaddyConfig(h.cfg)
		if err := h.caddyService.ApplyConfig(newFullConfig); err != nil {
			if oldFullConfig != nil {
				if restoreErr := h.caddyService.ApplyConfig(oldFullConfig); restoreErr != nil {
					log.Printf("UpdateRule failed to restore previous Caddy config for caddy_id=%s: %v", caddyID, restoreErr)
				}
			}
			log.Printf("UpdateRule Caddy update failed for TCP rule caddy_id=%s: %v, restored previous config", caddyID, err)
			restoreRuleDBSnapshot()
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置更新失败: " + err.Error()})
			return
		}
	} else {
		if err := h.caddyService.SetConfigByID(caddyID, routeConfig); err != nil {
			if oldRouteConfig != nil {
				h.caddyService.SetConfigByID(caddyID, oldRouteConfig)
			}
			log.Printf("UpdateRule Caddy update failed for caddy_id=%s: %v, restored previous route", caddyID, err)
			restoreRuleDBSnapshot()
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "Caddy 配置更新失败: " + err.Error()})
			return
		}

		if err := h.caddyService.VerifyRouteExists(caddyID); err != nil {
			if oldRouteConfig != nil {
				h.caddyService.SetConfigByID(caddyID, oldRouteConfig)
			}
			log.Printf("UpdateRule Caddy verification failed for caddy_id=%s: %v, restored previous route", caddyID, err)
			restoreRuleDBSnapshot()
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
			if req.TLSSource == "acme_dns" && req.Protocol == "http" && req.EnableTLS && domain != "" {
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
	recordAudit(c, "更新", "负载均衡规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), req.Name, fmt.Sprintf("协议：%s", req.Protocol), domain, fmt.Sprintf("TLS：%s", boolText(req.EnableTLS))))
	recordAudit(c, "重载", "Caddy配置", services.FormatAuditDetail(services.AuditSourcePart("rule_update"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已更新"})
}

func (h *Handlers) DeleteRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	var protocol string
	var listenPort int
	var domain string
	var enableTLS bool
	err := db.DB.QueryRow("SELECT COALESCE(caddy_id,''), COALESCE(protocol,''), listen_port, COALESCE(domain,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&caddyID, &protocol, &listenPort, &domain, &enableTLS)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	// Delete all related rows in a single transaction so that certificate jobs
	// and their logs are never left as orphans.
	tx, err := db.DB.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启数据库事务失败"})
		return
	}

	if _, err := tx.Exec("DELETE FROM cert_jobs WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule cert_jobs delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除证书任务失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM upstreams WHERE rule_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule upstreams delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除上游服务器失败"})
		return
	}
	if _, err := tx.Exec("DELETE FROM lb_rules WHERE caddy_id = ?", caddyID); err != nil {
		tx.Rollback()
		log.Printf("DeleteRule lb_rules delete error for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "删除规则失败"})
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("DeleteRule transaction commit failed for caddy_id=%s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交规则删除失败"})
		return
	}

	// metrics_history lives in the separate metrics database, so it cannot
	// join the business transaction; delete best-effort after commit.
	if db.MetricsDB != nil {
		if _, err := db.MetricsDB.Exec("DELETE FROM metrics_history WHERE rule_id = ?", caddyID); err != nil {
			log.Printf("DeleteRule metrics_history delete error for caddy_id=%s: %v", caddyID, err)
		}
	}

	services.RemoveCertFiles(caddyID)
	services.RemoveRuleLogFiles(caddyID)

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

	recordAudit(c, "删除", "负载均衡规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), fmt.Sprintf("协议：%s", protocol), fmt.Sprintf("端口：%d", listenPort), domain))
	recordAudit(c, "重载", "Caddy配置", services.FormatAuditDetail(services.AuditSourcePart("rule_delete"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已删除"})
}

func (h *Handlers) DuplicateRule(c *gin.Context) {

	caddyID := c.Param("caddy_id")

	var rule models.LbRule
	var enableActiveHealthCheck bool
	var ipACLListJSON string
	var tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
	err := db.DB.QueryRow(`
		SELECT caddy_id, name, COALESCE(description,''), protocol, domain, listen_port, strategy, dynamic_dns,
		       COALESCE(enable_dns_server,0), COALESCE(dns_family,'ipv4'),
		       health_check_path, health_check_interval, health_check_timeout,
		       health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
		       enable_tls, COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), tls_cert, tls_key,
	       tls_http_redirect, COALESCE(enable_compress,1), COALESCE(compress_types,'gzip,zstd'), enabled, created_by,
	       COALESCE(host_header,''), COALESCE(dns_server,''), COALESCE(log_enabled,0),
	       COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
	       COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0)
	FROM lb_rules WHERE caddy_id = ?
`, caddyID).Scan(
		&rule.CaddyID, &rule.Name, &rule.Description, &rule.Protocol, &rule.Domain, &rule.ListenPort, &rule.Strategy,
		&rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsFamily, &rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout,
		&rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
		&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
		&rule.RequestBodyMaxSizeMB, &rule.UpstreamKeepaliveTimeout, &rule.ServerTokensHidden,
		&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.CAProviderID, &rule.TLSCert, &rule.TLSKey,
		&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.CreatedBy,
		&rule.HostHeader, &rule.DnsServer, &rule.LogEnabled,
		&rule.IPACLMode, &ipACLListJSON, &rule.CustomRoutesEnabled,
		&rule.ProxyDialTimeout, &rule.ProxyResponseHeaderTimeout, &rule.ProxyReadTimeout, &rule.ProxyWriteTimeout, &rule.ProxyStreamTimeout,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	rule.EnableActiveHealthCheck = enableActiveHealthCheck
	rule.TCPHealthCheckPort = tcpHealthCheckPort
	rule.TCPTryDuration = tcpTryDuration
	rule.TCPTryInterval = tcpTryInterval

	userID, _ := c.Get("user_id")
	var userIDInt int64
	if userID != nil {
		userIDInt = int64(userID.(float64))
	}

	newCaddyID, err := services.GenerateCaddyID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "生成规则 ID 失败"})
		return
	}

	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	tx, err := db.DB.BeginTx(c.Request.Context(), nil)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "开启复制事务失败"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if _, err := tx.Exec(`
		INSERT INTO lb_rules (name, description, protocol, domain, listen_port, strategy, dynamic_dns, enable_dns_server, dns_server, dns_family,
			health_check_path, health_check_interval, health_check_timeout,
			health_check_unhealthy_threshold, health_check_healthy_threshold,
			enable_active_health_check, tcp_health_check_port, tcp_try_duration, tcp_try_interval,
			request_body_max_size_mb, upstream_keepalive_timeout, server_tokens_hidden,
			enable_tls, tls_source, acme_config_id, ca_provider_id, tls_cert, tls_key,
		tls_http_redirect, enable_compress, compress_types, enabled, created_by, updated_by, created_at, updated_at, host_header, log_enabled, caddy_id,
		ip_acl_mode, ip_acl_list, custom_routes_enabled,
		proxy_dial_timeout, proxy_response_header_timeout, proxy_read_timeout, proxy_write_timeout, proxy_stream_timeout)
	VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, rule.Name+"（副本）", rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy,
		rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout,
		rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold,
		rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPTryDuration, rule.TCPTryInterval,
		rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden,
		rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.CAProviderID, rule.TLSCert, &rule.TLSKey,
		rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, 0, userIDInt, userIDInt,
		now, now, rule.HostHeader, rule.LogEnabled, newCaddyID,
		rule.IPACLMode, ipACLListJSON, rule.CustomRoutesEnabled,
		rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout, rule.ProxyWriteTimeout, rule.ProxyStreamTimeout,
	); err != nil {
		log.Printf("Failed to duplicate rule %s: %v", caddyID, err)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制规则失败，已回滚: " + err.Error()})
		return
	}

	upstreamRows, err := tx.Query(`
		SELECT host, port, weight, domain, dynamic_dns, enabled, COALESCE(protocol,'http'), COALESCE(max_connections,0), COALESCE(proxy_protocol,'')
		FROM upstreams WHERE rule_id = ?
	`, caddyID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取上游失败，已回滚: " + err.Error()})
		return
	}
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
		if err := upstreamRows.Scan(&u.Host, &u.Port, &u.Weight, &u.Domain, &u.DynamicDNS, &u.Enabled, &u.Protocol, &u.MaxConnections, &u.ProxyProtocol); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "扫描上游失败，已回滚: " + err.Error()})
			return
		}
		if _, err := tx.Exec(`
			INSERT INTO upstreams (rule_id, host, port, weight, domain, dynamic_dns, enabled, protocol, max_connections, proxy_protocol)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, newCaddyID, u.Host, u.Port, u.Weight, u.Domain, u.DynamicDNS, u.Enabled, u.Protocol, u.MaxConnections, u.ProxyProtocol); err != nil {
			upstreamRows.Close()
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制上游失败，已回滚: " + err.Error()})
			return
		}
	}
	upstreamRows.Close()

	if rule.CustomRoutesEnabled {
		if _, err := tx.Exec(`
			INSERT INTO path_rules (rule_id, sort_order, match_type, path, upstreams_json, created_at, updated_at)
			SELECT ?, sort_order, match_type, path, upstreams_json, datetime('now'), datetime('now') FROM path_rules WHERE rule_id = ?
		`, newCaddyID, caddyID); err != nil {
			c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "复制路径规则失败，已回滚: " + err.Error()})
			return
		}
	}

	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "提交复制事务失败: " + err.Error()})
		return
	}
	committed = true

	recordAudit(c, "复制", "负载均衡规则", services.FormatAuditDetail(fmt.Sprintf("源规则：%s", caddyID), fmt.Sprintf("新规则：%s", newCaddyID), rule.Name))
	c.JSON(http.StatusCreated, models.APIResponse{Code: 0, Message: "规则已复制", Data: gin.H{"caddy_id": newCaddyID}})
}

func (h *Handlers) EnableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	var ruleProtocol, ruleDomain string
	var rulePort int
	if err := db.DB.QueryRow("SELECT protocol, COALESCE(domain,''), listen_port FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&ruleProtocol, &ruleDomain, &rulePort); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "读取规则失败"})
		return
	}
	if err := h.validatePort(ruleProtocol, rulePort, caddyID); err != nil {
		c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: "端口冲突，无法启用: " + err.Error()})
		return
	}
	if ruleProtocol == "http" && ruleDomain != "" {
		var dupCount int
		if err := db.DB.QueryRow("SELECT COUNT(*) FROM lb_rules WHERE protocol = 'http' AND domain = ? AND caddy_id != ? AND enabled = 1", ruleDomain, caddyID).Scan(&dupCount); err == nil && dupCount > 0 {
			c.JSON(http.StatusBadRequest, models.APIResponse{Code: 400, Message: fmt.Sprintf("域名 %s 已被其他启用中的规则使用，无法启用", ruleDomain)})
			return
		}
	}

	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "启用规则失败"})
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
		if enableTLS && tlsSource == "acme_dns" && domain != "" {
			qm := services.GetCAQueueManager()

			var jobStatus, jobMsg string
			var jobExpiresAt sql.NullTime
			var jobID int
			hasJob := false
			err := db.DB.QueryRow("SELECT id, status, COALESCE(message,''), expires_at FROM cert_jobs WHERE rule_id=? ORDER BY id DESC LIMIT 1", caddyID).Scan(&jobID, &jobStatus, &jobMsg, &jobExpiresAt)
			if err == nil {
				hasJob = true
			}
			var renewalDays int
			db.DB.QueryRow("SELECT COALESCE(cert_renewal_days,30) FROM global_config WHERE id=1").Scan(&renewalDays)
			var expiryPtr *time.Time
			if jobExpiresAt.Valid {
				expiry := jobExpiresAt.Time
				expiryPtr = &expiry
			}
			action := ResolveEnableCertJobAction(hasJob, jobStatus, expiryPtr, time.Now(), renewalDays)

			switch action {
			case EnableCertJobCreate:
				if qm == nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化，无法创建证书签发任务"})
					return
				}
				if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "创建证书签发任务失败: " + err.Error()})
					return
				}
				recordAudit(c, "创建", "证书签发任务", fmt.Sprintf("启用规则 %s，创建证书签发任务 (%s)", caddyID, domain))
			case EnableCertJobKeep:
				recordAudit(c, "启用", "证书签发任务", fmt.Sprintf("启用规则 %s，证书有效（过期前%d天续签），保持现有证书", caddyID, renewalDays))
			case EnableCertJobResume:
				if _, err := db.DB.Exec("UPDATE cert_jobs SET status='issued', message='证书有效，已恢复使用', renewal_attempts=0, ca_available_after=NULL, last_error_code=NULL, updated_at=datetime('now') WHERE id=?", jobID); err != nil {
					log.Printf("EnableRule failed to resume cert job %d: %v", jobID, err)
				} else {
					recordAudit(c, "启用", "证书签发任务", fmt.Sprintf("启用规则 %s，证书仍有效，恢复使用现有证书", caddyID))
				}
			case EnableCertJobRenew:
				if qm == nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化，无法续签证书"})
					return
				}
				if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "续签排队失败: " + err.Error()})
					return
				}
				recordAudit(c, "续签", "证书签发任务", fmt.Sprintf("启用规则 %s，证书即将过期，重新排队续签", caddyID))
			case EnableCertJobRetry:
				if qm == nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "CA 队列未初始化，无法重试证书任务"})
					return
				}
				if err := services.CreateOrRequeueCertJob(caddyID, domain, caProviderID, qm); err != nil {
					c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "重试排队失败: " + err.Error()})
					return
				}
				recordAudit(c, "重试", "证书签发任务", fmt.Sprintf("启用规则 %s，任务之前已暂停/失败，重新排队", caddyID))
			default:
				recordAudit(c, "启用", "证书签发任务", fmt.Sprintf("启用规则 %s，签发任务已在进行中 (状态: %s)", caddyID, jobStatus))
			}
		}
	} else {
		log.Printf("EnableRule failed to read rule TLS state for caddy_id=%s: %v", caddyID, err)
	}

	recordAudit(c, "启用", "负载均衡规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已启用"))
	recordAudit(c, "重载", "Caddy配置", services.FormatAuditDetail(services.AuditSourcePart("rule_enable"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已启用"})
}

func (h *Handlers) DisableRule(c *gin.Context) {
	caddyID := c.Param("caddy_id")

	var exists bool
	err := db.DB.QueryRow("SELECT 1 FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusNotFound, models.APIResponse{Code: 404, Message: "规则不存在"})
		return
	}

	if _, err := db.DB.Exec("UPDATE lb_rules SET enabled = 0, updated_at = datetime('now') WHERE caddy_id = ?", caddyID); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "禁用规则失败"})
		return
	}

	if err := h.applyCaddyConfigWithRollback(); err != nil {
		// Revert DB state on Caddy failure
		db.DB.Exec("UPDATE lb_rules SET enabled = 1, updated_at = datetime('now') WHERE caddy_id = ?", caddyID)
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: fmt.Sprintf("Failed to apply Caddy config: %v", err)})
		return
	}

	var domain, tlsSource string
	var enableTLS bool
	if err := db.DB.QueryRow("SELECT COALESCE(domain,''), COALESCE(tls_source,''), COALESCE(enable_tls,0) FROM lb_rules WHERE caddy_id = ?", caddyID).Scan(&domain, &tlsSource, &enableTLS); err == nil {
		if enableTLS && tlsSource == "acme_dns" && domain != "" {
			result, _ := db.DB.Exec("UPDATE cert_jobs SET status='disabled', message='规则已禁用，任务已暂停', updated_at=datetime('now') WHERE rule_id=? AND status NOT IN ('failed','disabled')", caddyID)
			rows, _ := result.RowsAffected()
			if rows > 0 {
				services.WriteCertJobLogByRule(caddyID, "WARN", "cancelled", "规则已禁用，证书签发任务已暂停")
				recordAudit(c, "禁用", "证书签发任务", fmt.Sprintf("规则 %s 已禁用，%d 个证书任务状态设为已禁用", caddyID, rows))
			}
		}
	}

	recordAudit(c, "禁用", "负载均衡规则", services.FormatAuditDetail(services.AuditRulePart(caddyID), "状态：已禁用"))
	recordAudit(c, "重载", "Caddy配置", services.FormatAuditDetail(services.AuditSourcePart("rule_disable"), services.AuditRulePart(caddyID), services.AuditResultPart("success")))
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "规则已禁用"})
}

func (h *Handlers) GetRuleLogStream(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	offset, _ := strconv.ParseInt(c.Query("offset"), 10, 64)
	lines, next := services.ReadRuleLogFrom(caddyID, offset)
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"offset": next, "lines": lines}})
}

func (h *Handlers) GetRuleLogs(c *gin.Context) {
	caddyID := c.Param("caddy_id")
	content, offset := services.ReadRuleLogTail(caddyID, 1000)
	// offset must point just past the returned tail so a following stream
	// request continues without re-reading the same lines.
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{"content": content, "offset": offset + int64(len(content))}})
}
