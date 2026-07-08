package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

func (h *Handlers) GetSyncStatus(c *gin.Context) {
	var lastSync sql.NullTime
	var pendingCount int

	db.DB.QueryRow("SELECT last_sync, (SELECT COUNT(*) FROM nodes WHERE status = 'pending') FROM global_config WHERE id = 1").
		Scan(&lastSync, &pendingCount)

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: gin.H{
		"last_sync":     lastSync,
		"pending_nodes": pendingCount,
		"node_mode":     h.nodeService.GetMode(),
	}})
}

func (h *Handlers) GetSyncConfig(c *gin.Context) {
	// Get current config version
	var version int64
	db.DB.QueryRow("SELECT COALESCE(MAX(version), 0) FROM config_versions").Scan(&version)

	// Get all rules
	rows, _ := db.DB.Query(`
		SELECT id, COALESCE(caddy_id,''), name, protocol, COALESCE(domain,''), listen_port, strategy,
		       COALESCE(dynamic_dns,0), COALESCE(dns_server,''),
		       health_check_path, health_check_interval,
		       health_check_timeout, health_check_unhealthy_threshold, health_check_healthy_threshold,
		       COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		       COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0),
		       COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(tls_http_redirect,0),
		       enabled, created_at, updated_at
		FROM lb_rules
	`)
	defer rows.Close()

	var rules []models.LbRule
	for rows.Next() {
		var r models.LbRule
		var domain, strategy, tlsSource string
		var dynamicDNS, enableTLS, tlsHTTPRedirect, enableActiveHealthCheck bool
		var acmeConfigID, tcpHealthCheckPort, tcpTryDuration, tcpTryInterval int
		var requestBodyMaxSizeMB, upstreamKeepaliveTimeout, serverTokensHidden int
		err := rows.Scan(&r.ID, &r.CaddyID, &r.Name, &r.Protocol, &domain, &r.ListenPort, &strategy,
			&dynamicDNS, &r.DnsServer, &r.HealthCheckPath, &r.HealthCheckInterval, &r.HealthCheckTimeout,
			&r.HealthCheckUnhealthyThreshold, &r.HealthCheckHealthyThreshold,
			&enableActiveHealthCheck, &tcpHealthCheckPort, &tcpTryDuration, &tcpTryInterval,
			&requestBodyMaxSizeMB, &upstreamKeepaliveTimeout, &serverTokensHidden,
			&enableTLS, &tlsSource, &acmeConfigID, &tlsHTTPRedirect,
			&r.Enabled, &r.CreatedAt, &r.UpdatedAt)
		if err != nil {
			continue
		}
		r.Domain = domain
		r.Strategy = strategy
		if r.Strategy == "" {
			r.Strategy = "round_robin"
		}
		r.TLSSource = tlsSource
		r.ACMEConfigID = acmeConfigID
		r.DynamicDNS = dynamicDNS
		r.EnableTLS = enableTLS
		r.TLSHTTPRedirect = tlsHTTPRedirect
		r.EnableActiveHealthCheck = enableActiveHealthCheck
		r.TCPHealthCheckPort = tcpHealthCheckPort
		r.TCPTryDuration = tcpTryDuration
		r.TCPTryInterval = tcpTryInterval
		r.RequestBodyMaxSizeMB = requestBodyMaxSizeMB
		r.UpstreamKeepaliveTimeout = upstreamKeepaliveTimeout
		r.ServerTokensHidden = serverTokensHidden

		// Get upstreams for this rule
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

	// Get global config
	var cfg models.GlobalConfig
	db.DB.QueryRow(`
		SELECT id, caddy_config, dns_provider, log_level, access_log_enabled,
		       is_master, master_url, sync_interval, last_sync, updated_at
		FROM global_config WHERE id = 1
	`).Scan(&cfg.ID, &cfg.CaddyConfig, &cfg.DNSProvider, &cfg.LogLevel,
		&cfg.AccessLogEnabled, &cfg.IsMaster, &cfg.MasterURL,
		&cfg.SyncInterval, &cfg.LastSync, &cfg.UpdatedAt)

	sinceVersion, _ := strconv.ParseInt(c.Query("since_version"), 10, 64)
	if sinceVersion > 0 && sinceVersion >= version {
		c.JSON(http.StatusNotModified, models.APIResponse{Code: 304, Message: "No changes"})
		return
	}

	syncData := models.SyncData{
		Version:   version + 1,
		Timestamp: time.Now(),
		Rules:     rules,
		Config:    cfg,
	}

	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Data: syncData})
}

func (h *Handlers) ManualSync(c *gin.Context) {
	if err := h.syncService.SyncFromMaster(); err != nil {
		c.JSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: err.Error()})
		return
	}
	c.JSON(http.StatusOK, models.APIResponse{Code: 0, Message: "Sync completed"})
}
