package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func clusterVersionMiddleware(database *sql.DB) gin.HandlerFunc {
	installErr := installClusterVersionTriggers(database)
	return func(c *gin.Context) {
		if !isSynchronizedWrite(c.Request.Method, c.FullPath()) {
			c.Next()
			return
		}
		if installErr != nil {
			_ = c.Error(installErr)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "cluster version trigger unavailable"})
			return
		}
		c.Next()
	}
}

func installClusterVersionTriggers(database *sql.DB) error {
	tables := []struct {
		name            string
		snapshotColumns string
	}{
		{name: "lb_rules", snapshotColumns: "caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,host_header,ip_acl_mode,ip_acl_list,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,updated_by"},
		{name: "upstreams", snapshotColumns: "id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,dns_server,max_connections"},
		{name: "path_rules", snapshotColumns: "id,rule_id,sort_order,match_type,path,upstreams_json"},
		{name: "users", snapshotColumns: "id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at"},
		{name: "api_keys", snapshotColumns: "id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist"},
		{name: "ca_providers", snapshotColumns: "id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at"},
		{name: "certificate_configs", snapshotColumns: "id,name,dns_provider,dns_credentials,enabled,created_at,updated_at"},
		{name: "cert_jobs", snapshotColumns: "rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id,renewal_attempts,ca_available_after,last_error_code"},
	}
	const newCertificateMember = "NEW.status<>'disabled' AND COALESCE(NEW.cert_pem,'')<>'' AND COALESCE(NEW.key_pem,'')<>'' AND datetime(NEW.expires_at)>datetime('now')"
	const oldCertificateMember = "OLD.status<>'disabled' AND COALESCE(OLD.cert_pem,'')<>'' AND COALESCE(OLD.key_pem,'')<>'' AND datetime(OLD.expires_at)>datetime('now')"
	for _, table := range tables {
		for _, operation := range []string{"INSERT", "UPDATE", "DELETE"} {
			triggerName := fmt.Sprintf("cluster_version_%s_%s", table.name, strings.ToLower(operation))
			if _, err := database.Exec("DROP TRIGGER IF EXISTS " + triggerName); err != nil {
				return fmt.Errorf("replace cluster version trigger for %s %s: %w", operation, table.name, err)
			}
			operationClause := operation
			whenClause := "(SELECT COALESCE(is_master,0) FROM global_config WHERE id=1)=1"
			if operation == "UPDATE" {
				operationClause += " OF " + table.snapshotColumns
			}
			if table.name == "cert_jobs" {
				switch operation {
				case "INSERT":
					whenClause += " AND " + newCertificateMember
				case "UPDATE":
					whenClause += " AND ((" + oldCertificateMember + ") OR (" + newCertificateMember + "))"
				case "DELETE":
					whenClause += " AND " + oldCertificateMember
				}
			}
			statement := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS cluster_version_%s_%s
				AFTER %s ON %s
				WHEN %s
				BEGIN
					UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
				END`, table.name, strings.ToLower(operation), operationClause, table.name, whenClause)
			if _, err := database.Exec(statement); err != nil {
				return fmt.Errorf("install cluster version trigger for %s %s: %w", operation, table.name, err)
			}
		}
	}
	if _, err := database.Exec("DROP TRIGGER IF EXISTS cluster_version_cert_jobs_status_update"); err != nil {
		return fmt.Errorf("replace cluster version trigger for cert_jobs status UPDATE: %w", err)
	}
	if _, err := database.Exec("DROP TRIGGER IF EXISTS cluster_version_global_config_update"); err != nil {
		return fmt.Errorf("replace cluster version trigger for global_config UPDATE: %w", err)
	}
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_global_config_update
		AFTER UPDATE OF sync_caddy_config,caddy_config,log_level,access_log_json,access_log_format,cert_job_log_size_mb,runtime_log_size_mb,audit_retention_months,jwt_expire_minutes,timezone,acme_email,cert_expiry_days,cert_renewal_days,cert_renewal_attempts,default_ca_provider_id,dns_provider,dns_credentials,sync_interval,admin_tls_enabled,admin_tls_mode,admin_tls_cert,admin_tls_key,caddy_log_path,caddy_log_level,caddy_log_size_mb,request_body_max_size_mb,http_read_timeout,http_write_timeout,http_idle_timeout,upstream_keepalive_timeout,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,server_tokens_hidden ON global_config
		WHEN OLD.cluster_version IS NEW.cluster_version AND COALESCE(NEW.is_master,0)=1
		BEGIN
			UPDATE global_config SET cluster_version=COALESCE(cluster_version,0)+1 WHERE id=1;
		END`); err != nil {
		return fmt.Errorf("install cluster version trigger for global_config UPDATE: %w", err)
	}
	return nil
}

func isSynchronizedWrite(method, path string) bool {
	if method != http.MethodPost && method != http.MethodPut && method != http.MethodPatch && method != http.MethodDelete {
		return false
	}
	// Writes to synced global_config columns.
	if method == http.MethodPut && (path == "/api/v1/config" || path == "/api/v1/caddy/config" || path == "/api/v1/cluster/settings" || path == "/api/v1/admin-tls") {
		return true
	}
	// Config backup import rewrites rules/upstreams; the validate endpoint only previews.
	if method == http.MethodPost && (path == "/api/v1/config/import" || path == "/api/v1/config/import/v1") {
		return true
	}
	// Certificate issuance and job retry/delete write cert_jobs; parse and current-jobs queries are read-only.
	if path == "/api/v1/certificates/issue" ||
		(strings.HasPrefix(path, "/api/v1/certificates/jobs/") && (method == http.MethodDelete || (method == http.MethodPost && strings.HasSuffix(path, "/retry")))) {
		return true
	}
	// CA provider updates write ca_providers; the POST test endpoint only probes credentials.
	if method == http.MethodPut && strings.HasPrefix(path, "/api/v1/ca-providers") {
		return true
	}
	if path == "/api/v1/rules/cert-info" {
		return false
	}
	// Certificate config test endpoints only probe DNS credentials without writing.
	if method == http.MethodPost && strings.HasPrefix(path, "/api/v1/certificate-configs/") && strings.HasSuffix(path, "/test") {
		return false
	}
	for _, prefix := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/api-keys", "/api/v1/certificate-configs"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
