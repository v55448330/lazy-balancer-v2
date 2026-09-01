package middleware

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/models"
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
			c.AbortWithStatusJSON(http.StatusInternalServerError, models.APIResponse{Code: 500, Message: "集群版本触发器不可用"})
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
		{name: "lb_rules", snapshotColumns: "caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,host_header,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,updated_by,created_at,updated_at"},
		{name: "upstreams", snapshotColumns: "id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections"},
		{name: "path_rules", snapshotColumns: "id,rule_id,sort_order,match_type,path,upstreams_json"},
		// R72 F-4：users 触发器 OF 列表补 v2.1.8 的 MFA 权威列——此前不在列表内，
		// MFA 状态写（含管理员重置）不 bump cluster_version → 快照缓存持续命中
		// 旧指纹 → 从节点 304 循环，主节点 MFA 变更稳态永不传播（泄露 secret 经
		// 重置后在从节点仍可用）。记账三列（last_timestep/failed_attempts/
		// locked_until）不补——它们经 R72 F-3 的哈希清零已不参与漂移判定，补了
		// 反而让从节点本地登录 bump 版本引发无谓重放。pending 不跨节点不补。
		{name: "users", snapshotColumns: "id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,mfa_enabled,mfa_secret,mfa_recovery_codes"},
		{name: "api_keys", snapshotColumns: "id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist"},
		{name: "ca_providers", snapshotColumns: "id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at"},
		{name: "certificate_configs", snapshotColumns: "id,name,dns_provider,dns_credentials,enabled,created_at,updated_at"},
		{name: "cert_jobs", snapshotColumns: "rule_id,domain,status,cert_pem,key_pem,expires_at,ca_provider_id,renewal_attempts,ca_available_after,last_error_code,created_at,updated_at"},
		{name: "security_policies", snapshotColumns: "id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_whitelist_enabled,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,updated_by,created_at,updated_at,geoip_countries,geoip_mode,waf_check_response,ip_acl_list_refs,ip_whitelist_refs"},
		{name: "security_policy_bindings", snapshotColumns: "rule_caddy_id,policy_id"},
		{name: "security_custom_rules", snapshotColumns: "id,name,description,conditions,action,score,enabled,updated_by,created_at,updated_at"},
		{name: "security_block_pages", snapshotColumns: "id,name,description,content,is_default,created_by,created_at,updated_by,updated_at"},
		{name: "security_ip_lists", snapshotColumns: "id,name,description,category,entries,created_by,created_at,updated_by,updated_at"},
		{name: "security_crs_version", snapshotColumns: "id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at"},
		{name: "security_ip2region_version", snapshotColumns: "id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at"},
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
			// A5-N2：NULL 兜底与写闸（readonly.go 的 COALESCE(is_master,1)）对齐——
			// NULL 视为主节点。db.go 一次性回填生效后此处为纵深防御：回填前
			// 历史库 NULL 行两层判定不再分裂（写闸放行写、触发器却不 bump 版本）。
			whenClause := "(SELECT COALESCE(is_master,1) FROM global_config WHERE id=1)=1"
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
	// A5-N2：COALESCE(NEW.is_master,1) 同上——与写闸 NULL 语义一致。
	if _, err := database.Exec(`CREATE TRIGGER cluster_version_global_config_update
		AFTER UPDATE OF sync_global_config,sync_users,sync_rules,sync_waf_files,sync_security,caddy_config,log_level,access_log_json,access_log_format,cert_job_log_size_mb,audit_log_size_mb,runtime_log_size_mb,audit_retention_months,jwt_expire_minutes,timezone,acme_email,cert_expiry_days,cert_renewal_days,cert_renewal_attempts,default_ca_provider_id,dns_provider,dns_credentials,sync_interval,admin_tls_enabled,admin_tls_mode,admin_tls_cert,admin_tls_key,caddy_log_level,caddy_log_size_mb,request_body_max_size_mb,http_read_timeout,http_write_timeout,http_idle_timeout,upstream_keepalive_timeout,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,server_tokens_hidden,mfa_write_guard,mfa_lockout_enabled,github_proxy_url ON global_config
		WHEN OLD.cluster_version IS NEW.cluster_version AND COALESCE(NEW.is_master,1)=1
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
	// 审计 A3-S1/B3-S1：/api/v1/auth/mfa 下仅 activate/disable/recovery-codes
	// 三路由写 users 触发器 OF 列（mfa_enabled/mfa_secret/mfa_recovery_codes）；
	// verify/verify-step/setup 只写刻意排除的记账/pending 列（永不 bump）——
	// 不得按前缀捕获，否则触发器安装失败的降级态下 MFA 登录/step-up 被误伤
	// 500，UI 恢复路径对 MFA 用户截断。
	for _, exact := range []string{"/api/v1/auth/mfa/activate", "/api/v1/auth/mfa/disable", "/api/v1/auth/mfa/recovery-codes"} {
		if path == exact {
			return true
		}
	}
	for _, prefix := range []string{"/api/v1/rules", "/api/v1/users", "/api/v1/api-keys", "/api/v1/certificate-configs", "/api/v1/security"} {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
