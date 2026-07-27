package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"lazy-balancer-v2/internal/models"
)

func (s *SyncService) applySnapshot(ctx context.Context, snapshot models.ClusterSnapshot) error {
	previous, _, err := s.cluster.Snapshot(ctx, 0, "", "")
	if err != nil {
		return fmt.Errorf("备份本地快照: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始快照事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceSnapshotTx(ctx, tx, snapshot); err != nil {
		return err
	}
	removeMissingSnapshotCerts(previous.Certs, snapshot.Certs)
	if err := materializeSnapshotCerts(snapshot.Certs); err != nil {
		restoreSnapshotCerts(previous.Certs, snapshot.Certs)
		return fmt.Errorf("写入同步证书: %w", err)
	}
	if err := s.caddy.ApplyConfig(generateCaddyConfigFromStore(s.cfg, tx)); err != nil {
		restoreSnapshotCerts(previous.Certs, snapshot.Certs)
		return fmt.Errorf("重载 Caddy 失败，数据库已回滚: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET applied_version=?, sync_fingerprint=?, last_sync=datetime('now'), last_sync_error='' WHERE id=1`, snapshot.Version, snapshot.Fingerprint); err != nil {
		restoreSnapshotCerts(previous.Certs, snapshot.Certs)
		_ = s.caddy.ApplyConfig(GenerateCaddyConfig(s.cfg))
		return fmt.Errorf("记录同步状态: %w", err)
	}
	if err := tx.Commit(); err != nil {
		restoreSnapshotCerts(previous.Certs, snapshot.Certs)
		_ = s.caddy.ApplyConfig(GenerateCaddyConfig(s.cfg))
		return fmt.Errorf("提交快照事务: %w", err)
	}
	caddySync := "未开启"
	if snapshot.CaddyConfig != nil {
		caddySync = "已同步"
	}
	if RuntimeAdminTLSChanged(LoadAdminTLSConfig()) {
		RecordAuditLog("system", "重启", "系统", "同步到新的 HTTPS 访问配置，自动重启生效", "")
		log.Printf("Admin TLS config changed via sync, restarting to apply")
		go func() {
			time.Sleep(time.Second)
			os.Exit(0)
		}()
	}
	RecordAuditLog("system", "同步", "集群同步", FormatAuditDetail(fmt.Sprintf("应用版本：%d", snapshot.Version), fmt.Sprintf("规则 %d 条", len(snapshot.Rules)), fmt.Sprintf("用户 %d 个", len(snapshot.Users)), fmt.Sprintf("密钥 %d 个", len(snapshot.APIKeys)), fmt.Sprintf("证书 %d 张", len(snapshot.Certs)), "基本设置：已同步", fmt.Sprintf("Caddy 全局配置：%s", caddySync)), "")
	RecordAuditLog("system", "重载", "Caddy配置", "同步应用后自动重载", "")
	return nil
}

func restoreSnapshotCerts(previous, current []models.ClusterCertificate) {
	removeMissingSnapshotCerts(current, previous)
	_ = materializeSnapshotCerts(previous)
}

func removeMissingSnapshotCerts(previous, current []models.ClusterCertificate) {
	currentIDs := make(map[string]bool, len(current))
	for _, cert := range current {
		currentIDs[cert.RuleID] = true
	}
	for _, cert := range previous {
		if !currentIDs[cert.RuleID] {
			RemoveCertFiles(cert.RuleID)
		}
	}
}

func replaceSnapshotDB(ctx context.Context, database *sql.DB, snapshot models.ClusterSnapshot) error {
	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("开始快照事务: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := replaceSnapshotTx(ctx, tx, snapshot); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("提交快照事务: %w", err)
	}
	return nil
}

func replaceSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	for _, statement := range []string{"DELETE FROM path_rules", "DELETE FROM upstreams", "DELETE FROM cert_jobs", "DELETE FROM lb_rules", "DELETE FROM api_keys", "DELETE FROM users"} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理快照数据: %w", err)
		}
	}
	if err := insertSnapshotRules(ctx, tx, snapshot.Rules); err != nil {
		return err
	}
	for _, user := range snapshot.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,username,password_hash,role,display_name,is_enabled) VALUES (?,?,?,?,?,?)`, user.ID, user.Username, user.PasswordHash, user.Role, user.DisplayName, user.IsEnabled); err != nil {
			return fmt.Errorf("写入快照用户 %s: %w", user.Username, err)
		}
	}
	for _, key := range snapshot.APIKeys {
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,expires_at,is_enabled) VALUES (?,?,?,?,?,?,?)`, key.ID, key.Name, key.KeyHash, key.KeyPrefix, key.CreatedBy, nullableString(key.ExpiresAt), key.IsEnabled); err != nil {
			return fmt.Errorf("写入快照密钥 %d: %w", key.ID, err)
		}
	}
	for _, cert := range snapshot.Certs {
		if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (rule_id,domain,status,message,expires_at,cert_pem,key_pem) SELECT ?,COALESCE(domain,''),'issued','从主节点同步',?,?,? FROM lb_rules WHERE caddy_id=? AND tls_source='acme_dns'`, cert.RuleID, nullableString(cert.ExpiresAt), cert.CertPEM, cert.KeyPEM, cert.RuleID); err != nil {
			return fmt.Errorf("写入快照证书 %s: %w", cert.RuleID, err)
		}
	}
	if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
		return err
	}
	return nil
}

func insertSnapshotRules(ctx context.Context, tx *sql.Tx, rules []models.LbRule) error {
	for _, rule := range rules {
		ipACLListJSON, err := json.Marshal(rule.IPACLList)
		if err != nil {
			return fmt.Errorf("序列化快照规则 %s 的 IP 访问控制列表: %w", rule.CaddyID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,ip_acl_mode,ip_acl_list,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,host_header,enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,updated_by) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			rule.CaddyID, rule.Name, rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy, rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout, rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold, rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPProxyProtocol, rule.TCPTryDuration, rule.TCPTryInterval, rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden, rule.IPACLMode, string(ipACLListJSON), rule.CustomRoutesEnabled, rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout, rule.ProxyWriteTimeout, rule.ProxyStreamTimeout, rule.HostHeader, rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.CAProviderID, rule.TLSCert, rule.TLSKey, rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, rule.Enabled, rule.LogEnabled, rule.CreatedBy, rule.UpdatedBy); err != nil {
			return fmt.Errorf("写入快照规则 %s: %w", rule.CaddyID, err)
		}
		for _, upstream := range rule.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (id,rule_id,host,port,weight,domain,dynamic_dns,enabled,protocol,dns_server,max_connections) VALUES (?,?,?,?,?,?,?,?,?,?,?)`, upstream.ID, rule.CaddyID, upstream.Host, upstream.Port, upstream.Weight, upstream.Domain, upstream.DynamicDNS, upstream.Enabled, upstream.Protocol, upstream.DnsServer, upstream.MaxConnections); err != nil {
				return fmt.Errorf("写入快照上游 %s: %w", rule.CaddyID, err)
			}
		}
		if err := insertSnapshotPathRules(ctx, tx, rule.CaddyID, rule.PathRules); err != nil {
			return err
		}
	}
	return nil
}

func insertSnapshotPathRules(ctx context.Context, tx *sql.Tx, ruleID string, pathRules []models.PathRule) error {
	for _, pathRule := range pathRules {
		var upstreamsJSON any
		if pathRule.Upstreams != nil {
			encoded, err := json.Marshal(pathRule.Upstreams)
			if err != nil {
				return fmt.Errorf("序列化快照路径 %s 的上游: %w", pathRule.Path, err)
			}
			upstreamsJSON = string(encoded)
		}
		var err error
		if pathRule.ID > 0 {
			_, err = tx.ExecContext(ctx, `INSERT INTO path_rules (id,rule_id,sort_order,match_type,path,upstreams_json) VALUES (?,?,?,?,?,?)`, pathRule.ID, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, upstreamsJSON)
		} else {
			_, err = tx.ExecContext(ctx, `INSERT INTO path_rules (rule_id,sort_order,match_type,path,upstreams_json) VALUES (?,?,?,?,?)`, ruleID, pathRule.SortOrder, pathRule.MatchType, pathRule.Path, upstreamsJSON)
		}
		if err != nil {
			return fmt.Errorf("写入快照路径 %s: %w", pathRule.Path, err)
		}
	}
	return nil
}

func updateSnapshotSettings(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	settings := snapshot.BasicSettings
	query := `UPDATE global_config SET log_level=?,access_log_json=?,access_log_format=?,cert_job_log_size_mb=?,runtime_log_size_mb=?,audit_retention_months=?,jwt_expire_minutes=?,timezone=?,acme_email=?,cert_expiry_days=?,cert_renewal_days=?,cert_renewal_attempts=?,default_ca_provider_id=?,dns_provider=?,dns_credentials=?,sync_interval=?,admin_tls_enabled=?,admin_tls_mode=?,admin_tls_cert=?,admin_tls_key=?`
	args := []any{settings.LogLevel, settings.AccessLogJSON, settings.AccessLogFormat, settings.CertJobLogSizeMB, settings.RuntimeLogSizeMB, settings.AuditRetentionMonths, settings.JWTExpireMinutes, settings.Timezone, settings.ACMEEmail, settings.CertExpiryDays, settings.CertRenewalDays, settings.CertRenewalAttempts, settings.DefaultCAProviderID, settings.DNSProvider, settings.DNSCredentials, settings.SyncInterval, settings.AdminTLSEnabled, settings.AdminTLSMode, settings.AdminTLSCert, settings.AdminTLSKey}
	if snapshot.CaddyConfig != nil {
		query += ",caddy_config=?,caddy_log_path=?,caddy_log_level=?,caddy_log_size_mb=?,request_body_max_size_mb=?,http_read_timeout=?,http_write_timeout=?,http_idle_timeout=?,upstream_keepalive_timeout=?,proxy_dial_timeout=?,proxy_response_header_timeout=?,proxy_read_timeout=?,proxy_write_timeout=?,proxy_stream_timeout=?,server_tokens_hidden=?"
		args = append(args, *snapshot.CaddyConfig, settings.CaddyLogPath, settings.CaddyLogLevel, settings.CaddyLogSizeMB,
			settings.RequestBodyMaxSizeMB, settings.HTTPReadTimeout, settings.HTTPWriteTimeout, settings.HTTPIdleTimeout,
			settings.UpstreamKeepaliveTimeout, settings.ProxyDialTimeout, settings.ProxyResponseHeaderTimeout, settings.ProxyReadTimeout, settings.ProxyWriteTimeout, settings.ProxyStreamTimeout,
			settings.ServerTokensHidden)
	}
	query += " WHERE id=1"
	if _, err := tx.ExecContext(ctx, query, args...); err != nil {
		return fmt.Errorf("写入快照基础设置: %w", err)
	}
	return nil
}

func materializeSnapshotCerts(certs []models.ClusterCertificate) error {
	for _, cert := range certs {
		if err := WriteCertFiles(cert.RuleID, cert.CertPEM, cert.KeyPEM); err != nil {
			return err
		}
	}
	return nil
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
