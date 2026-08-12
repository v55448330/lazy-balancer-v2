package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"

	"lazy-balancer-v2/internal/models"
)

var restartRequiredHandler = struct {
	sync.RWMutex
	fn func()
}{fn: defaultRestartRequiredHandler}

func defaultRestartRequiredHandler() {
	go func() {
		time.Sleep(time.Second)
		os.Exit(0)
	}()
}

// SetRestartRequiredHandler installs the graceful restart signal used by the
// process lifecycle. Passing nil restores the standalone fallback behavior.
func SetRestartRequiredHandler(handler func()) {
	restartRequiredHandler.Lock()
	defer restartRequiredHandler.Unlock()
	if handler == nil {
		restartRequiredHandler.fn = defaultRestartRequiredHandler
		return
	}
	restartRequiredHandler.fn = handler
}

func requestRestart() {
	restartRequiredHandler.RLock()
	handler := restartRequiredHandler.fn
	restartRequiredHandler.RUnlock()
	handler()
}

func (s *SyncService) applySnapshot(ctx context.Context, snapshot models.ClusterSnapshot) error {
	if err := validateSnapshotACMEState(snapshot); err != nil {
		return err
	}
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
	if err := removeMissingSnapshotCerts(previous.Certs, snapshot.Certs); err != nil {
		return errors.Join(fmt.Errorf("删除本地旧证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
	}
	if err := materializeSnapshotCerts(snapshot.Certs); err != nil {
		return errors.Join(fmt.Errorf("写入同步证书: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
	}
	if err := s.materializeSnapshotDNSOwnership(snapshot.ACME); err != nil {
		return errors.Join(fmt.Errorf("写入同步 DNS 所有权状态: %w", err), s.restoreSnapshotArtifacts(previous, snapshot))
	}
	if _, err := tx.ExecContext(ctx, `UPDATE global_config SET applied_version=?, cluster_version=?, sync_fingerprint=?, last_sync=datetime('now'), last_sync_error='' WHERE id=1`, snapshot.Version, snapshot.Version, snapshot.Fingerprint); err != nil {
		return errors.Join(
			fmt.Errorf("记录同步状态: %w", err),
			s.restoreSnapshotArtifacts(previous, snapshot),
		)
	}
	if err := tx.Commit(); err != nil {
		return errors.Join(
			fmt.Errorf("提交快照事务: %w", err),
			s.restoreSnapshotArtifacts(previous, snapshot),
		)
	}
	// Caddy 重载必须在事务提交之后：buildWafHandler 等安全配置读取走 db.DB，
	// 提交前的事务内生成看不到本次写入的 security_* 表。重载失败仅记录，
	// 不回滚已提交的快照。
	if err := s.caddy.ApplyConfig(GenerateCaddyConfig()); err != nil {
		Logf("error", "集群同步后重载 Caddy 失败（快照已提交）: %v", err)
		RecordAuditLog("system", "重载失败", "Caddy配置", fmt.Sprintf("同步应用后自动重载失败: %v", err), "")
	} else {
		RecordAuditLog("system", "重载", "Caddy配置", "同步应用后自动重载", "")
	}
	clusterSnapshotCaches.Delete(s.db)
	caddySync := "未开启"
	if snapshot.CaddyConfig != nil {
		caddySync = "已同步"
	}
	if RuntimeAdminTLSChanged(LoadAdminTLSConfig()) {
		RecordAuditLog("system", "重启", "系统", "同步到新的 HTTPS 访问配置，自动重启生效", "")
		log.Printf("Admin TLS config changed via sync, restarting to apply")
		requestRestart()
	}
	RecordAuditLog("system", "同步", "集群同步", FormatAuditDetail(fmt.Sprintf("应用版本：%d", snapshot.Version), fmt.Sprintf("规则 %d 条", len(snapshot.Rules)), fmt.Sprintf("用户 %d 个", len(snapshot.Users)), fmt.Sprintf("密钥 %d 个", len(snapshot.APIKeys)), fmt.Sprintf("证书 %d 张", len(snapshot.Certs)), "基本设置：已同步", fmt.Sprintf("Caddy 全局配置：%s", caddySync)), "")
	return nil
}

func (s *SyncService) restoreSnapshotArtifacts(previous, current models.ClusterSnapshot) error {
	return errors.Join(restoreSnapshotCerts(previous.Certs, current.Certs), s.materializeSnapshotDNSOwnership(previous.ACME))
}

func (s *SyncService) materializeSnapshotDNSOwnership(acme *models.ClusterACMEState) error {
	if acme == nil {
		return nil
	}
	if err := validateDNSOwnership(acme.DNSOwnership); err != nil {
		return err
	}
	dataDir := ""
	if s.cfg != nil {
		dataDir = s.cfg.DataDir
	}
	if dataDir == "" {
		var err error
		dataDir, err = clusterDatabaseDir(s.db)
		if err != nil {
			return err
		}
	}
	path := filepath.Join(dataDir, "acme_dns_ownership.json")
	temporary, err := os.CreateTemp(dataDir, ".acme-dns-ownership-*")
	if err != nil {
		return fmt.Errorf("创建 DNS 所有权临时文件: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		return errors.Join(fmt.Errorf("设置 DNS 所有权文件权限: %w", err), temporary.Close())
	}
	if _, err := temporary.Write(acme.DNSOwnership); err != nil {
		return errors.Join(fmt.Errorf("写入 DNS 所有权临时文件: %w", err), temporary.Close())
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(fmt.Errorf("同步 DNS 所有权临时文件: %w", err), temporary.Close())
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("关闭 DNS 所有权临时文件: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("替换 DNS 所有权状态: %w", err)
	}
	if err := syncParentDir(path); err != nil {
		return fmt.Errorf("同步 DNS 所有权目录: %w", err)
	}
	return nil
}

func restoreSnapshotCerts(previous, current []models.ClusterCertificate) error {
	return errors.Join(removeMissingSnapshotCerts(current, previous), materializeSnapshotCerts(previous))
}

func removeMissingSnapshotCerts(previous, current []models.ClusterCertificate) error {
	currentIDs := make(map[string]bool, len(current))
	for _, cert := range current {
		currentIDs[cert.RuleID] = true
	}
	var errs []error
	for _, cert := range previous {
		if !currentIDs[cert.RuleID] {
			if err := RemoveCertFiles(cert.RuleID); err != nil {
				errs = append(errs, fmt.Errorf("删除证书 %s: %w", cert.RuleID, err))
			}
		}
	}
	return errors.Join(errs...)
}

func replaceSnapshotTx(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	statements := []string{"DELETE FROM path_rules", "DELETE FROM upstreams", "DELETE FROM cert_jobs", "DELETE FROM lb_rules", "DELETE FROM api_keys", "DELETE FROM users"}
	if snapshot.ACME != nil {
		statements = append(statements, "DELETE FROM certificate_configs", "DELETE FROM ca_providers")
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理快照数据: %w", err)
		}
	}
	if snapshot.ACME != nil {
		for _, provider := range snapshot.ACME.CAProviders {
			if _, err := tx.ExecContext(ctx, `INSERT INTO ca_providers (id,name,provider,directory_url,credentials,max_concurrent,min_interval_ms,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`, provider.ID, provider.Name, provider.Provider, provider.DirectoryURL, nullableString(provider.Credentials), provider.MaxConcurrent, provider.MinIntervalMS, provider.Enabled, provider.CreatedAt, provider.UpdatedAt); err != nil {
				return fmt.Errorf("写入快照 CA 提供商 %d: %w", provider.ID, err)
			}
		}
		for _, config := range snapshot.ACME.CertificateConfigs {
			if _, err := tx.ExecContext(ctx, `INSERT INTO certificate_configs (id,name,dns_provider,dns_credentials,enabled,created_at,updated_at) VALUES (?,?,?,?,?,?,?)`, config.ID, config.Name, config.DNSProvider, nullableString(config.DNSCredentials), config.Enabled, config.CreatedAt, nullableTime(config.UpdatedAt.NullTime)); err != nil {
				return fmt.Errorf("写入快照证书配置 %d: %w", config.ID, err)
			}
		}
	}
	if err := insertSnapshotRules(ctx, tx, snapshot.Rules); err != nil {
		return err
	}
	for _, user := range snapshot.Users {
		if _, err := tx.ExecContext(ctx, `INSERT INTO users (id,username,password_hash,role,display_name,is_enabled,password_version,password_changed_at,created_at,last_login) VALUES (?,?,?,?,?,?,?,?,?,?)`, user.ID, user.Username, user.PasswordHash, user.Role, user.DisplayName, user.IsEnabled, user.PasswordVersion, user.PasswordChangedAt, user.CreatedAt, nullableTime(user.LastLogin.NullTime)); err != nil {
			return fmt.Errorf("写入快照用户 %s: %w", user.Username, err)
		}
	}
	for _, key := range snapshot.APIKeys {
		whitelistJSON, err := json.Marshal(key.MCPIPWhitelist)
		if err != nil {
			return fmt.Errorf("序列化快照密钥 %d 的 MCP IP 白名单: %w", key.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO api_keys (id,name,key_hash,key_prefix,created_by,expires_at,is_enabled,mcp_enabled,read_only,mcp_ip_whitelist) VALUES (?,?,?,?,?,?,?,?,?,?)`, key.ID, key.Name, key.KeyHash, key.KeyPrefix, key.CreatedBy, nullableString(key.ExpiresAt), key.IsEnabled, key.MCPEnabled, key.ReadOnly, string(whitelistJSON)); err != nil {
			return fmt.Errorf("写入快照密钥 %d: %w", key.ID, err)
		}
	}
	for _, cert := range snapshot.Certs {
		message := "从主节点同步"
		if cert.SourceStatus != "" {
			message += "，源任务状态：" + cert.SourceStatus
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO cert_jobs (rule_id,domain,status,message,expires_at,cert_pem,key_pem,ca_provider_id,renewal_attempts,ca_available_after,last_error_code) SELECT ?,COALESCE(NULLIF(?,''),domain),'issued',?,?,?,?,?,?,?,? FROM lb_rules WHERE caddy_id=? AND tls_source='acme_dns'`, cert.RuleID, cert.Domain, message, nullableString(cert.ExpiresAt), cert.CertPEM, cert.KeyPEM, cert.CAProviderID, cert.RenewalAttempts, nullableTime(cert.CAAvailableAfter.NullTime), nullableString(cert.LastErrorCode), cert.RuleID); err != nil {
			return fmt.Errorf("写入快照证书 %s: %w", cert.RuleID, err)
		}
	}
	if err := updateSnapshotSettings(ctx, tx, snapshot); err != nil {
		return err
	}
	if err := applySecurityTables(ctx, tx, snapshot); err != nil {
		return err
	}
	return nil
}

func applySecurityTables(ctx context.Context, tx *sql.Tx, snapshot models.ClusterSnapshot) error {
	// 与规则/用户等表一致的全量替换语义：空载荷意味着主节点已清空，从节点必须
	// 同步删除，不能因载荷为空而提前返回。
	statements := []string{
		"DELETE FROM security_policy_bindings",
		"DELETE FROM security_policies",
		"DELETE FROM security_custom_rules",
		"DELETE FROM security_block_pages",
		"DELETE FROM security_crs_version",
		"DELETE FROM security_ip2region_version",
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("清理安全同步表: %w", err)
		}
	}
	var policies []map[string]interface{}
	if len(snapshot.SecurityPolicies) > 0 {
		if err := json.Unmarshal(snapshot.SecurityPolicies, &policies); err != nil {
			return fmt.Errorf("解析 security_policies: %w", err)
		}
	}
	for _, p := range policies {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policies (id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,rate_limit_response,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,enabled,created_at,updated_at,geoip_countries,geoip_mode) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			p["id"], p["name"], p["description"], p["mode"], p["anomaly_threshold"],
			p["ip_acl_mode"], snapshotJSONText(p["ip_acl_list"]), p["ip_acl_enabled"],
			snapshotJSONText(p["ip_whitelist"]), snapshotJSONText(p["ip_blacklist"]),
			p["rate_limit_enabled"], p["rate_limit_rps"], p["rate_limit_burst"], p["rate_limit_response"],
			snapshotJSONText(p["crs_rule_groups"]), snapshotJSONText(p["crs_excluded_rules"]), snapshotJSONText(p["custom_rules"]),
			p["block_page_id"], p["enabled"], p["created_at"], p["updated_at"],
			snapshotJSONText(p["geoip_countries"]), p["geoip_mode"]); err != nil {
			return fmt.Errorf("写入 security_policy: %w", err)
		}
	}
	var bindings []map[string]interface{}
	if len(snapshot.SecurityBindings) > 0 {
		if err := json.Unmarshal(snapshot.SecurityBindings, &bindings); err != nil {
			return fmt.Errorf("解析 security_bindings: %w", err)
		}
	}
	for _, b := range bindings {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) VALUES (?, ?)`, b["rule_caddy_id"], b["policy_id"]); err != nil {
			return fmt.Errorf("写入 security_policy_binding: %w", err)
		}
	}
	if err := applySecurityCustomRules(ctx, tx, snapshot.SecurityCustomRules); err != nil {
		return err
	}
	if err := applySecurityBlockPages(ctx, tx, snapshot.SecurityBlockPages); err != nil {
		return err
	}
	if err := applySecurityCRSVersion(ctx, tx, snapshot.SecurityCRSVersion); err != nil {
		return err
	}
	if err := applySecurityIP2RegionVersion(ctx, tx, snapshot.SecurityIP2RegionVersion); err != nil {
		return err
	}
	return nil
}

// snapshotJSONText 写入快照中的 JSON 文本列。dumpTableAsJSON 已把该列作为
// JSON 字符串携带，直接透传，避免二次编码成带引号的字面量。
func snapshotJSONText(value interface{}) interface{} {
	switch v := value.(type) {
	case nil:
		return nil
	case string:
		return v
	default:
		encoded, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		return string(encoded)
	}
}

func applySecurityCustomRules(ctx context.Context, tx *sql.Tx, rules []models.SecurityCustomRule) error {
	for _, rule := range rules {
		conditions := rule.Conditions
		if conditions == nil {
			conditions = []models.CustomRuleCondition{}
		}
		conditionsJSON, err := json.Marshal(conditions)
		if err != nil {
			return fmt.Errorf("序列化快照自定义安全规则 %d 的条件: %w", rule.ID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_custom_rules (id,name,description,conditions,action,score,status_code,enabled,updated_by,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			rule.ID, rule.Name, rule.Description, string(conditionsJSON), rule.Action, rule.Score, rule.StatusCode, rule.Enabled, rule.UpdatedBy, rule.CreatedAt, rule.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照自定义安全规则 %d: %w", rule.ID, err)
		}
	}
	return nil
}

func applySecurityBlockPages(ctx context.Context, tx *sql.Tx, pages []models.SecurityBlockPage) error {
	for _, page := range pages {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_block_pages (id,name,description,content,status_code,is_default,created_by,created_at,updated_by,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			page.ID, page.Name, page.Description, page.Content, page.StatusCode, page.IsDefault, page.CreatedBy, page.CreatedAt, page.UpdatedBy, page.UpdatedAt); err != nil {
			return fmt.Errorf("写入快照拦截页面 %d: %w", page.ID, err)
		}
	}
	return nil
}

func applySecurityCRSVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityCRSVersion) error {
	for _, version := range versions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_crs_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			version.ID, version.Version, nullableString(version.UpdatedAt), version.AutoUpdate, version.UpdateStatus, version.Message,
			nullableString(version.LastChecked), nullableString(version.NextUpdate), nullableString(version.Trigger), nullableString(version.StartedAt), nullableString(version.FinishedAt)); err != nil {
			return fmt.Errorf("写入快照 CRS 版本 %d: %w", version.ID, err)
		}
	}
	return nil
}

func applySecurityIP2RegionVersion(ctx context.Context, tx *sql.Tx, versions []models.ClusterSecurityIP2RegionVersion) error {
	for _, version := range versions {
		if _, err := tx.ExecContext(ctx, `INSERT INTO security_ip2region_version (id,version,updated_at,auto_update,update_status,message,last_checked,next_update,trigger,started_at,finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
			version.ID, version.Version, nullableString(version.UpdatedAt), version.AutoUpdate, version.UpdateStatus, version.Message,
			nullableString(version.LastChecked), nullableString(version.NextUpdate), nullableString(version.Trigger), nullableString(version.StartedAt), nullableString(version.FinishedAt)); err != nil {
			return fmt.Errorf("写入快照 ip2region 版本 %d: %w", version.ID, err)
		}
	}
	return nil
}

func validateSnapshotACMEState(snapshot models.ClusterSnapshot) error {
	if snapshot.ACME == nil {
		if snapshot.SchemaVersion >= 3 {
			return errors.New("schema v3 快照缺少必需的 ACME 区段")
		}
		return nil
	}
	if snapshot.ACME.CAProviders == nil || snapshot.ACME.CertificateConfigs == nil || len(snapshot.ACME.DNSOwnership) == 0 {
		return errors.New("快照 ACME 区段缺少 ca_providers、certificate_configs 或 dns_ownership")
	}
	if err := validateDNSOwnership(snapshot.ACME.DNSOwnership); err != nil {
		return err
	}
	providers := make(map[int]struct{}, len(snapshot.ACME.CAProviders))
	for _, provider := range snapshot.ACME.CAProviders {
		if provider.ID <= 0 || provider.Name == "" || provider.Provider == "" || provider.DirectoryURL == "" {
			return fmt.Errorf("快照 CA 提供商 %d 字段不完整", provider.ID)
		}
		providers[provider.ID] = struct{}{}
	}
	configs := make(map[int]struct{}, len(snapshot.ACME.CertificateConfigs))
	for _, config := range snapshot.ACME.CertificateConfigs {
		if config.ID <= 0 || config.Name == "" || config.DNSProvider == "" {
			return fmt.Errorf("快照证书配置 %d 字段不完整", config.ID)
		}
		configs[config.ID] = struct{}{}
	}
	for _, rule := range snapshot.Rules {
		if !rule.EnableTLS || rule.TLSSource != "acme_dns" {
			continue
		}
		if rule.ACMEConfigID == 0 {
			return fmt.Errorf("快照规则 %s 未设置证书配置", rule.CaddyID)
		}
		if _, exists := configs[rule.ACMEConfigID]; !exists {
			return fmt.Errorf("快照规则 %s 引用了不存在的证书配置 %d", rule.CaddyID, rule.ACMEConfigID)
		}
		if rule.CAProviderID != 0 {
			if _, exists := providers[rule.CAProviderID]; exists {
				continue
			}
			return fmt.Errorf("快照规则 %s 引用了不存在的 CA 提供商 %d", rule.CaddyID, rule.CAProviderID)
		}
	}
	for _, cert := range snapshot.Certs {
		if cert.CAProviderID == 0 {
			continue
		}
		if _, exists := providers[cert.CAProviderID]; !exists {
			return fmt.Errorf("快照证书 %s 引用了不存在的 CA 提供商 %d", cert.RuleID, cert.CAProviderID)
		}
	}
	return nil
}

func insertSnapshotRules(ctx context.Context, tx *sql.Tx, rules []models.LbRule) error {
	for _, rule := range rules {
		ipACLListJSON, err := json.Marshal(rule.IPACLList)
		if err != nil {
			return fmt.Errorf("序列化快照规则 %s 的 IP 访问控制列表: %w", rule.CaddyID, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO lb_rules (id,caddy_id,name,description,protocol,domain,listen_port,strategy,dynamic_dns,enable_dns_server,dns_server,dns_family,health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,ip_acl_mode,ip_acl_list,custom_routes_enabled,proxy_dial_timeout,proxy_response_header_timeout,proxy_read_timeout,proxy_write_timeout,proxy_stream_timeout,proxy_flush_interval,proxy_stream_close_delay,host_header,enable_tls,tls_source,acme_config_id,ca_provider_id,tls_cert,tls_key,tls_http_redirect,enable_compress,compress_types,enabled,log_enabled,created_by,updated_by,created_at,updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rule.ID, rule.CaddyID, rule.Name, rule.Description, rule.Protocol, rule.Domain, rule.ListenPort, rule.Strategy, rule.DynamicDNS, rule.EnableDnsServer, rule.DnsServer, rule.DnsFamily, rule.HealthCheckPath, rule.HealthCheckInterval, rule.HealthCheckTimeout, rule.HealthCheckUnhealthyThreshold, rule.HealthCheckHealthyThreshold, rule.EnableActiveHealthCheck, rule.TCPHealthCheckPort, rule.TCPProxyProtocol, rule.TCPTryDuration, rule.TCPTryInterval, rule.RequestBodyMaxSizeMB, rule.UpstreamKeepaliveTimeout, rule.ServerTokensHidden, rule.IPACLMode, string(ipACLListJSON), rule.CustomRoutesEnabled, rule.ProxyDialTimeout, rule.ProxyResponseHeaderTimeout, rule.ProxyReadTimeout, rule.ProxyWriteTimeout, rule.ProxyStreamTimeout, rule.ProxyFlushInterval, rule.ProxyStreamCloseDelay, rule.HostHeader, rule.EnableTLS, rule.TLSSource, rule.ACMEConfigID, rule.CAProviderID, rule.TLSCert, rule.TLSKey, rule.TLSHTTPRedirect, rule.EnableCompress, rule.CompressTypes, rule.Enabled, rule.LogEnabled, rule.CreatedBy, rule.UpdatedBy, rule.CreatedAt, nullableTime(rule.UpdatedAt.NullTime)); err != nil {
			return fmt.Errorf("写入快照规则 %s: %w", rule.CaddyID, err)
		}
		for _, upstream := range rule.Upstreams {
			if _, err := tx.ExecContext(ctx, `INSERT INTO upstreams (id,rule_id,host,port,weight,dynamic_dns,enabled,protocol,max_connections) VALUES (?,?,?,?,?,?,?,?,?)`, upstream.ID, rule.CaddyID, upstream.Host, upstream.Port, upstream.Weight, upstream.DynamicDNS, upstream.Enabled, upstream.Protocol, upstream.MaxConnections); err != nil {
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
	if settings.JWTExpireMinutes <= 0 || settings.JWTExpireMinutes > 1440 {
		settings.JWTExpireMinutes = 20
	}
	query := `UPDATE global_config SET log_level=?,cert_job_log_size_mb=?,runtime_log_size_mb=?,audit_retention_months=?,jwt_expire_minutes=?,timezone=?,acme_email=?,cert_expiry_days=?,cert_renewal_days=?,cert_renewal_attempts=?,default_ca_provider_id=?,dns_provider=?,dns_credentials=?,sync_interval=?,admin_tls_enabled=?,admin_tls_mode=?,admin_tls_cert=?,admin_tls_key=?`
	args := []any{settings.LogLevel, settings.CertJobLogSizeMB, settings.RuntimeLogSizeMB, settings.AuditRetentionMonths, settings.JWTExpireMinutes, settings.Timezone, settings.ACMEEmail, settings.CertExpiryDays, settings.CertRenewalDays, settings.CertRenewalAttempts, settings.DefaultCAProviderID, settings.DNSProvider, settings.DNSCredentials, settings.SyncInterval, settings.AdminTLSEnabled, settings.AdminTLSMode, settings.AdminTLSCert, settings.AdminTLSKey}
	if snapshot.CaddyConfig != nil {
		query += ",caddy_config=?,access_log_json=?,access_log_format=?,caddy_log_path=?,caddy_log_level=?,caddy_log_size_mb=?,request_body_max_size_mb=?,http_read_timeout=?,http_write_timeout=?,http_idle_timeout=?,upstream_keepalive_timeout=?,proxy_dial_timeout=?,proxy_response_header_timeout=?,proxy_read_timeout=?,proxy_write_timeout=?,proxy_stream_timeout=?,proxy_flush_interval=?,proxy_stream_close_delay=?,server_tokens_hidden=?"
		args = append(args, *snapshot.CaddyConfig, settings.AccessLogJSON, settings.AccessLogFormat, settings.CaddyLogPath, settings.CaddyLogLevel, settings.CaddyLogSizeMB,
			settings.RequestBodyMaxSizeMB, settings.HTTPReadTimeout, settings.HTTPWriteTimeout, settings.HTTPIdleTimeout,
			settings.UpstreamKeepaliveTimeout, settings.ProxyDialTimeout, settings.ProxyResponseHeaderTimeout, settings.ProxyReadTimeout, settings.ProxyWriteTimeout, settings.ProxyStreamTimeout, settings.ProxyFlushInterval, settings.ProxyStreamCloseDelay,
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

func nullableTime(value sql.NullTime) any {
	if !value.Valid {
		return nil
	}
	return value.Time
}
