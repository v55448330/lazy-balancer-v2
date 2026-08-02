package services

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// API Key 安全属性不能由旧读取端静默降级为宽权限默认值。
const CurrentSnapshotSchema = 2

type clusterSnapshotCache struct {
	mu          sync.Mutex
	initialized bool
	version     int
	snapshot    models.ClusterSnapshot
}

var clusterSnapshotCaches sync.Map

type snapshotStore interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

// Snapshot builds the full cluster snapshot. tokenKey signs the payload with
// the requesting node's cluster token (HMAC-SHA256) so slaves can verify
// authenticity, not just integrity; leave empty to skip signing (legacy path).
func (s *ClusterService) Snapshot(ctx context.Context, sinceVersion int, clientFingerprint string, tokenKey string) (models.ClusterSnapshot, bool, error) {
	s.retryPendingPinCleanup()
	snapshot, err := s.cachedSnapshot(ctx)
	if err != nil {
		return models.ClusterSnapshot{}, false, err
	}
	snapshot.SchemaVersion = CurrentSnapshotSchema
	snapshot.MinReaderVersion = CurrentSnapshotSchema
	canonical := snapshot
	canonical.Fingerprint = ""
	canonical.Version = 0
	content, err := json.Marshal(canonical)
	if err != nil {
		return models.ClusterSnapshot{}, false, fmt.Errorf("序列化集群快照: %w", err)
	}
	hash := sha256.Sum256(content)
	snapshot.Fingerprint = hex.EncodeToString(hash[:])
	if tokenKey != "" {
		// The signature additionally binds the version, so a captured older
		// snapshot cannot be replayed even though its content hash is valid.
		signed := snapshot
		signed.Fingerprint = ""
		signed.Signature = ""
		signedContent, err := json.Marshal(signed)
		if err != nil {
			return models.ClusterSnapshot{}, false, fmt.Errorf("序列化快照签名内容: %w", err)
		}
		mac := hmac.New(sha256.New, []byte(tokenKey))
		mac.Write(signedContent)
		snapshot.Signature = hex.EncodeToString(mac.Sum(nil))
		if _, err := s.db.ExecContext(ctx, "UPDATE nodes SET registration_secret=NULL, registration_secret_expires_at=NULL WHERE cluster_token_hash=? AND registration_secret IS NOT NULL", tokenHash(tokenKey)); err != nil {
			return models.ClusterSnapshot{}, false, fmt.Errorf("确认旧协议集群令牌交付: %w", err)
		}
	}
	if sinceVersion >= snapshot.Version && clientFingerprint != "" && clientFingerprint == snapshot.Fingerprint {
		return snapshot, false, nil
	}
	return snapshot, true, nil
}

func (s *ClusterService) ConfirmRegistration(ctx context.Context, token string) error {
	result, err := s.db.ExecContext(ctx, "UPDATE nodes SET registration_secret=NULL WHERE cluster_token_hash=?", tokenHash(token))
	if err != nil {
		return fmt.Errorf("确认集群令牌交付: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("读取集群令牌确认结果: %w", err)
	}
	if updated == 0 {
		return ErrInvalidClusterAuth
	}
	return nil
}

func (s *ClusterService) cachedSnapshot(ctx context.Context) (models.ClusterSnapshot, error) {
	value, _ := clusterSnapshotCaches.LoadOrStore(s.db, &clusterSnapshotCache{})
	cache := value.(*clusterSnapshotCache)
	cache.mu.Lock()
	defer cache.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("开启集群快照事务: %w", err)
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&version); err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取集群版本: %w", err)
	}
	if cache.initialized && cache.version == version {
		return cache.snapshot, nil
	}
	snapshot, err := s.buildSnapshot(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, err
	}
	if err := tx.Commit(); err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("提交集群快照事务: %w", err)
	}
	cache.initialized = true
	cache.version = snapshot.Version
	cache.snapshot = snapshot
	return snapshot, nil
}

func (s *ClusterService) buildSnapshot(ctx context.Context, store snapshotStore) (models.ClusterSnapshot, error) {
	var snapshot models.ClusterSnapshot
	var syncCaddy bool
	var caddyConfig string
	err := store.QueryRowContext(ctx, `SELECT COALESCE(cluster_version,0), COALESCE(sync_caddy_config,0), COALESCE(caddy_config,'{}'),
		COALESCE(log_level,'info'), COALESCE(access_log_json,1), COALESCE(access_log_format,''),
		COALESCE(cert_job_log_size_mb,10), COALESCE(runtime_log_size_mb,100), COALESCE(audit_retention_months,3), COALESCE(jwt_expire_minutes,20), COALESCE(timezone,'Asia/Shanghai'),
		COALESCE(acme_email,''), COALESCE(cert_expiry_days,30), COALESCE(cert_renewal_days,30), COALESCE(cert_renewal_attempts,5),
		COALESCE(default_ca_provider_id,0), COALESCE(dns_provider,''), COALESCE(dns_credentials,''), COALESCE(sync_interval,60),
		COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'), COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,'')
		FROM global_config WHERE id=1`).Scan(&snapshot.Version, &syncCaddy, &caddyConfig,
		&snapshot.BasicSettings.LogLevel, &snapshot.BasicSettings.AccessLogJSON, &snapshot.BasicSettings.AccessLogFormat,
		&snapshot.BasicSettings.CertJobLogSizeMB, &snapshot.BasicSettings.RuntimeLogSizeMB, &snapshot.BasicSettings.AuditRetentionMonths, &snapshot.BasicSettings.JWTExpireMinutes, &snapshot.BasicSettings.Timezone,
		&snapshot.BasicSettings.ACMEEmail, &snapshot.BasicSettings.CertExpiryDays, &snapshot.BasicSettings.CertRenewalDays, &snapshot.BasicSettings.CertRenewalAttempts,
		&snapshot.BasicSettings.DefaultCAProviderID, &snapshot.BasicSettings.DNSProvider, &snapshot.BasicSettings.DNSCredentials, &snapshot.BasicSettings.SyncInterval,
		&snapshot.BasicSettings.AdminTLSEnabled, &snapshot.BasicSettings.AdminTLSMode, &snapshot.BasicSettings.AdminTLSCert, &snapshot.BasicSettings.AdminTLSKey)
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取集群基础设置: %w", err)
	}
	if syncCaddy {
		snapshot.CaddyConfig = &caddyConfig
		if err := store.QueryRowContext(ctx, `SELECT COALESCE(caddy_log_path,'/app/logs/caddy.log'), COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
			COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0), COALESCE(http_idle_timeout,0),
			COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
			COALESCE(server_tokens_hidden,0)
			FROM global_config WHERE id=1`).Scan(
			&snapshot.BasicSettings.CaddyLogPath, &snapshot.BasicSettings.CaddyLogLevel, &snapshot.BasicSettings.CaddyLogSizeMB,
			&snapshot.BasicSettings.RequestBodyMaxSizeMB, &snapshot.BasicSettings.HTTPReadTimeout, &snapshot.BasicSettings.HTTPWriteTimeout, &snapshot.BasicSettings.HTTPIdleTimeout,
			&snapshot.BasicSettings.UpstreamKeepaliveTimeout,
			&snapshot.BasicSettings.ProxyDialTimeout, &snapshot.BasicSettings.ProxyResponseHeaderTimeout, &snapshot.BasicSettings.ProxyReadTimeout, &snapshot.BasicSettings.ProxyWriteTimeout, &snapshot.BasicSettings.ProxyStreamTimeout,
			&snapshot.BasicSettings.ServerTokensHidden); err != nil {
			return models.ClusterSnapshot{}, fmt.Errorf("读取 Caddy 全局设置: %w", err)
		}
	}
	if snapshot.Rules, err = s.snapshotRules(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Users, err = s.snapshotUsers(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.APIKeys, err = s.snapshotAPIKeys(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.Certs, err = s.snapshotCertificates(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.ACME, err = s.snapshotACME(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	return snapshot, nil
}

func (s *ClusterService) snapshotACME(ctx context.Context, store snapshotStore) (*models.ClusterACMEState, error) {
	state := &models.ClusterACMEState{}
	rows, err := store.QueryContext(ctx, `SELECT id,name,provider,directory_url,COALESCE(credentials,''),COALESCE(max_concurrent,1),COALESCE(min_interval_ms,2000),COALESCE(enabled,1),created_at,updated_at FROM ca_providers ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 CA 提供商: %w", err)
	}
	for rows.Next() {
		var provider models.CAProvider
		if err := rows.Scan(&provider.ID, &provider.Name, &provider.Provider, &provider.DirectoryURL, &provider.Credentials, &provider.MaxConcurrent, &provider.MinIntervalMS, &provider.Enabled, &provider.CreatedAt, &provider.UpdatedAt); err != nil {
			rows.Close()
			return nil, fmt.Errorf("扫描快照 CA 提供商: %w", err)
		}
		state.CAProviders = append(state.CAProviders, provider)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("关闭 CA 提供商结果: %w", err)
	}

	rows, err = store.QueryContext(ctx, `SELECT id,name,COALESCE(dns_provider,'dnspod'),COALESCE(dns_credentials,''),COALESCE(enabled,1),created_at,updated_at FROM certificate_configs ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照证书配置: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var config models.CertificateConfig
		if err := rows.Scan(&config.ID, &config.Name, &config.DNSProvider, &config.DNSCredentials, &config.Enabled, &config.CreatedAt, &config.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照证书配置: %w", err)
		}
		state.CertificateConfigs = append(state.CertificateConfigs, config)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照证书配置: %w", err)
	}
	dataDir, err := clusterSnapshotDataDir(ctx, store)
	if err != nil {
		return nil, err
	}
	ownership, err := os.ReadFile(filepath.Join(dataDir, "acme_dns_ownership.json"))
	if errors.Is(err, os.ErrNotExist) {
		ownership = []byte(`{"version":1,"records":[]}`)
	} else if err != nil {
		return nil, fmt.Errorf("读取 DNS 所有权状态: %w", err)
	}
	if !json.Valid(ownership) {
		return nil, errors.New("DNS 所有权状态不是有效 JSON")
	}
	state.DNSOwnership = ownership
	return state, nil
}

func clusterSnapshotDataDir(ctx context.Context, store snapshotStore) (string, error) {
	var sequence int
	var name, databasePath string
	if err := store.QueryRowContext(ctx, "PRAGMA database_list").Scan(&sequence, &name, &databasePath); err != nil {
		return "", fmt.Errorf("读取集群数据库路径: %w", err)
	}
	if databasePath == "" {
		return "", errors.New("无法确定集群数据目录")
	}
	return filepath.Dir(databasePath), nil
}

func clusterDatabaseDir(database *sql.DB) (string, error) {
	var sequence int
	var name, databasePath string
	if err := database.QueryRow("PRAGMA database_list").Scan(&sequence, &name, &databasePath); err != nil {
		return "", fmt.Errorf("读取集群数据库路径: %w", err)
	}
	if databasePath == "" {
		return "", errors.New("无法确定集群数据目录")
	}
	return filepath.Dir(databasePath), nil
}

func (s *ClusterService) snapshotRules(ctx context.Context, store snapshotStore) ([]models.LbRule, error) {
	rows, err := store.QueryContext(ctx, `SELECT COALESCE(id,0), COALESCE(caddy_id,''), name, COALESCE(description,''), protocol, COALESCE(domain,''), listen_port,
		COALESCE(strategy,'weighted_round_robin'), COALESCE(dynamic_dns,0), COALESCE(enable_dns_server,0), COALESCE(dns_server,''), COALESCE(dns_family,'ipv4'),
		COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,5), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(host_header,''),
		COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0),
		COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), COALESCE(enabled,1), COALESCE(log_enabled,0), COALESCE(created_by,0), COALESCE(updated_by,0), created_at, updated_at
		FROM lb_rules ORDER BY caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照规则: %w", err)
	}
	defer rows.Close()
	rules := make([]models.LbRule, 0)
	for rows.Next() {
		var rule models.LbRule
		var ipACLListJSON string
		if err := rows.Scan(&rule.ID, &rule.CaddyID, &rule.Name, &rule.Description, &rule.Protocol, &rule.Domain, &rule.ListenPort,
			&rule.Strategy, &rule.DynamicDNS, &rule.EnableDnsServer, &rule.DnsServer, &rule.DnsFamily,
			&rule.HealthCheckPath, &rule.HealthCheckInterval, &rule.HealthCheckTimeout, &rule.HealthCheckUnhealthyThreshold, &rule.HealthCheckHealthyThreshold,
			&rule.EnableActiveHealthCheck, &rule.TCPHealthCheckPort, &rule.TCPProxyProtocol, &rule.TCPTryDuration, &rule.TCPTryInterval,
			&rule.RequestBodyMaxSizeMB, &rule.UpstreamKeepaliveTimeout, &rule.ServerTokensHidden, &rule.HostHeader,
			&rule.IPACLMode, &ipACLListJSON, &rule.CustomRoutesEnabled,
			&rule.ProxyDialTimeout, &rule.ProxyResponseHeaderTimeout, &rule.ProxyReadTimeout, &rule.ProxyWriteTimeout, &rule.ProxyStreamTimeout,
			&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.CAProviderID, &rule.TLSCert, &rule.TLSKey,
			&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.LogEnabled, &rule.CreatedBy, &rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照规则: %w", err)
		}
		if err := json.Unmarshal([]byte(ipACLListJSON), &rule.IPACLList); err != nil {
			return nil, fmt.Errorf("解析快照规则 %s 的 IP 访问控制列表: %w", rule.CaddyID, err)
		}
		upstreams, upstreamErr := s.snapshotUpstreams(ctx, store, rule.CaddyID)
		if upstreamErr != nil {
			return nil, upstreamErr
		}
		rule.Upstreams = upstreams
		pathRules, pathRulesErr := s.snapshotPathRules(ctx, store, rule.CaddyID)
		if pathRulesErr != nil {
			return nil, pathRulesErr
		}
		rule.PathRules = pathRules
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照规则: %w", err)
	}
	return rules, nil
}

func (s *ClusterService) snapshotPathRules(ctx context.Context, store snapshotStore, ruleID string) ([]models.PathRule, error) {
	return db.LoadPathRules(ctx, store, ruleID)
}

func (s *ClusterService) snapshotUpstreams(ctx context.Context, store snapshotStore, ruleID string) ([]models.Upstream, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(domain,''), COALESCE(dynamic_dns,0), COALESCE(enabled,1), COALESCE(protocol,'http'), COALESCE(dns_server,''), COALESCE(max_connections,0) FROM upstreams WHERE rule_id=? ORDER BY id`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("读取规则上游 %s: %w", ruleID, err)
	}
	defer rows.Close()
	upstreams := make([]models.Upstream, 0)
	for rows.Next() {
		var upstream models.Upstream
		if err := rows.Scan(&upstream.ID, &upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Weight, &upstream.Domain, &upstream.DynamicDNS, &upstream.Enabled, &upstream.Protocol, &upstream.DnsServer, &upstream.MaxConnections); err != nil {
			return nil, fmt.Errorf("扫描规则上游 %s: %w", ruleID, err)
		}
		upstreams = append(upstreams, upstream)
	}
	return upstreams, rows.Err()
}

func (s *ClusterService) snapshotUsers(ctx context.Context, store snapshotStore) ([]models.ClusterUser, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, username, password_hash, role, COALESCE(display_name,''), COALESCE(is_enabled,1),
		COALESCE(password_version,0), strftime('%Y-%m-%dT%H:%M:%fZ', password_changed_at), created_at, last_login FROM users ORDER BY username`)
	if err != nil {
		return nil, fmt.Errorf("读取快照用户: %w", err)
	}
	defer rows.Close()
	users := make([]models.ClusterUser, 0)
	for rows.Next() {
		var user models.ClusterUser
		var passwordChangedAt sql.NullString
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.Role, &user.DisplayName, &user.IsEnabled, &user.PasswordVersion, &passwordChangedAt, &user.CreatedAt, &user.LastLogin); err != nil {
			return nil, fmt.Errorf("扫描快照用户: %w", err)
		}
		if passwordChangedAt.Valid {
			user.PasswordChangedAt = &passwordChangedAt.String
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (s *ClusterService) snapshotAPIKeys(ctx context.Context, store snapshotStore) ([]models.ClusterAPIKey, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, name, key_hash, key_prefix, created_by, COALESCE(expires_at,''), COALESCE(is_enabled,1), COALESCE(mcp_enabled,0), COALESCE(read_only,0), COALESCE(mcp_ip_whitelist,'') FROM api_keys ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照密钥: %w", err)
	}
	defer rows.Close()
	keys := make([]models.ClusterAPIKey, 0)
	for rows.Next() {
		var key models.ClusterAPIKey
		var whitelistJSON string
		if err := rows.Scan(&key.ID, &key.Name, &key.KeyHash, &key.KeyPrefix, &key.CreatedBy, &key.ExpiresAt, &key.IsEnabled, &key.MCPEnabled, &key.ReadOnly, &whitelistJSON); err != nil {
			return nil, fmt.Errorf("扫描快照密钥: %w", err)
		}
		if whitelistJSON != "" {
			if err := json.Unmarshal([]byte(whitelistJSON), &key.MCPIPWhitelist); err != nil {
				return nil, fmt.Errorf("解析快照密钥 %d 的 MCP IP 白名单: %w", key.ID, err)
			}
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (s *ClusterService) snapshotCertificates(ctx context.Context, store snapshotStore) ([]models.ClusterCertificate, error) {
	rows, err := store.QueryContext(ctx, `SELECT caddy_id, tls_cert, tls_key FROM lb_rules WHERE enable_tls=1 AND tls_source='manual' AND COALESCE(tls_cert,'')<>'' AND COALESCE(tls_key,'')<>'' ORDER BY caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照证书: %w", err)
	}
	certs := make([]models.ClusterCertificate, 0)
	for rows.Next() {
		var cert models.ClusterCertificate
		if err := rows.Scan(&cert.RuleID, &cert.CertPEM, &cert.KeyPEM); err != nil {
			rows.Close()
			return nil, fmt.Errorf("扫描快照证书: %w", err)
		}
		certs = append(certs, cert)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("关闭手工证书结果: %w", err)
	}

	rows, err = store.QueryContext(ctx, `SELECT r.caddy_id,r.domain,j.domain,j.cert_pem,j.key_pem,COALESCE(j.expires_at,''),COALESCE(j.ca_provider_id,0),j.status
		FROM lb_rules r JOIN cert_jobs j ON j.rule_id=r.caddy_id
		WHERE r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' AND j.status<>'disabled'
		AND COALESCE(j.cert_pem,'')<>'' AND COALESCE(j.key_pem,'')<>'' AND datetime(j.expires_at)>datetime('now')
		ORDER BY r.caddy_id,COALESCE(j.updated_at,j.created_at) DESC,j.id DESC`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 ACME 证书: %w", err)
	}
	defer rows.Close()
	selected := make(map[string]struct{})
	for rows.Next() {
		var cert models.ClusterCertificate
		var ruleDomain string
		if err := rows.Scan(&cert.RuleID, &ruleDomain, &cert.Domain, &cert.CertPEM, &cert.KeyPEM, &cert.ExpiresAt, &cert.CAProviderID, &cert.SourceStatus); err != nil {
			return nil, fmt.Errorf("扫描快照 ACME 证书: %w", err)
		}
		if _, exists := selected[cert.RuleID]; exists {
			continue
		}
		canonicalRuleDomain, err := CanonicalACMEDomains(ruleDomain)
		if err != nil {
			return nil, fmt.Errorf("规范化快照规则 %s 域名: %w", cert.RuleID, err)
		}
		canonicalJobDomain, err := CanonicalACMEDomains(cert.Domain)
		if err != nil || canonicalJobDomain != canonicalRuleDomain {
			continue
		}
		cert.Domain = canonicalJobDomain
		selected[cert.RuleID] = struct{}{}
		certs = append(certs, cert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照 ACME 证书: %w", err)
	}
	return certs, nil
}
