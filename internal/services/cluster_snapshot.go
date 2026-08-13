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
	"sort"
	"sync"
	"time"

	"lazy-balancer-v2/internal/dnsprovider/ownership"
	"lazy-balancer-v2/internal/models"
)

// API Key 安全属性不能由旧读取端静默降级为宽权限默认值。
const CurrentSnapshotSchema = 3

type clusterSnapshotCache struct {
	mu          sync.Mutex
	initialized bool
	version     int
	snapshot    models.ClusterSnapshot
	canonical   json.RawMessage
	fingerprint string
	ownership   [sha256.Size]byte
	expiresAt   time.Time
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
	snapshot, canonical, fingerprint, err := s.cachedSnapshot(ctx)
	if err != nil {
		return models.ClusterSnapshot{}, false, err
	}
	snapshot.Fingerprint = fingerprint
	snapshot.CanonicalPayload = append(json.RawMessage(nil), canonical...)
	if tokenKey != "" {
		// The signature additionally binds the version, so a captured older
		// snapshot cannot be replayed even though its content hash is valid.
		mac := hmac.New(sha256.New, []byte(tokenKey))
		_, _ = mac.Write(canonical)
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

func (s *ClusterService) cachedSnapshot(ctx context.Context) (models.ClusterSnapshot, json.RawMessage, string, error) {
	value, _ := clusterSnapshotCaches.LoadOrStore(s.db, &clusterSnapshotCache{})
	cache := value.(*clusterSnapshotCache)
	cache.mu.Lock()
	defer cache.mu.Unlock()

	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("开启集群快照事务: %w", err)
	}
	defer tx.Rollback()

	var version int
	if err := tx.QueryRowContext(ctx, "SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1").Scan(&version); err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("读取集群版本: %w", err)
	}
	ownershipHash, err := snapshotOwnershipHash(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", err
	}
	now := s.snapshotNow()
	if cache.initialized && cache.version == version && cache.ownership == ownershipHash && (cache.expiresAt.IsZero() || now.Before(cache.expiresAt)) {
		return cache.snapshot, cache.canonical, cache.fingerprint, nil
	}
	snapshot, err := s.buildSnapshot(ctx, tx)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", err
	}
	snapshot.SchemaVersion = CurrentSnapshotSchema
	snapshot.MinReaderVersion = CurrentSnapshotSchema
	canonicalSnapshot := snapshot
	canonicalSnapshot.Fingerprint = ""
	canonicalSnapshot.Signature = ""
	canonicalSnapshot.CanonicalPayload = nil
	canonical, err := json.Marshal(canonicalSnapshot)
	if err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("序列化集群快照: %w", err)
	}
	hash := sha256.Sum256(canonical)
	fingerprint := hex.EncodeToString(hash[:])
	if err := tx.Commit(); err != nil {
		return models.ClusterSnapshot{}, nil, "", fmt.Errorf("提交集群快照事务: %w", err)
	}
	cache.initialized = true
	cache.version = snapshot.Version
	cache.snapshot = snapshot
	cache.canonical = canonical
	cache.fingerprint = fingerprint
	cache.ownership = ownershipHash
	cache.expiresAt = nearestSnapshotCertificateExpiry(snapshot.Certs)
	return snapshot, canonical, fingerprint, nil
}

func snapshotOwnershipHash(ctx context.Context, store snapshotStore) ([sha256.Size]byte, error) {
	dataDir, err := clusterSnapshotDataDir(ctx, store)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	content, err := os.ReadFile(filepath.Join(dataDir, "acme_dns_ownership.json"))
	if errors.Is(err, os.ErrNotExist) {
		content = []byte(`{"version":1,"records":[]}`)
	} else if err != nil {
		return [sha256.Size]byte{}, fmt.Errorf("读取 DNS 所有权状态: %w", err)
	}
	if err := validateDNSOwnership(content); err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(content), nil
}

func nearestSnapshotCertificateExpiry(certificates []models.ClusterCertificate) time.Time {
	var nearest time.Time
	for _, certificate := range certificates {
		if certificate.ExpiresAt == "" {
			continue
		}
		expiresAt, err := parseSnapshotExpiry(certificate.ExpiresAt)
		if err == nil && (nearest.IsZero() || expiresAt.Before(nearest)) {
			nearest = expiresAt
		}
	}
	return nearest
}

func parseSnapshotExpiry(value string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999-07:00", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("无法解析证书过期时间 %q", value)
}

func (s *ClusterService) buildSnapshot(ctx context.Context, store snapshotStore) (models.ClusterSnapshot, error) {
	var snapshot models.ClusterSnapshot
	var syncCaddy bool
	var caddyConfig string
	err := store.QueryRowContext(ctx, `SELECT COALESCE(cluster_version,0), COALESCE(sync_caddy_config,0), COALESCE(caddy_config,'{}'),
		COALESCE(log_level,'info'),
		COALESCE(cert_job_log_size_mb,10), COALESCE(audit_log_size_mb,10), COALESCE(runtime_log_size_mb,100), COALESCE(audit_retention_months,3), COALESCE(jwt_expire_minutes,20), COALESCE(timezone,'Asia/Shanghai'),
		COALESCE(acme_email,''), COALESCE(cert_expiry_days,30), COALESCE(cert_renewal_days,30), COALESCE(cert_renewal_attempts,5),
		COALESCE(default_ca_provider_id,0), COALESCE(dns_provider,''), COALESCE(dns_credentials,''), COALESCE(sync_interval,60),
		COALESCE(admin_tls_enabled,0), COALESCE(admin_tls_mode,'selfsigned'), COALESCE(admin_tls_cert,''), COALESCE(admin_tls_key,'')
		FROM global_config WHERE id=1`).Scan(&snapshot.Version, &syncCaddy, &caddyConfig,
		&snapshot.BasicSettings.LogLevel,
		&snapshot.BasicSettings.CertJobLogSizeMB, &snapshot.BasicSettings.AuditLogSizeMB, &snapshot.BasicSettings.RuntimeLogSizeMB, &snapshot.BasicSettings.AuditRetentionMonths, &snapshot.BasicSettings.JWTExpireMinutes, &snapshot.BasicSettings.Timezone,
		&snapshot.BasicSettings.ACMEEmail, &snapshot.BasicSettings.CertExpiryDays, &snapshot.BasicSettings.CertRenewalDays, &snapshot.BasicSettings.CertRenewalAttempts,
		&snapshot.BasicSettings.DefaultCAProviderID, &snapshot.BasicSettings.DNSProvider, &snapshot.BasicSettings.DNSCredentials, &snapshot.BasicSettings.SyncInterval,
		&snapshot.BasicSettings.AdminTLSEnabled, &snapshot.BasicSettings.AdminTLSMode, &snapshot.BasicSettings.AdminTLSCert, &snapshot.BasicSettings.AdminTLSKey)
	if err != nil {
		return models.ClusterSnapshot{}, fmt.Errorf("读取集群基础设置: %w", err)
	}
	if syncCaddy {
		snapshot.CaddyConfig = &caddyConfig
		if err := store.QueryRowContext(ctx, `SELECT COALESCE(caddy_log_path,'/app/logs/caddy.log'), COALESCE(caddy_log_level,'info'), COALESCE(caddy_log_size_mb,100),
			COALESCE(access_log_json,1), COALESCE(access_log_format,''),
			COALESCE(request_body_max_size_mb,0), COALESCE(http_read_timeout,0), COALESCE(http_write_timeout,0), COALESCE(http_idle_timeout,0),
			COALESCE(upstream_keepalive_timeout,0),
			COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
			COALESCE(server_tokens_hidden,0)
			FROM global_config WHERE id=1`).Scan(
			&snapshot.BasicSettings.CaddyLogPath, &snapshot.BasicSettings.CaddyLogLevel, &snapshot.BasicSettings.CaddyLogSizeMB,
			&snapshot.BasicSettings.AccessLogJSON, &snapshot.BasicSettings.AccessLogFormat,
			&snapshot.BasicSettings.RequestBodyMaxSizeMB, &snapshot.BasicSettings.HTTPReadTimeout, &snapshot.BasicSettings.HTTPWriteTimeout, &snapshot.BasicSettings.HTTPIdleTimeout,
			&snapshot.BasicSettings.UpstreamKeepaliveTimeout,
			&snapshot.BasicSettings.ProxyDialTimeout, &snapshot.BasicSettings.ProxyResponseHeaderTimeout, &snapshot.BasicSettings.ProxyReadTimeout, &snapshot.BasicSettings.ProxyWriteTimeout, &snapshot.BasicSettings.ProxyStreamTimeout, &snapshot.BasicSettings.ProxyFlushInterval, &snapshot.BasicSettings.ProxyStreamCloseDelay,
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
	if snapshot.SecurityPolicies, err = s.snapshotSecurityPolicies(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityBindings, err = s.snapshotSecurityBindings(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityCustomRules, err = s.snapshotSecurityCustomRules(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityBlockPages, err = s.snapshotSecurityBlockPages(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityCRSVersion, err = s.snapshotSecurityCRSVersion(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	if snapshot.SecurityIP2RegionVersion, err = s.snapshotSecurityIP2RegionVersion(ctx, store); err != nil {
		return models.ClusterSnapshot{}, err
	}
	return snapshot, nil
}

func (s *ClusterService) snapshotSecurityPolicies(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	return s.dumpTableAsJSON(ctx, store, "security_policies", "id,name,description,mode,anomaly_threshold,ip_acl_mode,ip_acl_list,ip_acl_enabled,ip_whitelist,ip_blacklist,rate_limit_enabled,rate_limit_rps,rate_limit_burst,crs_rule_groups,crs_excluded_rules,custom_rules,block_page_id,block_status_code,enabled,created_at,updated_at,geoip_countries,geoip_mode", "id")
}

func (s *ClusterService) snapshotSecurityBindings(ctx context.Context, store snapshotStore) (json.RawMessage, error) {
	return s.dumpTableAsJSON(ctx, store, "security_policy_bindings", "rule_caddy_id,policy_id", "rule_caddy_id")
}

func (s *ClusterService) snapshotSecurityCustomRules(ctx context.Context, store snapshotStore) ([]models.SecurityCustomRule, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,name,COALESCE(description,''),COALESCE(conditions,'[]'),COALESCE(action,'block'),COALESCE(score,5),COALESCE(status_code,403),COALESCE(enabled,1),COALESCE(updated_by,0),created_at,updated_at FROM security_custom_rules ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照自定义安全规则: %w", err)
	}
	defer rows.Close()
	rules := make([]models.SecurityCustomRule, 0)
	for rows.Next() {
		var rule models.SecurityCustomRule
		var conditionsJSON string
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.Description, &conditionsJSON, &rule.Action, &rule.Score, &rule.StatusCode, &rule.Enabled, &rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照自定义安全规则: %w", err)
		}
		if err := json.Unmarshal([]byte(conditionsJSON), &rule.Conditions); err != nil {
			return nil, fmt.Errorf("解析快照自定义安全规则 %d 的条件: %w", rule.ID, err)
		}
		rules = append(rules, rule)
	}
	return rules, rows.Err()
}

func (s *ClusterService) snapshotSecurityBlockPages(ctx context.Context, store snapshotStore) ([]models.SecurityBlockPage, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,name,COALESCE(description,''),COALESCE(content,''),COALESCE(status_code,403),COALESCE(is_default,0),COALESCE(created_by,0),created_at,COALESCE(updated_by,0),updated_at FROM security_block_pages ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照拦截页面: %w", err)
	}
	defer rows.Close()
	pages := make([]models.SecurityBlockPage, 0)
	for rows.Next() {
		var page models.SecurityBlockPage
		if err := rows.Scan(&page.ID, &page.Name, &page.Description, &page.Content, &page.StatusCode, &page.IsDefault, &page.CreatedBy, &page.CreatedAt, &page.UpdatedBy, &page.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照拦截页面: %w", err)
		}
		pages = append(pages, page)
	}
	return pages, rows.Err()
}

func (s *ClusterService) snapshotSecurityCRSVersion(ctx context.Context, store snapshotStore) ([]models.ClusterSecurityCRSVersion, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,version,COALESCE(updated_at,''),COALESCE(auto_update,1),COALESCE(update_status,'idle'),COALESCE(message,''),COALESCE(last_checked,''),COALESCE(next_update,''),COALESCE(trigger,''),COALESCE(started_at,''),COALESCE(finished_at,'') FROM security_crs_version ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 CRS 版本: %w", err)
	}
	defer rows.Close()
	versions := make([]models.ClusterSecurityCRSVersion, 0)
	for rows.Next() {
		var version models.ClusterSecurityCRSVersion
		if err := rows.Scan(&version.ID, &version.Version, &version.UpdatedAt, &version.AutoUpdate, &version.UpdateStatus, &version.Message, &version.LastChecked, &version.NextUpdate, &version.Trigger, &version.StartedAt, &version.FinishedAt); err != nil {
			return nil, fmt.Errorf("扫描快照 CRS 版本: %w", err)
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (s *ClusterService) snapshotSecurityIP2RegionVersion(ctx context.Context, store snapshotStore) ([]models.ClusterSecurityIP2RegionVersion, error) {
	rows, err := store.QueryContext(ctx, `SELECT id,version,COALESCE(updated_at,''),COALESCE(auto_update,1),COALESCE(update_status,'idle'),COALESCE(message,''),COALESCE(last_checked,''),COALESCE(next_update,''),COALESCE(trigger,''),COALESCE(started_at,''),COALESCE(finished_at,'') FROM security_ip2region_version ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 ip2region 版本: %w", err)
	}
	defer rows.Close()
	versions := make([]models.ClusterSecurityIP2RegionVersion, 0)
	for rows.Next() {
		var version models.ClusterSecurityIP2RegionVersion
		if err := rows.Scan(&version.ID, &version.Version, &version.UpdatedAt, &version.AutoUpdate, &version.UpdateStatus, &version.Message, &version.LastChecked, &version.NextUpdate, &version.Trigger, &version.StartedAt, &version.FinishedAt); err != nil {
			return nil, fmt.Errorf("扫描快照 ip2region 版本: %w", err)
		}
		versions = append(versions, version)
	}
	return versions, rows.Err()
}

func (s *ClusterService) dumpTableAsJSON(ctx context.Context, store snapshotStore, table, columns, orderBy string) (json.RawMessage, error) {
	rows, err := store.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM %s ORDER BY %s", columns, table, orderBy))
	if err != nil {
		return nil, fmt.Errorf("读取 %s: %w", table, err)
	}
	defer rows.Close()
	colNames, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]interface{}, 0)
	for rows.Next() {
		values := make([]interface{}, len(colNames))
		ptrs := make([]interface{}, len(colNames))
		for i := range values {
			ptrs[i] = &values[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		row := make(map[string]interface{})
		for i, col := range colNames {
			row[col] = values[i]
		}
		result = append(result, row)
	}
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if string(data) == "null" {
		data = []byte("[]")
	}
	return data, nil
}

func (s *ClusterService) snapshotACME(ctx context.Context, store snapshotStore) (*models.ClusterACMEState, error) {
	state := &models.ClusterACMEState{CAProviders: make([]models.CAProvider, 0), CertificateConfigs: make([]models.CertificateConfig, 0)}
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
	if err := validateDNSOwnership(ownership); err != nil {
		return nil, err
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
		COALESCE(health_check_path,''), COALESCE(health_check_interval,10), COALESCE(health_check_timeout,2), COALESCE(health_check_unhealthy_threshold,3), COALESCE(health_check_healthy_threshold,2),
		COALESCE(enable_active_health_check,0), COALESCE(tcp_health_check_port,0), COALESCE(tcp_proxy_protocol,0), COALESCE(tcp_try_duration,0), COALESCE(tcp_try_interval,250),
		COALESCE(request_body_max_size_mb,0), COALESCE(upstream_keepalive_timeout,0), COALESCE(server_tokens_hidden,0), COALESCE(host_header,''),
		COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(custom_routes_enabled,0),
		COALESCE(proxy_dial_timeout,0), COALESCE(proxy_response_header_timeout,0), COALESCE(proxy_read_timeout,0), COALESCE(proxy_write_timeout,0), COALESCE(proxy_stream_timeout,0), COALESCE(proxy_flush_interval,0), COALESCE(proxy_stream_close_delay,0),
		COALESCE(enable_tls,0), COALESCE(tls_source,'manual'), COALESCE(acme_config_id,0), COALESCE(ca_provider_id,0), COALESCE(tls_cert,''), COALESCE(tls_key,''),
		COALESCE(tls_http_redirect,0), COALESCE(enable_compress,1), COALESCE(compress_types,'gzip'), COALESCE(enabled,1), COALESCE(log_enabled,0), COALESCE(created_by,0), COALESCE(updated_by,0), created_at, updated_at
		FROM lb_rules ORDER BY caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照规则: %w", err)
	}
	defer rows.Close()

	upstreamsByRule, err := s.snapshotAllUpstreams(ctx, store)
	if err != nil {
		return nil, err
	}
	pathRulesByRule, err := s.snapshotAllPathRules(ctx, store)
	if err != nil {
		return nil, err
	}

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
			&rule.ProxyDialTimeout, &rule.ProxyResponseHeaderTimeout, &rule.ProxyReadTimeout, &rule.ProxyWriteTimeout, &rule.ProxyStreamTimeout, &rule.ProxyFlushInterval, &rule.ProxyStreamCloseDelay,
			&rule.EnableTLS, &rule.TLSSource, &rule.ACMEConfigID, &rule.CAProviderID, &rule.TLSCert, &rule.TLSKey,
			&rule.TLSHTTPRedirect, &rule.EnableCompress, &rule.CompressTypes, &rule.Enabled, &rule.LogEnabled, &rule.CreatedBy, &rule.UpdatedBy, &rule.CreatedAt, &rule.UpdatedAt); err != nil {
			return nil, fmt.Errorf("扫描快照规则: %w", err)
		}
		if err := json.Unmarshal([]byte(ipACLListJSON), &rule.IPACLList); err != nil {
			return nil, fmt.Errorf("解析快照规则 %s 的 IP 访问控制列表: %w", rule.CaddyID, err)
		}
		rule.Upstreams = upstreamsByRule[rule.CaddyID]
		if rule.Upstreams == nil {
			rule.Upstreams = make([]models.Upstream, 0)
		}
		rule.PathRules = pathRulesByRule[rule.CaddyID]
		if rule.PathRules == nil {
			rule.PathRules = make([]models.PathRule, 0)
		}
		rules = append(rules, rule)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照规则: %w", err)
	}
	return rules, nil
}

func (s *ClusterService) snapshotAllUpstreams(ctx context.Context, store snapshotStore) (map[string][]models.Upstream, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, rule_id, host, port, COALESCE(weight,1), COALESCE(dynamic_dns,0), COALESCE(enabled,1), COALESCE(protocol,'http'), COALESCE(max_connections,0) FROM upstreams ORDER BY rule_id, id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照上游: %w", err)
	}
	defer rows.Close()
	byRule := make(map[string][]models.Upstream)
	for rows.Next() {
		var upstream models.Upstream
		if err := rows.Scan(&upstream.ID, &upstream.RuleID, &upstream.Host, &upstream.Port, &upstream.Weight, &upstream.DynamicDNS, &upstream.Enabled, &upstream.Protocol, &upstream.MaxConnections); err != nil {
			return nil, fmt.Errorf("扫描快照上游: %w", err)
		}
		byRule[upstream.RuleID] = append(byRule[upstream.RuleID], upstream)
	}
	return byRule, rows.Err()
}

func (s *ClusterService) snapshotAllPathRules(ctx context.Context, store snapshotStore) (map[string][]models.PathRule, error) {
	rows, err := store.QueryContext(ctx, `SELECT id, rule_id, sort_order, match_type, path, upstreams_json FROM path_rules ORDER BY rule_id, sort_order, id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照路径规则: %w", err)
	}
	defer rows.Close()
	byRule := make(map[string][]models.PathRule)
	for rows.Next() {
		var pathRule models.PathRule
		var upstreamsJSON sql.NullString
		if err := rows.Scan(&pathRule.ID, &pathRule.RuleID, &pathRule.SortOrder, &pathRule.MatchType, &pathRule.Path, &upstreamsJSON); err != nil {
			return nil, fmt.Errorf("扫描快照路径规则: %w", err)
		}
		if upstreamsJSON.Valid {
			if err := json.Unmarshal([]byte(upstreamsJSON.String), &pathRule.Upstreams); err != nil {
				return nil, fmt.Errorf("解析快照路径规则 %d 的上游: %w", pathRule.ID, err)
			}
		}
		byRule[pathRule.RuleID] = append(byRule[pathRule.RuleID], pathRule)
	}
	return byRule, rows.Err()
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

	rows, err = store.QueryContext(ctx, `SELECT r.caddy_id,r.domain,j.domain,j.cert_pem,j.key_pem,COALESCE(j.expires_at,''),COALESCE(j.ca_provider_id,0),j.status,
		COALESCE(j.renewal_attempts,0),j.ca_available_after,COALESCE(j.last_error_code,''),COALESCE(julianday(COALESCE(j.updated_at,j.created_at)),0),j.id
		FROM lb_rules r JOIN cert_jobs j ON j.rule_id=r.caddy_id
		WHERE r.enabled=1 AND r.enable_tls=1 AND r.tls_source='acme_dns' AND j.status<>'disabled'
		AND COALESCE(j.cert_pem,'')<>'' AND COALESCE(j.key_pem,'')<>''
		ORDER BY r.caddy_id`)
	if err != nil {
		return nil, fmt.Errorf("读取快照 ACME 证书: %w", err)
	}
	defer rows.Close()
	type snapshotCertificateCandidate struct {
		selection CertificateCandidate
		snapshot  models.ClusterCertificate
	}
	candidatesByRule := make(map[string][]snapshotCertificateCandidate)
	ruleDomains := make(map[string]string)
	now := s.snapshotNow()
	for rows.Next() {
		var cert models.ClusterCertificate
		var ruleDomain string
		var candidate CertificateCandidate
		if err := rows.Scan(&cert.RuleID, &ruleDomain, &cert.Domain, &cert.CertPEM, &cert.KeyPEM, &cert.ExpiresAt, &cert.CAProviderID, &cert.SourceStatus, &cert.RenewalAttempts, &cert.CAAvailableAfter, &cert.LastErrorCode, &candidate.UpdatedAt, &candidate.ID); err != nil {
			return nil, fmt.Errorf("扫描快照 ACME 证书: %w", err)
		}
		canonicalRuleDomain, err := CanonicalACMEDomains(ruleDomain)
		if err != nil {
			return nil, fmt.Errorf("规范化快照规则 %s 域名: %w", cert.RuleID, err)
		}
		candidate.Domain = cert.Domain
		candidate.Status = cert.SourceStatus
		candidate.CertPEM = cert.CertPEM
		candidate.KeyPEM = cert.KeyPEM
		if _, valid := SelectCertificate([]CertificateCandidate{candidate}, canonicalRuleDomain, now); !valid {
			warnSnapshotCertificateCandidate(cert.RuleID, int(candidate.ID), errors.New("证书、私钥、有效期或域名覆盖无效"), now)
			continue
		}
		cert.Domain = canonicalRuleDomain
		ruleDomains[cert.RuleID] = canonicalRuleDomain
		candidatesByRule[cert.RuleID] = append(candidatesByRule[cert.RuleID], snapshotCertificateCandidate{selection: candidate, snapshot: cert})
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("遍历快照 ACME 证书: %w", err)
	}
	ruleIDs := make([]string, 0, len(candidatesByRule))
	for ruleID := range candidatesByRule {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)
	for _, ruleID := range ruleIDs {
		selectionCandidates := make([]CertificateCandidate, 0, len(candidatesByRule[ruleID]))
		for _, candidate := range candidatesByRule[ruleID] {
			selectionCandidates = append(selectionCandidates, candidate.selection)
		}
		selection, selected := SelectCertificate(selectionCandidates, ruleDomains[ruleID], now)
		if !selected {
			continue
		}
		for _, candidate := range candidatesByRule[ruleID] {
			if candidate.selection.ID == selection.Candidate.ID {
				certs = append(certs, candidate.snapshot)
				break
			}
		}
	}
	return certs, nil
}

var snapshotCertificateWarnings = struct {
	sync.Mutex
	last map[string]time.Time
}{last: make(map[string]time.Time)}

// snapshotCertificateWarningsGCTtl 控制警告 map 中条目的最长保留时间。
// 超过此时间未被再次更新的条目会在下次 warnSnapshotCertificateCandidate 调用时被清理。
const snapshotCertificateWarningsGCTtl = time.Hour

func warnSnapshotCertificateCandidate(ruleID string, jobID int, cause error, now time.Time) {
	key := fmt.Sprintf("%s/%d", ruleID, jobID)
	snapshotCertificateWarnings.Lock()
	last := snapshotCertificateWarnings.last[key]
	if !last.IsZero() && now.Sub(last) < 5*time.Minute {
		snapshotCertificateWarnings.Unlock()
		return
	}
	snapshotCertificateWarnings.last[key] = now
	// Round 35 I-13: 顺手清理过期条目，防止长期运行 master 节点的 map 无限增长。
	for k, t := range snapshotCertificateWarnings.last {
		if now.Sub(t) > snapshotCertificateWarningsGCTtl {
			delete(snapshotCertificateWarnings.last, k)
		}
	}
	snapshotCertificateWarnings.Unlock()
	Logf("warn", "cluster snapshot skipped malformed certificate candidate: rule_id=%s job_id=%d error=%v", ruleID, jobID, cause)
}

func validateDNSOwnership(data []byte) error {
	var state struct {
		Version int                `json:"version"`
		Records []ownership.Record `json:"records"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("DNS 所有权状态不是有效 JSON: %w", err)
	}
	if state.Version != 1 || state.Records == nil {
		return errors.New("DNS 所有权状态格式无效")
	}
	for _, record := range state.Records {
		if record.Provider == "" || record.Zone == "" || record.FQDN == "" || record.Value == "" || record.RecordID == "" {
			return errors.New("DNS 所有权记录缺少 provider、zone、fqdn、value 或 record_id")
		}
	}
	return nil
}
