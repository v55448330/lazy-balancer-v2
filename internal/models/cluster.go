package models

import (
	"encoding/json"
	"errors"
	"net/url"
	"time"
)

var ErrInvalidClusterAccessURL = errors.New("访问地址必须是无凭证、查询参数或片段的 HTTP 或 HTTPS URL")

type ClusterRegisterRequest struct {
	Token     string `json:"token" binding:"required"`
	Name      string `json:"name" binding:"required"`
	IPAddress string `json:"ip_address" binding:"required,ip"`
	Port      int    `json:"port" binding:"omitempty,min=1,max=65535"`
	Protocol  string `json:"protocol" binding:"omitempty,oneof=http https"`
	AccessURL string `json:"access_url"`
}

type ClusterNodeAccessURLRequest struct {
	AccessURL string `json:"access_url"`
}

func ValidateClusterAccessURL(value string) error {
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil || parsed.Opaque != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ErrInvalidClusterAccessURL
	}
	return nil
}

type ClusterLoginTicketRequest struct {
	Ticket string `json:"ticket" binding:"required"`
}

type ClusterLoginTicketClaims struct {
	UserID    int    `json:"user_id"`
	Username  string `json:"username"`
	NodeID    int    `json:"node_id"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"`
}

// 集群服务控制动作（主节点 → 从节点）：Caddy 进程启停与应用进程重启。
const (
	ClusterServiceActionStartCaddy   = "start_caddy"
	ClusterServiceActionStopCaddy    = "stop_caddy"
	ClusterServiceActionRestartCaddy = "restart_caddy"
	ClusterServiceActionRestartApp   = "restart_app"
)

// IsValidClusterServiceAction 判定动作是否在受控集合内（主从两侧共用同一口径）。
func IsValidClusterServiceAction(action string) bool {
	switch action {
	case ClusterServiceActionStartCaddy, ClusterServiceActionStopCaddy, ClusterServiceActionRestartCaddy, ClusterServiceActionRestartApp:
		return true
	}
	return false
}

// ClusterNodeServiceRequest 主节点服务控制端点请求体。
type ClusterNodeServiceRequest struct {
	Action string `json:"action" binding:"required"`
}

// ClusterServiceControlRequest 从节点服务控制端点请求体：票据即凭证
// （HMAC-SHA256，密钥为集群令牌哈希，90 秒一次性，与动作绑定）。
type ClusterServiceControlRequest struct {
	Action string `json:"action" binding:"required"`
	Ticket string `json:"ticket" binding:"required"`
}

// ClusterServiceControlClaims 服务控制票据载荷。
type ClusterServiceControlClaims struct {
	NodeID    int    `json:"node_id"`
	Action    string `json:"action"`
	JTI       string `json:"jti"`
	ExpiresAt int64  `json:"expires_at"`
}

// ClusterServiceControlIssue 主节点签发结果：票据 + 目标从节点信息（不跨网络传输）。
type ClusterServiceControlIssue struct {
	Ticket   string
	NodeName string
	URL      string
}

type ClusterLoginTicketResponse struct {
	Ticket string `json:"ticket"`
	URL    string `json:"url"`
}

type ClusterModeRequest struct {
	Mode          string `json:"mode" binding:"required,oneof=master slave"`
	MasterURL     string `json:"master_url"`
	RegisterToken string `json:"register_token"`
	NodeName      string `json:"node_name"`
}

type ClusterSettingsRequest struct {
	// SyncInterval 范围校验（10-86400）在 ClusterService.UpdateSettings 完成，
	// 以便返回「同步间隔需在 10-86400 秒之间」的具体文案；binding 层不再拦截（R42 发现1）。
	SyncInterval     *int  `json:"sync_interval"`
	SyncGlobalConfig *bool `json:"sync_global_config"`
	SyncUsers        *bool `json:"sync_users"`
	SyncRules        *bool `json:"sync_rules"`
	SyncWafFiles     *bool `json:"sync_waf_files"`
	SyncSecurity     *bool `json:"sync_security"`
}

type ClusterRegistration struct {
	RegistrationID     int    `json:"registration_id"`
	RegistrationSecret string `json:"registration_secret"`
}

type ClusterRegistrationStatus struct {
	Status       string `json:"status"`
	ClusterToken string `json:"cluster_token,omitempty"`
}

type SyncErrorCode string

const (
	SyncErrorCodeSchemaTooNew     SyncErrorCode = "schema_too_new"
	SyncErrorCodeSchemaTooOld     SyncErrorCode = "schema_too_old"
	SyncErrorCodeSignatureInvalid SyncErrorCode = "signature_invalid"
	SyncErrorCodePinMismatch      SyncErrorCode = "pin_mismatch"
	SyncErrorCodeValidationFailed SyncErrorCode = "validation_failed"
	SyncErrorCodeApplyFailed      SyncErrorCode = "apply_failed"
	SyncErrorCodeTransportError   SyncErrorCode = "transport_error"
)

type ClusterHealth struct {
	CaddyOK          bool          `json:"caddy_ok"`
	RulesCount       int           `json:"rules_count"`
	CertsExpiring30d int           `json:"certs_expiring_30d"`
	LastSyncAt       string        `json:"last_sync_at"`
	LastSyncError    string        `json:"last_sync_error"`
	SyncErrorCode    SyncErrorCode `json:"sync_error_code,omitempty"`
	UptimeSec        int64         `json:"uptime_sec"`
}

type ClusterReport struct {
	AppliedVersion int           `json:"applied_version" binding:"min=0"`
	ServiceStatus  string        `json:"service_status" binding:"required,oneof=ok degraded"`
	Health         ClusterHealth `json:"health"`
	LastSyncAt     string        `json:"last_sync_at"`
	LastSyncError  string        `json:"last_sync_error"`
	SyncErrorCode  SyncErrorCode `json:"sync_error_code,omitempty" binding:"omitempty,oneof=schema_too_new schema_too_old signature_invalid pin_mismatch validation_failed apply_failed transport_error"`
	// SectionHashes 携带从节点 cluster_applied_sections 的已应用节哈希（本地
	// 当前已落库口径），供主节点聚合 per-section 同步状态。旧版本从节点不上
	// 报（nil，omitempty 省略字段），主节点据此展示「旧版本从节点」占位。
	SectionHashes map[string]string `json:"section_hashes,omitempty"`
	// Detached 为真表示从节点已提升脱离，请求主节点删除本节点记录（令牌随行撤销）。
	Detached bool `json:"detached"`
}

// ClusterSectionSyncStatus 是主节点状态端点聚合的单个同步节比对结果：
// Hash 为从节点上报的本地哈希，MasterHash 为主节点自身快照节哈希，
// Synced 仅在两者非空且一致时为真（从节点缺记录按滞后处理）。
type ClusterSectionSyncStatus struct {
	Section    string `json:"section"`
	Label      string `json:"label"`
	Hash       string `json:"hash"`
	MasterHash string `json:"master_hash"`
	Synced     bool   `json:"synced"`
}

type ClusterBasicSettings struct {
	LogLevel                   string `json:"log_level"`
	AccessLogJSON              bool   `json:"access_log_json,omitempty"`
	AccessLogFormat            string `json:"access_log_format,omitempty"`
	CertJobLogSizeMB           int    `json:"cert_job_log_size_mb"`
	AuditLogSizeMB             int    `json:"audit_log_size_mb"`
	RuntimeLogSizeMB           int    `json:"runtime_log_size_mb"`
	AuditRetentionMonths       int    `json:"audit_retention_months"`
	JWTExpireMinutes           int    `json:"jwt_expire_minutes"`
	Timezone                   string `json:"timezone"`
	ACMEEmail                  string `json:"acme_email"`
	CertExpiryDays             int    `json:"cert_expiry_days"`
	CertRenewalDays            int    `json:"cert_renewal_days"`
	CertRenewalAttempts        int    `json:"cert_renewal_attempts"`
	DefaultCAProviderID        int    `json:"default_ca_provider_id"`
	DNSProvider                string `json:"dns_provider"`
	DNSCredentials             string `json:"dns_credentials"`
	SyncInterval               int    `json:"sync_interval"`
	CaddyLogLevel              string `json:"caddy_log_level,omitempty"`
	CaddyLogSizeMB             int    `json:"caddy_log_size_mb,omitempty"`
	RequestBodyMaxSizeMB       int    `json:"request_body_max_size_mb,omitempty"`
	HTTPReadTimeout            int    `json:"http_read_timeout,omitempty"`
	HTTPWriteTimeout           int    `json:"http_write_timeout,omitempty"`
	HTTPIdleTimeout            int    `json:"http_idle_timeout,omitempty"`
	UpstreamKeepaliveTimeout   int    `json:"upstream_keepalive_timeout,omitempty"`
	ProxyDialTimeout           int    `json:"proxy_dial_timeout,omitempty"`
	ProxyResponseHeaderTimeout int    `json:"proxy_response_header_timeout,omitempty"`
	ProxyReadTimeout           int    `json:"proxy_read_timeout,omitempty"`
	ProxyWriteTimeout          int    `json:"proxy_write_timeout,omitempty"`
	ProxyStreamTimeout         int    `json:"proxy_stream_timeout,omitempty"`
	ProxyFlushInterval         int    `json:"proxy_flush_interval,omitempty"`
	ProxyStreamCloseDelay      int    `json:"proxy_stream_close_delay,omitempty"`
	GitHubProxyURL             string `json:"github_proxy_url,omitempty"`
	ServerTokensHidden         bool   `json:"server_tokens_hidden,omitempty"`
	AdminTLSEnabled            bool   `json:"admin_tls_enabled,omitempty"`
	AdminTLSMode               string `json:"admin_tls_mode,omitempty"`
	AdminTLSCert               string `json:"admin_tls_cert,omitempty"`
	AdminTLSKey                string `json:"admin_tls_key,omitempty"`
	// v2.1.8 MFA 全局开关（决策3：从节点行为与主节点一致）。
	MFAWriteGuard     bool `json:"mfa_write_guard"`
	MFALockoutEnabled bool `json:"mfa_lockout_enabled"`
}

type ClusterUser struct {
	ID                int          `json:"id"`
	Username          string       `json:"username"`
	PasswordHash      string       `json:"password_hash"`
	Role              string       `json:"role"`
	DisplayName       string       `json:"display_name"`
	IsEnabled         bool         `json:"is_enabled"`
	PasswordVersion   int64        `json:"password_version"`
	PasswordChangedAt *string      `json:"password_changed_at"`
	CreatedAt         time.Time    `json:"created_at"`
	LastLogin         JSONNullTime `json:"last_login"`
	// v2.1.8 MFA（决策3）：随快照同步——从节点本地验证 TOTP，无需回主节点。
	MFAEnabled        bool   `json:"mfa_enabled"`
	MFASecret         string `json:"mfa_secret"`
	MFARecoveryCodes  string `json:"mfa_recovery_codes"`
	MFALastTimestep   int64  `json:"mfa_last_timestep"`
	MFAFailedAttempts int    `json:"mfa_failed_attempts"`
	MFALockedUntil    string `json:"mfa_locked_until"`
	// pending 密钥不跨节点（绑定向导是节点本地交互；半途切换面板属可重做流程）。
}

// ClusterLockedUser 是主节点活跃登录锁的同步载荷（SC-4 修订）：主节点账号被锁
// 状态必须传播到从节点（从节点本地锁定独立生效）。走快照独立顶层载荷
// locked_users 而非 users 节列——login_* 不在 users 触发器快照列/节哈希/漂移
// 守卫内，避免每次登录失败触发 users/api_keys 全量重放与漂移循环。只携带
// 未来时间的活跃锁（与 loginLockedNow 同口径），自然过期后条目自动从快照消失。
type ClusterLockedUser struct {
	Username    string `json:"username"`
	LockedUntil string `json:"locked_until"`
}

type ClusterAPIKey struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	KeyHash        string       `json:"key_hash"`
	KeyPrefix      string       `json:"key_prefix"`
	CreatedBy      int          `json:"created_by"`
	LastUsed       JSONNullTime `json:"last_used"`
	ExpiresAt      string       `json:"expires_at"`
	IsEnabled      bool         `json:"is_enabled"`
	MCPEnabled     bool         `json:"mcp_enabled"`
	ReadOnly       bool         `json:"read_only"`
	MCPIPWhitelist []string     `json:"mcp_ip_whitelist"`
	CreatedAt      time.Time    `json:"created_at"`
}

type ClusterCertificate struct {
	RuleID           string       `json:"rule_id"`
	Domain           string       `json:"domain,omitempty"`
	CertPEM          string       `json:"cert_pem"`
	KeyPEM           string       `json:"key_pem"`
	ExpiresAt        string       `json:"expires_at"`
	CAProviderID     int          `json:"ca_provider_id,omitempty"`
	SourceStatus     string       `json:"source_status,omitempty"`
	RenewalAttempts  int          `json:"renewal_attempts,omitempty"`
	CAAvailableAfter JSONNullTime `json:"ca_available_after"`
	LastErrorCode    string       `json:"last_error_code,omitempty"`
}

type ClusterACMEState struct {
	CAProviders        []CAProvider        `json:"ca_providers"`
	CertificateConfigs []CertificateConfig `json:"certificate_configs"`
	DNSOwnership       json.RawMessage     `json:"dns_ownership"`
}

type ClusterSnapshot struct {
	Version             int                  `json:"version"`
	SchemaVersion       int                  `json:"schema_version,omitempty"`
	MinReaderVersion    int                  `json:"min_reader_version,omitempty"`
	Fingerprint         string               `json:"fingerprint"`
	Signature           string               `json:"signature,omitempty"`
	CanonicalPayload    json.RawMessage      `json:"canonical_payload,omitempty"`
	Rules               []LbRule             `json:"rules"`
	Users               []ClusterUser        `json:"users"`
	APIKeys             []ClusterAPIKey      `json:"api_keys"`
	BasicSettings       ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig         *string              `json:"caddy_config,omitempty"`
	Certs               []ClusterCertificate `json:"certs"`
	ACME                *ClusterACMEState    `json:"acme,omitempty"`
	SecurityPolicies    json.RawMessage      `json:"security_policies,omitempty"`
	SecurityBindings    json.RawMessage      `json:"security_bindings,omitempty"`
	SecurityCustomRules []SecurityCustomRule `json:"security_custom_rules,omitempty"`
	SecurityBlockPages  []SecurityBlockPage  `json:"security_block_pages,omitempty"`
	// SecurityIPLists（v2.3.0）：可复用 IP 地址列表全量 dump（行结构与
	// security_policies 同款 map 形态）；策略 ip_acl_list_refs/
	// ip_whitelist_refs 以 id 引用本表，随 security 节一起全量替换。
	SecurityIPLists          json.RawMessage                   `json:"security_ip_lists,omitempty"`
	SecurityCRSVersion       []ClusterSecurityCRSVersion       `json:"security_crs_version,omitempty"`
	SecurityIP2RegionVersion []ClusterSecurityIP2RegionVersion `json:"security_ip2region_version,omitempty"`
	WafFiles                 *ClusterWafFilesRef               `json:"waf_files,omitempty"`
	SectionHashes            map[string]string                 `json:"section_hashes,omitempty"`
	// MasterSyncSwitches 为主节点五类同步开关，随快照下发；从节点跳过判定
	// 以此为准（从节点本地开关列不参与，避免永远默认全开导致开关失效）。
	MasterSyncSwitches *ClusterSyncSwitchesPayload `json:"master_sync_switches,omitempty"`
	// LockedUsers（SC-4 修订）：主节点活跃登录锁，独立顶层载荷——不参与任何
	// 节哈希/漂移守卫（避免登录失败触发 users 全量重放）；从端只延长不清除。
	// 加性可选字段、omitempty：旧主端缺省 → 从端 no-op；旧从端忽略未知字段
	// （先例：MasterSyncSwitches/WafFiles），故不 bump CurrentSnapshotSchema。
	LockedUsers []ClusterLockedUser `json:"locked_users,omitempty"`
}

type ClusterSyncSwitchesPayload struct {
	GlobalConfig bool `json:"global_config"`
	Users        bool `json:"users"`
	Rules        bool `json:"rules"`
	WafFiles     bool `json:"waf_files"`
	Security     bool `json:"security"`
}

// ClusterWafFilesRef 是快照携带的 WAF 规则文件哈希引用（不含内容）：
// 从节点比对本地哈希，不一致才向主节点 /cluster/sync/waf-files 拉取，
// 规则等 DB 变更引发的快照传输不再搭车 MB 级文件内容。
type ClusterWafFilesRef struct {
	CRSVersion   string `json:"crs_version"`
	CRSSha256    string `json:"crs_sha256"`
	IP2RegionTag string `json:"ip2region_version"`
	IP2RegionSha string `json:"ip2region_sha256"`
}

type ClusterSecurityCRSVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
}

type ClusterSecurityIP2RegionVersion struct {
	ID           int    `json:"id"`
	Version      string `json:"version"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	Trigger      string `json:"trigger"`
	StartedAt    string `json:"started_at"`
	FinishedAt   string `json:"finished_at"`
}

func (snapshot ClusterSnapshot) MarshalJSON() ([]byte, error) {
	type snapshotAlias ClusterSnapshot
	if snapshot.SchemaVersion < 3 || len(snapshot.CanonicalPayload) == 0 {
		return json.Marshal(snapshotAlias(snapshot))
	}
	return json.Marshal(struct {
		SchemaVersion    int             `json:"schema_version"`
		MinReaderVersion int             `json:"min_reader_version"`
		Version          int             `json:"version"`
		Fingerprint      string          `json:"fingerprint"`
		Signature        string          `json:"signature"`
		CanonicalPayload json.RawMessage `json:"canonical_payload"`
	}{
		SchemaVersion:    snapshot.SchemaVersion,
		MinReaderVersion: snapshot.MinReaderVersion,
		Version:          snapshot.Version,
		Fingerprint:      snapshot.Fingerprint,
		Signature:        snapshot.Signature,
		CanonicalPayload: snapshot.CanonicalPayload,
	})
}

type ClusterNodeView struct {
	ID              int            `json:"id"`
	Name            string         `json:"name"`
	IPAddress       string         `json:"ip_address"`
	Port            int            `json:"port"`
	Protocol        string         `json:"protocol"`
	AccessURL       string         `json:"access_url"`
	Status          string         `json:"status"`
	IsApproved      bool           `json:"is_approved"`
	ReportedVersion int            `json:"reported_version"`
	CurrentVersion  int            `json:"current_version"`
	Health          *ClusterHealth `json:"health"`
	LastSeen        string         `json:"last_seen"`
	CreatedAt       string         `json:"created_at"`
	// SectionSync 为主节点聚合的 per-section 同步状态，仅包含主节点同步开关
	// 开启的节；旧版本从节点无上报时为 nil（JSON 省略），前端展示占位文案。
	SectionSync []ClusterSectionSyncStatus `json:"section_sync,omitempty"`
}

type ClusterStatus struct {
	NodeMode         string        `json:"node_mode"`
	ClusterVersion   int           `json:"cluster_version"`
	MasterURL        string        `json:"master_url"`
	SyncInterval     int           `json:"sync_interval"`
	SyncGlobalConfig bool          `json:"sync_global_config"`
	SyncUsers        bool          `json:"sync_users"`
	SyncRules        bool          `json:"sync_rules"`
	SyncWafFiles     bool          `json:"sync_waf_files"`
	SyncSecurity     bool          `json:"sync_security"`
	ClusterActive    bool          `json:"cluster_active"`
	AppliedVersion   int           `json:"applied_version"`
	LastSyncAt       string        `json:"last_sync_at"`
	LastSyncError    string        `json:"last_sync_error"`
	SyncErrorCode    SyncErrorCode `json:"sync_error_code,omitempty"`
	PendingCount     int           `json:"pending_count"`
	ApprovedCount    int           `json:"approved_count"`
}
