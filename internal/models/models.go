package models

import (
	"database/sql"
	"encoding/json"
	"time"
)

// RevokedTokenTimeFormat 吊销 JWT 的 expires_at 统一格式（收敛
// handlers 写侧与 middleware 读侧曾跨包双份定义——单侧改动会静默失配）。
const RevokedTokenTimeFormat = "2006-01-02T15:04:05Z"

// User represents a user in the system
type User struct {
	ID           int            `json:"id"`
	Username     string         `json:"username"`
	PasswordHash string         `json:"-"`
	Role         string         `json:"role"`
	DisplayName  sql.NullString `json:"display_name"`
	IsEnabled    bool           `json:"is_enabled"`
	CreatedAt    time.Time      `json:"created_at"`
	LastLogin    sql.NullTime   `json:"last_login"`
	// v2.3.0:认证来源(local/oidc)——票据登录跨节点透传、响应透出供前端区分
	AuthProvider string `json:"auth_provider"`
	// IsSetupAdmin 标记初始化创建的首个管理员（break-glass 入口）：不可删除/
	// 禁用/降级，前端据此禁用对应操作。
	IsSetupAdmin bool `json:"is_setup_admin"`
}

type UserResponse struct {
	ID           int        `json:"id"`
	Username     string     `json:"username"`
	Role         string     `json:"role"`
	DisplayName  *string    `json:"display_name"`
	IsEnabled    bool       `json:"is_enabled"`
	MFAEnabled   bool       `json:"mfa_enabled"`
	AuthProvider string     `json:"auth_provider"`
	IsSetupAdmin bool       `json:"is_setup_admin"`
	CreatedAt    time.Time  `json:"created_at"`
	LastLogin    *time.Time `json:"last_login"`
}

// NewUserResponse 构造用户响应。mfaEnabled 必须由调用方从 users.mfa_enabled
// 读取后传入：将原本「构造后手工 response.MFAEnabled=…」
// 的口径收敛为签名参数——历史上两次都因新增返回路径忘记
// 补字段导致 mfa_enabled 恒 false（前端登录预检误报）。签名强制让遗漏在
// 编译期失败，而不是静默返回错误值。
func NewUserResponse(user User, mfaEnabled bool) UserResponse {
	response := UserResponse{
		ID:           user.ID,
		Username:     user.Username,
		Role:         user.Role,
		IsEnabled:    user.IsEnabled,
		MFAEnabled:   mfaEnabled,
		CreatedAt:    user.CreatedAt,
		AuthProvider: user.AuthProvider,
		IsSetupAdmin: user.IsSetupAdmin,
	}
	if user.DisplayName.Valid {
		response.DisplayName = &user.DisplayName.String
	}
	if user.LastLogin.Valid {
		response.LastLogin = &user.LastLogin.Time
	}
	return response
}

// APIKey represents an API key
type APIKey struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	KeyHash        string       `json:"-"`
	KeyPrefix      string       `json:"key_prefix"`
	CreatedBy      int          `json:"created_by"`
	LastUsed       sql.NullTime `json:"last_used"`
	ExpiresAt      sql.NullTime `json:"expires_at"`
	IsEnabled      bool         `json:"is_enabled"`
	MCPEnabled     bool         `json:"mcp_enabled"`
	ReadOnly       bool         `json:"read_only"`
	MCPIPWhitelist []string     `json:"mcp_ip_whitelist"`
	CreatedAt      time.Time    `json:"created_at"`
}

type APIKeyResponse struct {
	ID             int        `json:"id"`
	Name           string     `json:"name"`
	KeyPrefix      string     `json:"key_prefix"`
	CreatedBy      int        `json:"created_by"`
	LastUsed       *time.Time `json:"last_used"`
	ExpiresAt      *time.Time `json:"expires_at"`
	IsEnabled      bool       `json:"is_enabled"`
	MCPEnabled     bool       `json:"mcp_enabled"`
	ReadOnly       bool       `json:"read_only"`
	MCPIPWhitelist []string   `json:"mcp_ip_whitelist"`
	CreatedAt      time.Time  `json:"created_at"`
}

type APIKeyWithUserResponse struct {
	APIKeyResponse
	Username string `json:"username"`
}

func NewAPIKeyResponse(key APIKey) APIKeyResponse {
	response := APIKeyResponse{
		ID:             key.ID,
		Name:           key.Name,
		KeyPrefix:      key.KeyPrefix,
		CreatedBy:      key.CreatedBy,
		IsEnabled:      key.IsEnabled,
		MCPEnabled:     key.MCPEnabled,
		ReadOnly:       key.ReadOnly,
		MCPIPWhitelist: key.MCPIPWhitelist,
		CreatedAt:      key.CreatedAt,
	}
	if key.LastUsed.Valid {
		response.LastUsed = &key.LastUsed.Time
	}
	if key.ExpiresAt.Valid {
		response.ExpiresAt = &key.ExpiresAt.Time
	}
	return response
}

func NewAPIKeyWithUserResponse(key APIKey, username string) APIKeyWithUserResponse {
	return APIKeyWithUserResponse{APIKeyResponse: NewAPIKeyResponse(key), Username: username}
}

// LbRule represents a load balancing rule
type LbRule struct {
	ID                            int    `json:"id"`
	CaddyID                       string `json:"caddy_id"`
	Name                          string `json:"name"`
	Description                   string `json:"description"`
	Protocol                      string `json:"protocol"`
	Domain                        string `json:"domain"`
	ListenPort                    int    `json:"listen_port"`
	Strategy                      string `json:"strategy"`
	DynamicDNS                    bool   `json:"dynamic_dns"`
	EnableDnsServer               bool   `json:"enable_dns_server"`
	DnsServer                     string `json:"dns_server"`
	DnsFamily                     string `json:"dns_family"`
	HealthCheckPath               string `json:"health_check_path"`
	HealthCheckInterval           int    `json:"health_check_interval"`
	HealthCheckTimeout            int    `json:"health_check_timeout"`
	HealthCheckUnhealthyThreshold int    `json:"health_check_unhealthy_threshold"`
	HealthCheckHealthyThreshold   int    `json:"health_check_healthy_threshold"`
	EnableActiveHealthCheck       bool   `json:"enable_active_health_check"`
	TCPHealthCheckPort            int    `json:"tcp_health_check_port"`
	TCPProxyProtocol              bool   `json:"tcp_proxy_protocol"`
	TCPTryDuration                int    `json:"tcp_try_duration"`
	TCPTryInterval                int    `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB          int    `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout      int    `json:"upstream_keepalive_timeout"`
	ServerTokensHidden            int    `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	// NTLM 兼容开关（2026-10-12）：1=按 NTLM 兼容形态渲染（保存门强制
	// strategy=cookie）；仅 HTTP 语义，TCP 行恒 0。
	NTLMCompatible             int        `json:"ntlm_compatible"`
	UpstreamForceHTTP1         int        `json:"upstream_force_http1"`
	CustomRoutesEnabled        bool       `json:"custom_routes_enabled"`
	ProxyDialTimeout           int        `json:"proxy_dial_timeout"`
	ProxyResponseHeaderTimeout int        `json:"proxy_response_header_timeout"`
	ProxyReadTimeout           int        `json:"proxy_read_timeout"`
	ProxyWriteTimeout          int        `json:"proxy_write_timeout"`
	ProxyStreamTimeout         int        `json:"proxy_stream_timeout"`
	ProxyFlushInterval         int        `json:"proxy_flush_interval"`
	ProxyStreamCloseDelay      int        `json:"proxy_stream_close_delay"`
	PathRules                  []PathRule `json:"path_rules"`
	Upstreams                  []Upstream `json:"upstreams"`
	HostHeader                 string     `json:"host_header"`
	// 健康检查域名（2026-10-10）：主动健康检查 probe 的 Host 头；空=跟随 HostHeader。
	HealthCheckHost string `json:"health_check_host"`
	EnableTLS       bool   `json:"enable_tls"`
	TLSSource       string `json:"tls_source"`
	ACMEConfigID    int    `json:"acme_config_id"`
	CAProviderID    int    `json:"ca_provider_id"`
	TLSCert         string `json:"tls_cert,omitempty"`
	TLSKey          string `json:"tls_key,omitempty"`
	// TLSKeySet 标记「已有隐藏私钥」——GetRule 对只读 Key/非管理员掩码 tls_key
	// 为空串时置 true，编辑表单借此区分「未配置」与「已隐藏」。
	TLSKeySet       bool   `json:"tls_key_set,omitempty"`
	TLSHTTPRedirect bool   `json:"tls_http_redirect"`
	EnableCompress  bool   `json:"enable_compress"`
	CompressTypes   string `json:"compress_types"`
	Enabled         bool   `json:"enabled"`
	LogEnabled      bool   `json:"log_enabled"`
	// 阶段拦截页（规则级覆盖层，阶段化安全流水线）：阶段 1=IP 访问控制+地域
	// 拦截预检，阶段 3=WAF；0=未配（跟随策略，v2.3.1 逐策略归因默认层）。
	// status ∈ {0,400,401,403,404,503}，0 在渲染侧归一 403。
	BlockPageStage1ID     int          `json:"block_page_stage1_id"`
	BlockPageStage1Status int          `json:"block_page_stage1_status"`
	BlockPageStage3ID     int          `json:"block_page_stage3_id"`
	BlockPageStage3Status int          `json:"block_page_stage3_status"`
	CreatedBy             int          `json:"created_by"`
	UpdatedBy             int          `json:"updated_by"`
	CreatedAt             time.Time    `json:"created_at"`
	UpdatedAt             JSONNullTime `json:"updated_at"`
}

// CAProvider represents an ACME certificate authority configuration.
type CAProvider struct {
	ID            int       `json:"id"`
	Name          string    `json:"name"`
	Provider      string    `json:"provider"`
	DirectoryURL  string    `json:"directory_url"`
	Credentials   string    `json:"credentials,omitempty"`
	MaxConcurrent int       `json:"max_concurrent"`
	MinIntervalMS int       `json:"min_interval_ms"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// CAProviderCredentials holds typed credential fields for ZeroSSL.
type CAProviderCredentials struct {
	EABKID     string `json:"eab_kid,omitempty"`
	EABHMACKey string `json:"eab_hmac_key,omitempty"`
}

// UpdateCAProviderRequest represents a partial update to a CA provider.
// Pointer fields are only applied when non-nil.
type UpdateCAProviderRequest struct {
	Name          *string `json:"name"`
	Provider      *string `json:"provider"`
	Credentials   *string `json:"credentials"`
	MaxConcurrent *int    `json:"max_concurrent"`
	MinIntervalMS *int    `json:"min_interval_ms"`
	Enabled       *bool   `json:"enabled"`
}

// 威胁大屏中央视觉模式封闭枚举（列 global_config.threat_screen_mode）。
// 三处消费同一列表：写侧校验（handlers/caddy.go 400 白名单）、从端快照
// apply 归一（services/cluster_apply.go 非法值回默认）、读侧渲染。
// 默认值单源 db.DefaultThreatScreenMode（= ThreatScreenModeMap）。
const (
	ThreatScreenModeMap   = "map"
	ThreatScreenModeGlobe = "globe"
)

// IsValidThreatScreenMode 报告模式值是否属于封闭枚举。
func IsValidThreatScreenMode(mode string) bool {
	return mode == ThreatScreenModeMap || mode == ThreatScreenModeGlobe
}

// GlobalConfig represents global configuration
type GlobalConfig struct {
	ID          int    `json:"id"`
	CaddyConfig string `json:"caddy_config"`
	// DNSProvider 是全局配置遗留字段——签发链唯一凭证来源是
	// certificate_configs 表；响应面已收敛（omitempty，空值不下发；
	// 集群快照走 ClusterBasicSettings 独立字段，不受此收敛影响）。DNS 凭证
	// 正文不属于该响应模型：/config 面向全部登录用户，凭证列只存
	// certificate_configs。
	DNSProvider                string `json:"dns_provider,omitempty"`
	ACMEEmail                  string `json:"acme_email"`
	CertExpiryDays             int    `json:"cert_expiry_days"`
	CertRenewalDays            int    `json:"cert_renewal_days"`
	CertRenewalAttempts        int    `json:"cert_renewal_attempts"`
	LogLevel                   string `json:"log_level"`
	CaddyLogLevel              string `json:"caddy_log_level"`
	CaddyLogSizeMB             int    `json:"caddy_log_size_mb"`
	RequestBodyMaxSizeMB       int    `json:"request_body_max_size_mb"`
	HTTPReadTimeout            int    `json:"http_read_timeout"`
	HTTPWriteTimeout           int    `json:"http_write_timeout"`
	HTTPIdleTimeout            int    `json:"http_idle_timeout"`
	UpstreamKeepaliveTimeout   int    `json:"upstream_keepalive_timeout"`
	ProxyDialTimeout           int    `json:"proxy_dial_timeout"`
	ProxyResponseHeaderTimeout int    `json:"proxy_response_header_timeout"`
	ProxyReadTimeout           int    `json:"proxy_read_timeout"`
	ProxyWriteTimeout          int    `json:"proxy_write_timeout"`
	ProxyStreamTimeout         int    `json:"proxy_stream_timeout"`
	ProxyFlushInterval         int    `json:"proxy_flush_interval"`
	ProxyStreamCloseDelay      int    `json:"proxy_stream_close_delay"`
	ServerTokensHidden         bool   `json:"server_tokens_hidden"`
	TaskLogSizeMB              int    `json:"task_log_size_mb"`
	AuditLogSizeMB             int    `json:"audit_log_size_mb"`
	RuntimeLogSizeMB           int    `json:"runtime_log_size_mb"`
	AccessLogJSON              bool   `json:"access_log_json"`
	AccessLogFormat            string `json:"access_log_format"`
	AuditRetentionMonths       int    `json:"audit_retention_months"`
	JWTExpireMinutes           int    `json:"jwt_expire_minutes"`
	Timezone                   string `json:"timezone"`
	GitHubProxyURL             string `json:"github_proxy_url"`
	// GitHubToken 可选 GITHUB_TOKEN（2026-09-25 用户裁定）：响应面永不回显
	// 原文（json:"-"），仅 HasGitHubToken 显隐；写路径 UpdateConfigRequest。
	GitHubToken         string `json:"-"`
	HasGitHubToken      bool   `json:"has_github_token"`
	IsMaster            bool   `json:"is_master"`
	MasterURL           string `json:"master_url"`
	SyncInterval        int    `json:"sync_interval"`
	DefaultCAProviderID int    `json:"default_ca_provider_id"`
	// ServerMapLat/ServerMapLon 威胁大屏本站坐标（v3，node-local 列）：
	// 0,0=未设置（前端回退地图视觉中心）。节点属性不随集群同步。
	ServerMapLat float64 `json:"server_map_lat"`
	ServerMapLon float64 `json:"server_map_lon"`
	// ThreatScreenMode 威胁大屏中央视觉模式（v2.3.8）：map=360°地图+雷达扫掠 /
	// globe=旋转地球+垂直扫描。缺省 db.DefaultThreatScreenMode。该列随集群
	// 快照（ClusterBasicSettings）同步：从节点写入口被只读门拒绝，配置只能
	// 由主节点下发。枚举校验单源见 IsValidThreatScreenMode。
	ThreatScreenMode string `json:"threat_screen_mode"`
	// ThreatTrafficSampleN 大屏逐请求光流采样：-1=自适应（内部从 1/1 起步，
	// 按事件速率在 1/4/8 档与滞回切换）、0=关闭。全量档已退役（自适应低流量
	// 等价全量）；固定 2..64/1 存量由启动迁移归一 -1。
	ThreatTrafficSampleN int `json:"threat_traffic_sample_n"`
	// SecurityEventsRetentionDays/RowCap 安全事件保留（v2.3.8 显式设置）：
	// 写侧只接受 1-3650 天 / 1-1 亿行（旧「0=自动」语义已废除）；库内 0/NULL
	// 属 legacy 形态，由启动迁移一次性归一。渲染/查询直读库值。
	SecurityEventsRetentionDays int `json:"security_events_retention_days"`
	SecurityEventsRowCap        int `json:"security_events_row_cap"`
	// v2.1.8 MFA 全局开关（响应面）
	MFAWriteGuard     bool `json:"mfa_write_guard"`
	MFALockoutEnabled bool `json:"mfa_lockout_enabled"`
	// v2.3.x 受信代理（CDN 真实 IP）：响应面。
	TrustedProxyEnabled bool   `json:"trusted_proxy_enabled"`
	TrustedProxyRanges  string `json:"trusted_proxy_ranges"`
	// 受信网段引用的 IP 地址列表 id（JSON 数组文本，2026-10-12）：与内联
	// trusted_proxy_ranges 合并投影（2026-10-15 热路径化，tp.txt/lb_file）。
	TrustedProxyRangeRefs string       `json:"trusted_proxy_range_refs"`
	TrustedProxyHeaders   string       `json:"trusted_proxy_headers"`
	TrustedProxyStrict    bool         `json:"trusted_proxy_strict"`
	LastSync              JSONNullTime `json:"last_sync"`
	UpdatedAt             JSONNullTime `json:"updated_at"`
}

// Upstream represents an upstream server
type Upstream struct {
	ID     int    `json:"id"`
	RuleID string `json:"rule_id"`
	Host   string `json:"host"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
	// DynamicDNS 是 upstreams 表的废弃列：渲染只读规则级 DynamicDNS，写侧
	// 恒落 0（值不再传播）。响应面已收敛（omitempty——恒 false 不下发，
	// 防消费者据恒假值误判；导入/快照缺省即零值，双向兼容），新代码禁止
	// 据此做任何判定。
	DynamicDNS     bool   `json:"dynamic_dns,omitempty"`
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol"`
	MaxConnections int    `json:"max_connections"`
	// 逐上游回源域名（2026-10-10）：非空时驱动该上游回源 Host 头与 HTTPS SNI
	// （map 处理器晚绑定查表）；空=跟随规则级 HostHeader/现状默认。
	OriginDomain string `json:"origin_domain,omitempty"`
}

type PathRuleUpstream struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Weight   int    `json:"weight"`
	Protocol string `json:"protocol"`
}

type PathRule struct {
	ID        int    `json:"id"`
	RuleID    string `json:"-"`
	SortOrder int    `json:"sort_order"`
	MatchType string `json:"match_type"`
	Path      string `json:"path"`
	// 上游 path 改写：空串=原样转发（现状语义）；非空前缀匹配剥匹配前缀后前置、
	// 精确匹配整体替换（query 均保留，形状经 caddy 2.11.4 引擎实证）。
	UpstreamPath string `json:"upstream_path"`
	// 直接返回/301 跳转（2026-10-10 用户裁定）：ResponseMode ''=转发上游（现状）
	// /static=静态响应（Status+Body+ContentType）/redirect=301 跳转（RedirectTo）。
	ResponseMode        string             `json:"response_mode"`
	ResponseStatus      int                `json:"response_status"`
	ResponseBody        string             `json:"response_body"`
	ResponseContentType string             `json:"response_content_type"`
	RedirectTo          string             `json:"redirect_to"`
	Upstreams           []PathRuleUpstream `json:"upstreams"`
	CreatedAt           time.Time          `json:"-"`
	UpdatedAt           sql.NullTime       `json:"-"`
}

// CertificateConfig represents free certificate configuration (ACME + DNS provider)
type CertificateConfig struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	DNSProvider    string       `json:"dns_provider"`
	DNSCredentials string       `json:"dns_credentials"`
	Enabled        bool         `json:"enabled"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      JSONNullTime `json:"updated_at"`
}

// RuleCertInfo represents parsed TLS certificate information for display in the UI
type RuleCertInfo struct {
	CaddyID       string `json:"caddy_id"`
	Source        string `json:"source"`          // "manual" | "acme_dns"
	Domains       string `json:"domains"`         // rule domain or certificate DNS names
	Issuer        string `json:"issuer"`          // issuer CN or Organization
	NotBefore     string `json:"not_before"`      // formatted effective time
	NotAfter      string `json:"not_after"`       // formatted expiration time
	DaysRemaining int    `json:"days_remaining"`  // days until expiration (negative if expired)
	Status        string `json:"status"`          // "valid" | "expiring" | "expired" | "unknown"
	Error         string `json:"error,omitempty"` // error message when parsing fails
}

// CertInfoBatchRequest represents a batch cert-info query request
type CertInfoBatchRequest struct {
	CaddyIDs []string `json:"caddy_ids" binding:"required"`
}

// JSONNullTime wraps sql.NullTime so that it serializes as a RFC3339 string
// when valid and as null when invalid, instead of the default {"Time":...,"Valid":...}
// object which cannot be parsed by JavaScript's new Date().
type JSONNullTime struct {
	sql.NullTime
}

func (n JSONNullTime) MarshalJSON() ([]byte, error) {
	if !n.Valid {
		return []byte("null"), nil
	}
	return n.Time.MarshalJSON()
}

func (n *JSONNullTime) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		n.Valid = false
		n.Time = time.Time{}
		return nil
	}
	var parsed time.Time
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	n.Valid = true
	n.Time = parsed
	return nil
}

// CertJob represents an ACME certificate issuance job
type CertJob struct {
	ID               int          `json:"id"`
	RuleID           string       `json:"rule_id"`
	Domain           string       `json:"domain"`
	CAProviderID     int          `json:"ca_provider_id"`
	CAProviderName   string       `json:"ca_provider_name,omitempty"`
	Status           string       `json:"status"`
	Message          string       `json:"message"`
	CertPEM          string       `json:"cert_pem,omitempty"`
	KeyPEM           string       `json:"key_pem,omitempty"`
	RenewalAttempts  int          `json:"renewal_attempts,omitempty"`
	CAAvailableAfter JSONNullTime `json:"ca_available_after,omitempty"`
	LastErrorCode    string       `json:"last_error_code,omitempty"`
	ExpiresAt        JSONNullTime `json:"expires_at"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        JSONNullTime `json:"updated_at"`
}

// LoginRequest 登录入参。username/password 补长度上限——
// 此前仅 required，未认证请求可携带 ~64KiB「用户名」，失败登录按原文写入
// audit_log（每次一行等大，限流 10/min/IP 可被分布式绕开，放大审计库）。
// 上限与写入侧对齐：username=users.username 列宽 50；password=bcrypt 有效
// 上限 72 字节（更长值永远无法匹配任何已存哈希）。
type LoginRequest struct {
	Username string `json:"username" binding:"required,max=50"`
	Password string `json:"password" binding:"required,max=72"`
}

type LoginResponse struct {
	Token    string       `json:"token"`
	User     UserResponse `json:"user"`
	NodeMode string       `json:"node_mode"`
}

type CreateUserRequest struct {
	Username    string `json:"username" binding:"required,min=3,max=50"`
	Password    string `json:"password" binding:"required,max=72"`
	Role        string `json:"role" binding:"required"`
	DisplayName string `json:"display_name" binding:"max=50"`
}

type CreateAPIKeyRequest struct {
	Name           string     `json:"name" binding:"required"`
	ExpiresAt      *time.Time `json:"expires_at"`
	MCPEnabled     bool       `json:"mcp_enabled"`
	ReadOnly       bool       `json:"read_only"`
	MCPIPWhitelist []string   `json:"mcp_ip_whitelist"`
}

type UpdateAPIKeyRequest struct {
	IsEnabled      *bool     `json:"is_enabled"`
	MCPEnabled     *bool     `json:"mcp_enabled"`
	ReadOnly       *bool     `json:"read_only"`
	MCPIPWhitelist *[]string `json:"mcp_ip_whitelist"`
}

type CreateRuleRequest struct {
	Name                          string     `json:"name" binding:"required"`
	Description                   string     `json:"description"`
	Protocol                      string     `json:"protocol" binding:"required"`
	Domain                        string     `json:"domain"`
	ListenPort                    int        `json:"listen_port"`
	Strategy                      string     `json:"strategy"`
	DynamicDNS                    bool       `json:"dynamic_dns"`
	EnableDnsServer               bool       `json:"enable_dns_server"`
	DnsServer                     string     `json:"dns_server"`
	DnsFamily                     string     `json:"dns_family"`
	HealthCheckPath               string     `json:"health_check_path"`
	HealthCheckInterval           int        `json:"health_check_interval"`
	HealthCheckTimeout            int        `json:"health_check_timeout"`
	HealthCheckUnhealthyThreshold int        `json:"health_check_unhealthy_threshold"`
	HealthCheckHealthyThreshold   int        `json:"health_check_healthy_threshold"`
	EnableActiveHealthCheck       bool       `json:"enable_active_health_check"`
	TCPHealthCheckPort            int        `json:"tcp_health_check_port"`
	TCPProxyProtocol              bool       `json:"tcp_proxy_protocol"`
	TCPTryDuration                int        `json:"tcp_try_duration"`
	TCPTryInterval                int        `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB          int        `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout      int        `json:"upstream_keepalive_timeout"`
	ServerTokensHidden            int        `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	NTLMCompatible                int        `json:"ntlm_compatible"`      // 0=off, 1=NTLM 兼容形态（要求 strategy=cookie）
	UpstreamForceHTTP1            int        `json:"upstream_force_http1"` // 通用列：1=上游强制 HTTP/1.1（https 上游禁 ALPN h2）
	CustomRoutesEnabled           bool       `json:"custom_routes_enabled"`
	ProxyDialTimeout              int        `json:"proxy_dial_timeout"`
	ProxyResponseHeaderTimeout    int        `json:"proxy_response_header_timeout"`
	ProxyReadTimeout              int        `json:"proxy_read_timeout"`
	ProxyWriteTimeout             int        `json:"proxy_write_timeout"`
	ProxyStreamTimeout            int        `json:"proxy_stream_timeout"`
	ProxyFlushInterval            int        `json:"proxy_flush_interval"`
	ProxyStreamCloseDelay         int        `json:"proxy_stream_close_delay"`
	PathRules                     []PathRule `json:"path_rules"`
	HostHeader                    string     `json:"host_header"`
	// 健康检查域名：空=跟随 HostHeader（省略与空串同义，创建语义）。
	HealthCheckHost string     `json:"health_check_host"`
	Upstreams       []Upstream `json:"upstreams" binding:"required"`
	EnableTLS       bool       `json:"enable_tls"`
	TLSSource       string     `json:"tls_source"`
	ACMEConfigID    int        `json:"acme_config_id"`
	CAProviderID    int        `json:"ca_provider_id"`
	TLSCert         string     `json:"tls_cert"`
	TLSKey          string     `json:"tls_key"`
	TLSHTTPRedirect bool       `json:"tls_http_redirect"`
	EnableCompress  bool       `json:"enable_compress"`
	CompressTypes   string     `json:"compress_types"`
	LogEnabled      bool       `json:"log_enabled"`
	// 阶段拦截页覆盖层（0=跟随策略；status ∈ {0,400,401,403,404,503}）
	BlockPageStage1ID     int `json:"block_page_stage1_id"`
	BlockPageStage1Status int `json:"block_page_stage1_status"`
	BlockPageStage3ID     int `json:"block_page_stage3_id"`
	BlockPageStage3Status int `json:"block_page_stage3_status"`
	// 缺省（nil）=创建即启用（向后兼容历史调用方）；显式 false=创建为
	// 禁用（UI 复制向导按预览「禁用」态落库）。
	Enabled *bool `json:"enabled,omitempty"`
}

type UpdateRuleRequest struct {
	Name string `json:"name"`
	// HostHeader/Description/DnsServer/HealthCheckPath 指针化——
	// 省略（nil）=保留原值，显式空串=清空；旧行为空串与省略无法区分。
	Description         *string `json:"description"`
	Protocol            string  `json:"protocol"`
	Domain              string  `json:"domain"`
	ListenPort          int     `json:"listen_port"`
	Strategy            string  `json:"strategy"`
	DynamicDNS          *bool   `json:"dynamic_dns"`
	EnableDnsServer     *bool   `json:"enable_dns_server"`
	DnsServer           *string `json:"dns_server"`
	DnsFamily           string  `json:"dns_family"`
	HealthCheckPath     *string `json:"health_check_path"`
	HealthCheckInterval int     `json:"health_check_interval"`
	HealthCheckTimeout  int     `json:"health_check_timeout"`
	// 健康检查双阈值指针化——省略（nil）=保留原值。
	// 显式 0 不再落库：写侧校验 400、启动迁移回填默认 3/2，渲染层直读库值
	// 且无效值显性失败（无写死兜底）。
	HealthCheckUnhealthyThreshold *int  `json:"health_check_unhealthy_threshold"`
	HealthCheckHealthyThreshold   *int  `json:"health_check_healthy_threshold"`
	EnableActiveHealthCheck       *bool `json:"enable_active_health_check"`
	// TCP 字段指针化——省略（nil）=保留原值。
	// tcp_try_duration 0=不重试；tcp_try_interval 由启动回填默认 250
	//（毫秒，单位与渲染输出 "250ms" 一致；DDL 与回填同取
	// db.DefaultTCPTryInterval），tcp_health_check_port 0=跟随上游端口。
	TCPHealthCheckPort       *int  `json:"tcp_health_check_port"`
	TCPProxyProtocol         *bool `json:"tcp_proxy_protocol"`
	TCPTryDuration           *int  `json:"tcp_try_duration"`
	TCPTryInterval           *int  `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB     *int  `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout *int  `json:"upstream_keepalive_timeout"`
	ServerTokensHidden       *int  `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	// NTLM 兼容开关：指针化——省略（nil）=保留原值，显式 0=关闭。
	NTLMCompatible             *int        `json:"ntlm_compatible"`
	UpstreamForceHTTP1         *int        `json:"upstream_force_http1"`
	CustomRoutesEnabled        *bool       `json:"custom_routes_enabled"`
	ProxyDialTimeout           *int        `json:"proxy_dial_timeout"`
	ProxyResponseHeaderTimeout *int        `json:"proxy_response_header_timeout"`
	ProxyReadTimeout           *int        `json:"proxy_read_timeout"`
	ProxyWriteTimeout          *int        `json:"proxy_write_timeout"`
	ProxyStreamTimeout         *int        `json:"proxy_stream_timeout"`
	ProxyFlushInterval         *int        `json:"proxy_flush_interval"`
	ProxyStreamCloseDelay      *int        `json:"proxy_stream_close_delay"`
	PathRules                  *[]PathRule `json:"path_rules"`
	HostHeader                 *string     `json:"host_header"`
	// 健康检查域名：指针化同 HostHeader——省略=保留原值，显式空串=清空。
	HealthCheckHost *string    `json:"health_check_host"`
	Upstreams       []Upstream `json:"upstreams"`
	EnableTLS       *bool      `json:"enable_tls"`
	TLSSource       string     `json:"tls_source"`
	ACMEConfigID    int        `json:"acme_config_id"`
	CAProviderID    *int       `json:"ca_provider_id"`
	TLSCert         string     `json:"tls_cert"`
	TLSKey          string     `json:"tls_key"`
	TLSHTTPRedirect *bool      `json:"tls_http_redirect"`
	EnableCompress  *bool      `json:"enable_compress"`
	CompressTypes   string     `json:"compress_types"`
	Enabled         *bool      `json:"enabled"`
	LogEnabled      *bool      `json:"log_enabled"`
	// 阶段拦截页覆盖层：指针化——省略（nil）=保留原值（同 CAProviderID 先例），
	// 显式 0=清除覆盖（跟随策略）。
	BlockPageStage1ID     *int `json:"block_page_stage1_id"`
	BlockPageStage1Status *int `json:"block_page_stage1_status"`
	BlockPageStage3ID     *int `json:"block_page_stage3_id"`
	BlockPageStage3Status *int `json:"block_page_stage3_status"`
	// ExpectedUpdatedAt 是可选乐观并发前置条件：客户端回传打开编辑表单时
	// 看到的 updated_at（RFC3339 或库内平面 UTC 形态）。省略/空串=不校验
	// （API/MCP 向后兼容）；提供且与事务内读到的库值不一致 → 409。
	// 保护粒度为秒（updated_at 写侧 datetime('now')，比较前截断到秒）：
	// 同一秒内他人已提交时版本值不变，本前置条件无法识别——跨秒的并发提交
	// 才保证拦截；需要秒内严格性时须改用独立版本列（另行设计，非当前契约）。
	ExpectedUpdatedAt string `json:"expected_updated_at"`
}

type UpdateConfigRequest struct {
	Source      string  `json:"source"`
	DNSProvider *string `json:"dns_provider"`
	// global_config.dns_credentials 已退役（列由启动迁移删除）：签发链唯一凭证
	// 来源是 certificate_configs（DNS 凭证在证书配置页维护），请求体携带
	// dns_credentials 键不存在对应字段，不产生任何写入。
	ACMEEmail                  *string `json:"acme_email"`
	CertExpiryDays             *int    `json:"cert_expiry_days"`
	CertRenewalDays            *int    `json:"cert_renewal_days"`
	CertRenewalAttempts        *int    `json:"cert_renewal_attempts"`
	LogLevel                   *string `json:"log_level"`
	CaddyLogLevel              *string `json:"caddy_log_level"`
	CaddyLogSizeMB             *int    `json:"caddy_log_size_mb"`
	RequestBodyMaxSizeMB       *int    `json:"request_body_max_size_mb"`
	HTTPReadTimeout            *int    `json:"http_read_timeout"`
	HTTPWriteTimeout           *int    `json:"http_write_timeout"`
	HTTPIdleTimeout            *int    `json:"http_idle_timeout"`
	UpstreamKeepaliveTimeout   *int    `json:"upstream_keepalive_timeout"`
	ProxyDialTimeout           *int    `json:"proxy_dial_timeout"`
	ProxyResponseHeaderTimeout *int    `json:"proxy_response_header_timeout"`
	ProxyReadTimeout           *int    `json:"proxy_read_timeout"`
	ProxyWriteTimeout          *int    `json:"proxy_write_timeout"`
	ProxyStreamTimeout         *int    `json:"proxy_stream_timeout"`
	ProxyFlushInterval         *int    `json:"proxy_flush_interval"`
	ProxyStreamCloseDelay      *int    `json:"proxy_stream_close_delay"`
	ServerTokensHidden         *bool   `json:"server_tokens_hidden"`
	TaskLogSizeMB              *int    `json:"task_log_size_mb"`
	AuditLogSizeMB             *int    `json:"audit_log_size_mb"`
	RuntimeLogSizeMB           *int    `json:"runtime_log_size_mb"`
	AccessLogJSON              *bool   `json:"access_log_json"`
	AccessLogFormat            *string `json:"access_log_format"`
	AuditRetentionMonths       *int    `json:"audit_retention_months"`
	JWTExpireMinutes           *int    `json:"jwt_expire_minutes"`
	Timezone                   *string `json:"timezone"`
	GitHubProxyURL             *string `json:"github_proxy_url"`
	// GitHubToken 可选令牌三态：nil=保持现值、空串=清除
	// （唯一撤销路径）、非空=覆盖。响应面永不回显（GlobalConfig.GitHubToken json:"-"）。
	GitHubToken         *string `json:"github_token"`
	DefaultCAProviderID *int    `json:"default_ca_provider_id"`
	// 威胁大屏本站坐标（v3）：nil=保持现值；写侧范围校验（纬度 ±90/经度 ±180）。
	ServerMapLat *float64 `json:"server_map_lat"`
	ServerMapLon *float64 `json:"server_map_lon"`
	// 威胁大屏模式（v2.3.8）：nil=保持现值；仅允许 map/globe。
	ThreatScreenMode *string `json:"threat_screen_mode"`
	// 大屏逐请求光流采样：nil=保持现值；仅允许 -1=自适应、0=关闭。
	// 全量与固定 2..64 已废除（存量由启动迁移归一 -1）。
	ThreatTrafficSampleN *int `json:"threat_traffic_sample_n"`
	// 安全事件保留（v2.3.8）：nil=保持现值；写侧只接受天数 1-3650、行数上限
	// 1-1 亿（0=自动的旧语义已废除，0/NULL 仅作 legacy 库值由启动迁移归一）。
	SecurityEventsRetentionDays *int `json:"security_events_retention_days"`
	SecurityEventsRowCap        *int `json:"security_events_row_cap"`
	// v2.1.8 MFA 全局开关（基础设置卡片，决策6）：默认均关。
	MFAWriteGuard     *bool `json:"mfa_write_guard"`
	MFALockoutEnabled *bool `json:"mfa_lockout_enabled"`
	// v2.3.x 受信代理（CDN 真实 IP）：指针化，nil=保留原值；ranges/headers
	// 为 JSON 数组文本（有序），写侧校验并归一（裸 IP 补 /32 //128）。
	// range_refs 为引用的 IP 地址列表 id（JSON 数组文本，2026-10-12），写侧
	// 校验存在性/总 CIDR 上限/条目格式并归一为规范 JSON。
	TrustedProxyEnabled   *bool   `json:"trusted_proxy_enabled"`
	TrustedProxyRanges    *string `json:"trusted_proxy_ranges"`
	TrustedProxyRangeRefs *string `json:"trusted_proxy_range_refs"`
	TrustedProxyHeaders   *string `json:"trusted_proxy_headers"`
	TrustedProxyStrict    *bool   `json:"trusted_proxy_strict"`
}

type CreateCertificateConfigRequest struct {
	Name           string            `json:"name" binding:"required"`
	DNSProvider    string            `json:"dns_provider" binding:"required"`
	DNSCredentials map[string]string `json:"dns_credentials"`
	Enabled        bool              `json:"enabled"`
}

type UpdateCertificateConfigRequest struct {
	Name           string            `json:"name"`
	DNSProvider    string            `json:"dns_provider"`
	DNSCredentials map[string]string `json:"dns_credentials"`
	Enabled        *bool             `json:"enabled"`
}

type MetricsOverview struct {
	TotalRequests  int64   `json:"total_requests"`
	RequestsPerSec float64 `json:"requests_per_sec"`
	BytesIn        int64   `json:"bytes_in"`
	BytesOut       int64   `json:"bytes_out"`
	Status2xx      int64   `json:"status_2xx"`
	Status3xx      int64   `json:"status_3xx"`
	Status4xx      int64   `json:"status_4xx"`
	Status5xx      int64   `json:"status_5xx"`
	LatencyP50     int     `json:"latency_p50"`
	LatencyP95     int     `json:"latency_p95"`
	LatencyP99     int     `json:"latency_p99"`
	ActiveRules    int     `json:"active_rules"`
	TotalRules     int     `json:"total_rules"`
	OnlineNodes    int     `json:"online_nodes"`
}

// SystemInfo contains system information
type SystemInfo struct {
	IPAddress    string            `json:"ip_address"`
	Hostname     string            `json:"hostname"`
	OSInfo       string            `json:"os_info"`
	Kernel       string            `json:"kernel"`
	Architecture string            `json:"architecture"`
	NetworkIPs   map[string]string `json:"network_ips"`
	CaddyVersion string            `json:"caddy_version"`
	// RunningStatus 仅表示「面板进程可响应」恒为 running，不反映 Caddy admin
	// 是否可达（Caddy 停摆时本字段仍为 running）。
	RunningStatus string `json:"running_status"`
	Uptime        int64  `json:"uptime"`
	// NodeMode 三态：master / slave / unknown（unknown=角色查询失败或库未装配，
	// 不得把查询失败静默呈现为 master 误导排障）。
	NodeMode string `json:"node_mode"`
	Version  string `json:"version"`
}

// SystemMetrics contains system resource usage
type SystemMetrics struct {
	CPUPercent    float64 `json:"cpu_percent"`
	MemoryTotal   uint64  `json:"memory_total"`
	MemoryUsed    uint64  `json:"memory_used"`
	MemoryPercent float64 `json:"memory_percent"`
	DiskTotal     uint64  `json:"disk_total"`
	DiskUsed      uint64  `json:"disk_used"`
	DiskPercent   float64 `json:"disk_percent"`
	// 进程/线程配额：cgroup pids.current / pids.max（真正决定 fork 失败的一层，
	// 按线程计数、含僵尸）。PidsMax=0 表示无限（pids.max 为 "max"）。
	// NprocLimit 是 PID 1 的 RLIMIT_NPROC 软限（ulimit -u），0=未采集/无限；
	// 它按宿主 UID 计数，仅作二级提示。
	PidsCurrent int     `json:"pids_current"`
	PidsMax     int     `json:"pids_max"`
	NprocLimit  int     `json:"nproc_limit"`
	PidsPercent float64 `json:"pids_percent"`
	// Degraded 列出本次采集失败的分项（memory/disk/cpu/pids）——分项降级时
	// 对应数值为 0，消费方据此区分「真的是 0」与「采集失败」。
	Degraded []string `json:"degraded,omitempty"`
}

// RealtimeTraffic contains real-time network traffic data
type RealtimeTraffic struct {
	BytesIn  int64 `json:"bytes_in"`
	BytesOut int64 `json:"bytes_out"`
}

// ConnectionStats contains TCP connection statistics
type ConnectionStats struct {
	Established int64 `json:"established"`
	TimeWait    int64 `json:"time_wait"`
	SynSent     int64 `json:"syn_sent"`
	SynRecv     int64 `json:"syn_recv"`
	FinWait1    int64 `json:"fin_wait1"`
	FinWait2    int64 `json:"fin_wait2"`
	CloseWait   int64 `json:"close_wait"`
	LastAck     int64 `json:"last_ack"`
	Listening   int64 `json:"listening"`
	Closing     int64 `json:"closing"`
	Total       int64 `json:"total"`
}

// CaddyMetrics contains Caddy server metrics
type CaddyMetrics struct {
	RequestsTotal    int64 `json:"requests_total"`
	RequestsInFlight int64 `json:"requests_in_flight"`
	BytesIn          int64 `json:"bytes_in"`
	BytesOut         int64 `json:"bytes_out"`
	Status2xx        int64 `json:"status_2xx"`
	Status3xx        int64 `json:"status_3xx"`
	Status4xx        int64 `json:"status_4xx"`
	Status5xx        int64 `json:"status_5xx"`
	Goroutines       int64 `json:"goroutines"`
}

type HostMetrics struct {
	Host             string `json:"host"`
	RequestsTotal    int64  `json:"requests_total"`
	RequestsInFlight int64  `json:"requests_in_flight"`
	Status2xx        int64  `json:"status_2xx"`
	Status3xx        int64  `json:"status_3xx"`
	Status4xx        int64  `json:"status_4xx"`
	Status5xx        int64  `json:"status_5xx"`
	BytesIn          int64  `json:"bytes_in"`
	BytesOut         int64  `json:"bytes_out"`
}

type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}
