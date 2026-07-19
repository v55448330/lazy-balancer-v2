package models

import (
	"database/sql"
	"time"
)

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
}

// APIKey represents an API key
type APIKey struct {
	ID        int          `json:"id"`
	Name      string       `json:"name"`
	KeyHash   string       `json:"-"`
	KeyPrefix string       `json:"key_prefix"`
	CreatedBy int          `json:"created_by"`
	LastUsed  sql.NullTime `json:"last_used"`
	ExpiresAt sql.NullTime `json:"expires_at"`
	IsEnabled bool         `json:"is_enabled"`
	CreatedAt time.Time    `json:"created_at"`
}

// LbRule represents a load balancing rule
type LbRule struct {
	ID                            int          `json:"id"`
	CaddyID                       string       `json:"caddy_id"`
	Name                          string       `json:"name"`
	Description                   string       `json:"description"`
	Protocol                      string       `json:"protocol"`
	Domain                        string       `json:"domain"`
	ListenPort                    int          `json:"listen_port"`
	Strategy                      string       `json:"strategy"`
	DynamicDNS                    bool         `json:"dynamic_dns"`
	EnableDnsServer               bool         `json:"enable_dns_server"`
	DnsServer                     string       `json:"dns_server"`
	DnsFamily                     string       `json:"dns_family"`
	HealthCheckPath               string       `json:"health_check_path"`
	HealthCheckInterval           int          `json:"health_check_interval"`
	HealthCheckTimeout            int          `json:"health_check_timeout"`
	HealthCheckUnhealthyThreshold int          `json:"health_check_unhealthy_threshold"`
	HealthCheckHealthyThreshold   int          `json:"health_check_healthy_threshold"`
	EnableActiveHealthCheck       bool         `json:"enable_active_health_check"`
	TCPHealthCheckPort            int          `json:"tcp_health_check_port"`
	TCPTryDuration                int          `json:"tcp_try_duration"`
	TCPTryInterval                int          `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB          int          `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout      int          `json:"upstream_keepalive_timeout"`
	ServerTokensHidden            int          `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	Upstreams                     []Upstream   `json:"upstreams"`
	HostHeader                    string       `json:"host_header"`
	EnableTLS                     bool         `json:"enable_tls"`
	TLSSource                     string       `json:"tls_source"`
	ACMEConfigID                  int          `json:"acme_config_id"`
	CAProviderID                  int          `json:"ca_provider_id"`
	TLSCert                       string       `json:"tls_cert,omitempty"`
	TLSKey                        string       `json:"tls_key,omitempty"`
	TLSHTTPRedirect               bool         `json:"tls_http_redirect"`
	EnableCompress                bool         `json:"enable_compress"`
	CompressTypes                 string       `json:"compress_types"`
	Enabled                       bool         `json:"enabled"`
	LogEnabled                    bool         `json:"log_enabled"`
	CreatedBy                     int          `json:"created_by"`
	UpdatedBy                     int          `json:"updated_by"`
	CreatedAt                     time.Time    `json:"created_at"`
	UpdatedAt                     sql.NullTime `json:"updated_at"`
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
	DirectoryURL  *string `json:"directory_url"`
	Credentials   *string `json:"credentials"`
	MaxConcurrent *int    `json:"max_concurrent"`
	MinIntervalMS *int    `json:"min_interval_ms"`
	Enabled       *bool   `json:"enabled"`
}

// GlobalConfig represents global configuration
type GlobalConfig struct {
	ID                       int          `json:"id"`
	CaddyConfig              string       `json:"caddy_config"`
	DNSProvider              string       `json:"dns_provider"`
	DNSCredentials           string       `json:"-"`
	ACMEEmail                string       `json:"acme_email"`
	CertExpiryDays           int          `json:"cert_expiry_days"`
	CertRenewalDays          int          `json:"cert_renewal_days"`
	CertRenewalAttempts      int          `json:"cert_renewal_attempts"`
	LogLevel                 string       `json:"log_level"`
	AccessLogEnabled         bool         `json:"access_log_enabled"`
	CaddyLogPath             string       `json:"caddy_log_path"`
	CaddyLogLevel            string       `json:"caddy_log_level"`
	CaddyLogSizeMB           int          `json:"caddy_log_size_mb"`
	RequestBodyMaxSizeMB     int          `json:"request_body_max_size_mb"`
	HTTPReadTimeout          int          `json:"http_read_timeout"`
	HTTPWriteTimeout         int          `json:"http_write_timeout"`
	HTTPIdleTimeout          int          `json:"http_idle_timeout"`
	UpstreamKeepaliveTimeout int          `json:"upstream_keepalive_timeout"`
	ServerTokensHidden       bool         `json:"server_tokens_hidden"`
	CertJobLogSizeMB         int          `json:"cert_job_log_size_mb"`
	AccessLogJSON            bool         `json:"access_log_json"`
	AccessLogFormat          string       `json:"access_log_format"`
	AuditRetentionMonths     int          `json:"audit_retention_months"`
	JWTExpireMinutes         int          `json:"jwt_expire_minutes"`
	Timezone                 string       `json:"timezone"`
	IsMaster                 bool         `json:"is_master"`
	MasterURL                string       `json:"master_url"`
	SyncInterval             int          `json:"sync_interval"`
	DefaultCAProviderID      int          `json:"default_ca_provider_id"`
	ClusterVersion           int          `json:"cluster_version"`
	SyncCaddyConfig          bool         `json:"sync_caddy_config"`
	ClusterToken             string       `json:"-"`
	RegistrationID           int          `json:"-"`
	RegistrationSecret       string       `json:"-"`
	AppliedVersion           int          `json:"applied_version"`
	LastSyncError            string       `json:"last_sync_error"`
	LastSync                 sql.NullTime `json:"last_sync"`
	UpdatedAt                sql.NullTime `json:"updated_at"`
}

// Upstream represents an upstream server
type Upstream struct {
	ID             int    `json:"id"`
	RuleID         string `json:"rule_id"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Weight         int    `json:"weight"`
	Domain         string `json:"domain"`
	DynamicDNS     bool   `json:"dynamic_dns"`
	Enabled        bool   `json:"enabled"`
	Protocol       string `json:"protocol"`
	DnsServer      string `json:"dns_server"`
	MaxConnections int    `json:"max_connections"`
	ProxyProtocol  string `json:"proxy_protocol"`
}

// TLSCertificate represents a TLS certificate
type TLSCertificate struct {
	ID        int          `json:"id"`
	Domain    string       `json:"domain"`
	CertPEM   string       `json:"cert_pem"`
	KeyPEM    string       `json:"key_pem"`
	Issuer    string       `json:"issuer"`
	ExpiresAt sql.NullTime `json:"expires_at"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt sql.NullTime `json:"updated_at"`
}

// CertificateConfig represents free certificate configuration (ACME + DNS provider)
type CertificateConfig struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	DNSProvider    string       `json:"dns_provider"`
	DNSCredentials string       `json:"dns_credentials"`
	Enabled        bool         `json:"enabled"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      sql.NullTime `json:"updated_at"`
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
	ExpiresAt        sql.NullTime `json:"expires_at"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        sql.NullTime `json:"updated_at"`
}

// CertJobLog represents a single log line for a certificate issuance job
type CertJobLog struct {
	ID        int       `json:"id"`
	JobID     int       `json:"job_id"`
	Level     string    `json:"level"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// Node represents a node in the cluster
type Node struct {
	ID                 int           `json:"id"`
	Name               string        `json:"name"`
	Mode               string        `json:"mode"`
	IPAddress          string        `json:"ip_address"`
	Port               int           `json:"port"`
	MasterID           sql.NullInt64 `json:"master_id"`
	IsApproved         bool          `json:"is_approved"`
	SyncEnabled        bool          `json:"sync_enabled"`
	SyncInterval       int           `json:"sync_interval"`
	SyncScope          string        `json:"sync_scope"`
	Status             string        `json:"status"`
	ClusterTokenHash   string        `json:"-"`
	RegistrationSecret string        `json:"-"`
	ReportedVersion    int           `json:"reported_version"`
	HealthJSON         string        `json:"-"`
	LastSyncAt         sql.NullTime  `json:"last_sync_at"`
	LastSyncError      string        `json:"last_sync_error"`
	LastSeen           sql.NullTime  `json:"last_seen"`
	CreatedAt          time.Time     `json:"created_at"`
}

// MetricsHistory represents historical metrics data
type MetricsHistory struct {
	ID            int       `json:"id"`
	RuleID        int       `json:"rule_id"`
	Timestamp     time.Time `json:"timestamp"`
	RequestsTotal int       `json:"requests_total"`
	Requests2xx   int       `json:"requests_2xx"`
	Requests3xx   int       `json:"requests_3xx"`
	Requests4xx   int       `json:"requests_4xx"`
	Requests5xx   int       `json:"requests_5xx"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
	LatencyP50    int       `json:"latency_p50"`
	LatencyP95    int       `json:"latency_p95"`
	LatencyP99    int       `json:"latency_p99"`
}

// Request/Response types
type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginResponse struct {
	Token    string `json:"token"`
	User     User   `json:"user"`
	NodeMode string `json:"node_mode"`
}

type CreateUserRequest struct {
	Username    string `json:"username" binding:"required"`
	Password    string `json:"password" binding:"required"`
	Role        string `json:"role" binding:"required"`
	DisplayName string `json:"display_name"`
}

type CreateAPIKeyRequest struct {
	Name      string     `json:"name" binding:"required"`
	ExpiresAt *time.Time `json:"expires_at"`
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
	TCPTryDuration                int        `json:"tcp_try_duration"`
	TCPTryInterval                int        `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB          int        `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout      int        `json:"upstream_keepalive_timeout"`
	ServerTokensHidden            int        `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	HostHeader                    string     `json:"host_header"`
	Upstreams                     []Upstream `json:"upstreams" binding:"required"`
	EnableTLS                     bool       `json:"enable_tls"`
	TLSSource                     string     `json:"tls_source"`
	ACMEConfigID                  int        `json:"acme_config_id"`
	CAProviderID                  int        `json:"ca_provider_id"`
	TLSCert                       string     `json:"tls_cert"`
	TLSKey                        string     `json:"tls_key"`
	TLSHTTPRedirect               bool       `json:"tls_http_redirect"`
	EnableCompress                bool       `json:"enable_compress"`
	CompressTypes                 string     `json:"compress_types"`
	LogEnabled                    bool       `json:"log_enabled"`
}

type UpdateRuleRequest struct {
	Name                          string     `json:"name"`
	Description                   string     `json:"description"`
	Protocol                      string     `json:"protocol"`
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
	TCPTryDuration                int        `json:"tcp_try_duration"`
	TCPTryInterval                int        `json:"tcp_try_interval"`
	RequestBodyMaxSizeMB          *int       `json:"request_body_max_size_mb"`
	UpstreamKeepaliveTimeout      *int       `json:"upstream_keepalive_timeout"`
	ServerTokensHidden            *int       `json:"server_tokens_hidden"` // 0=default, 1=hide, 2=show
	HostHeader                    string     `json:"host_header"`
	Upstreams                     []Upstream `json:"upstreams"`
	EnableTLS                     bool       `json:"enable_tls"`
	TLSSource                     string     `json:"tls_source"`
	ACMEConfigID                  int        `json:"acme_config_id"`
	CAProviderID                  *int       `json:"ca_provider_id"`
	TLSCert                       string     `json:"tls_cert"`
	TLSKey                        string     `json:"tls_key"`
	TLSHTTPRedirect               bool       `json:"tls_http_redirect"`
	EnableCompress                bool       `json:"enable_compress"`
	CompressTypes                 string     `json:"compress_types"`
	Enabled                       bool       `json:"enabled"`
	LogEnabled                    bool       `json:"log_enabled"`
}

type UpdateConfigRequest struct {
	Source                   string  `json:"source"`
	DNSProvider              *string `json:"dns_provider"`
	DNSCredentials           *string `json:"dns_credentials"`
	ACMEEmail                *string `json:"acme_email"`
	CertExpiryDays           *int    `json:"cert_expiry_days"`
	CertRenewalDays          *int    `json:"cert_renewal_days"`
	CertRenewalAttempts      *int    `json:"cert_renewal_attempts"`
	LogLevel                 *string `json:"log_level"`
	AccessLogEnabled         *bool   `json:"access_log_enabled"`
	CaddyLogPath             *string `json:"caddy_log_path"`
	CaddyLogLevel            *string `json:"caddy_log_level"`
	CaddyLogSizeMB           *int    `json:"caddy_log_size_mb"`
	RequestBodyMaxSizeMB     *int    `json:"request_body_max_size_mb"`
	HTTPReadTimeout          *int    `json:"http_read_timeout"`
	HTTPWriteTimeout         *int    `json:"http_write_timeout"`
	HTTPIdleTimeout          *int    `json:"http_idle_timeout"`
	UpstreamKeepaliveTimeout *int    `json:"upstream_keepalive_timeout"`
	ServerTokensHidden       *bool   `json:"server_tokens_hidden"`
	CertJobLogSizeMB         *int    `json:"cert_job_log_size_mb"`
	AccessLogJSON            *bool   `json:"access_log_json"`
	AccessLogFormat          *string `json:"access_log_format"`
	AuditRetentionMonths     *int    `json:"audit_retention_months"`
	JWTExpireMinutes         *int    `json:"jwt_expire_minutes"`
	Timezone                 *string `json:"timezone"`
	DefaultCAProviderID      *int    `json:"default_ca_provider_id"`
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
	IPAddress     string            `json:"ip_address"`
	Hostname      string            `json:"hostname"`
	OSInfo        string            `json:"os_info"`
	Kernel        string            `json:"kernel"`
	Architecture  string            `json:"architecture"`
	NetworkIPs    map[string]string `json:"network_ips"`
	CaddyVersion  string            `json:"caddy_version"`
	RunningStatus string            `json:"running_status"`
	Uptime        int64             `json:"uptime"`
	NodeMode      string            `json:"node_mode"`
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
}

// RealtimeTraffic contains real-time network traffic data
type RealtimeTraffic struct {
	BytesIn    int64 `json:"bytes_in"`
	BytesOut   int64 `json:"bytes_out"`
	PacketsIn  int64 `json:"packets_in"`
	PacketsOut int64 `json:"packets_out"`
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
