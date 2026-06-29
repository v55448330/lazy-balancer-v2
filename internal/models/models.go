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
	Upstreams                     []Upstream   `json:"upstreams"`
	HostHeader                    string       `json:"host_header"`
	EnableTLS                     bool         `json:"enable_tls"`
	TLSSource                     string       `json:"tls_source"`
	ACMEConfigID                  int          `json:"acme_config_id"`
	TLSCert                       string       `json:"tls_cert,omitempty"`
	TLSKey                        string       `json:"tls_key,omitempty"`
	TLSAutoCert                   bool         `json:"tls_auto_cert"`
	TLSEmail                      string       `json:"tls_email"`
	TLSHTTPRedirect               bool         `json:"tls_http_redirect"`
	EnableCompress                bool         `json:"enable_compress"`
	CompressTypes                 string       `json:"compress_types"`
	Enabled                       bool         `json:"enabled"`
	CreatedBy                     int          `json:"created_by"`
	UpdatedBy                     int          `json:"updated_by"`
	CreatedAt                     time.Time    `json:"created_at"`
	UpdatedAt                     sql.NullTime `json:"updated_at"`
}

// GlobalConfig represents global configuration
type GlobalConfig struct {
	ID               int          `json:"id"`
	CaddyConfig      string       `json:"caddy_config"`
	DNSProvider      string       `json:"dns_provider"`
	DNSCredentials   string       `json:"-"`
	ACMEEmail        string       `json:"acme_email"`
	CertExpiryDays   int          `json:"cert_expiry_days"`
	LETSEncryptEmail string       `json:"letsencrypt_email"`
	LogLevel         string       `json:"log_level"`
	AccessLogEnabled bool         `json:"access_log_enabled"`
	IsMaster         bool         `json:"is_master"`
	MasterURL        string       `json:"master_url"`
	SyncInterval     int          `json:"sync_interval"`
	LastSync         sql.NullTime `json:"last_sync"`
	UpdatedAt        sql.NullTime `json:"updated_at"`
}

// Upstream represents an upstream server
type Upstream struct {
	ID         int    `json:"id"`
	RuleID     string `json:"rule_id"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Weight     int    `json:"weight"`
	Domain     string `json:"domain"`
	DynamicDNS bool   `json:"dynamic_dns"`
	Enabled    bool   `json:"enabled"`
	Protocol   string `json:"protocol"`
	DnsServer  string `json:"dns_server"`
}

// TLSCertificate represents a TLS certificate
type TLSCertificate struct {
	ID        int          `json:"id"`
	Domain    string       `json:"domain"`
	CertPEM   string       `json:"cert_pem"`
	KeyPEM    string       `json:"key_pem"`
	Issuer    string       `json:"issuer"`
	ACMEEmail string       `json:"acme_email"`
	ExpiresAt sql.NullTime `json:"expires_at"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt sql.NullTime `json:"updated_at"`
}

// CertificateConfig represents free certificate configuration (ACME + DNS provider)
type CertificateConfig struct {
	ID             int          `json:"id"`
	Name           string       `json:"name"`
	DNSProvider    string       `json:"dns_provider"`
	DNSCredentials string       `json:"-"`
	Enabled        bool         `json:"enabled"`
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      sql.NullTime `json:"updated_at"`
}

// RuleCertInfo represents parsed TLS certificate information for display in the UI
type RuleCertInfo struct {
	CaddyID       string `json:"caddy_id"`
	Source        string `json:"source"`         // "manual" | "acme_dns"
	Domains       string `json:"domains"`        // rule domain or certificate DNS names
	Issuer        string `json:"issuer"`         // issuer CN or Organization
	NotBefore     string `json:"not_before"`     // formatted effective time
	NotAfter      string `json:"not_after"`      // formatted expiration time
	DaysRemaining int    `json:"days_remaining"` // days until expiration (negative if expired)
	Status        string `json:"status"`         // "valid" | "expiring" | "expired" | "unknown"
	Error         string `json:"error,omitempty"` // error message when parsing fails
}

// CertInfoBatchRequest represents a batch cert-info query request
type CertInfoBatchRequest struct {
	CaddyIDs []string `json:"caddy_ids" binding:"required"`
}

// CertJob represents an ACME certificate issuance job
type CertJob struct {
	ID        int          `json:"id"`
	RuleID    string       `json:"rule_id"`
	Domain    string       `json:"domain"`
	Status    string       `json:"status"`
	Message   string       `json:"message"`
	ExpiresAt sql.NullTime `json:"expires_at"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt sql.NullTime `json:"updated_at"`
}

// Node represents a node in the cluster
type Node struct {
	ID           int           `json:"id"`
	Name         string        `json:"name"`
	Mode         string        `json:"mode"`
	IPAddress    string        `json:"ip_address"`
	Port         int           `json:"port"`
	MasterID     sql.NullInt64 `json:"master_id"`
	IsApproved   bool          `json:"is_approved"`
	SyncEnabled  bool          `json:"sync_enabled"`
	SyncInterval int           `json:"sync_interval"`
	SyncScope    string        `json:"sync_scope"`
	Status       string        `json:"status"`
	LastSeen     sql.NullTime  `json:"last_seen"`
	CreatedAt    time.Time     `json:"created_at"`
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

// ConfigVersion represents a configuration version for sync
type ConfigVersion struct {
	ID          int       `json:"id"`
	Version     int64     `json:"version"`
	Timestamp   time.Time `json:"timestamp"`
	ChangeType  string    `json:"change_type"`
	Description string    `json:"description"`
}

// SyncData represents the data to be synced between nodes
type SyncData struct {
	Version   int64        `json:"version"`
	Timestamp time.Time    `json:"timestamp"`
	Rules     []LbRule     `json:"rules"`
	Config    GlobalConfig `json:"config"`
	Users     []User       `json:"users,omitempty"`
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
	HostHeader                    string     `json:"host_header"`
	Upstreams                     []Upstream `json:"upstreams" binding:"required"`
	EnableTLS                     bool       `json:"enable_tls"`
	TLSSource                     string     `json:"tls_source"`
	ACMEConfigID                  int        `json:"acme_config_id"`
	TLSCert                       string     `json:"tls_cert"`
	TLSKey                        string     `json:"tls_key"`
	TLSAutoCert                   bool       `json:"tls_auto_cert"`
	TLSEmail                      string     `json:"tls_email"`
	TLSHTTPRedirect               bool       `json:"tls_http_redirect"`
	EnableCompress                bool       `json:"enable_compress"`
	CompressTypes                 string     `json:"compress_types"`
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
	HostHeader                    string     `json:"host_header"`
	Upstreams                     []Upstream `json:"upstreams"`
	EnableTLS                     bool       `json:"enable_tls"`
	TLSSource                     string     `json:"tls_source"`
	ACMEConfigID                  int        `json:"acme_config_id"`
	TLSCert                       string     `json:"tls_cert"`
	TLSKey                        string     `json:"tls_key"`
	TLSAutoCert                   bool       `json:"tls_auto_cert"`
	TLSEmail                      string     `json:"tls_email"`
	TLSHTTPRedirect               bool       `json:"tls_http_redirect"`
	EnableCompress                bool       `json:"enable_compress"`
	CompressTypes                 string     `json:"compress_types"`
	Enabled                       bool       `json:"enabled"`
}

type UpdateConfigRequest struct {
	DNSProvider      string `json:"dns_provider"`
	DNSCredentials   string `json:"dns_credentials"`
	ACMEEmail        string `json:"acme_email"`
	CertExpiryDays   int    `json:"cert_expiry_days"`
	LETSEncryptEmail string `json:"letsencrypt_email"`
	LogLevel         string `json:"log_level"`
	AccessLogEnabled *bool  `json:"access_log_enabled"`
	IsMaster         *bool  `json:"is_master"`
	MasterURL        string `json:"master_url"`
	SyncInterval     *int   `json:"sync_interval"`
}

type RegisterNodeRequest struct {
	Name      string `json:"name" binding:"required"`
	IPAddress string `json:"ip_address" binding:"required"`
	Port      int    `json:"port"`
}

type UpdateNodeRequest struct {
	Name         string `json:"name"`
	SyncEnabled  *bool  `json:"sync_enabled"`
	SyncInterval *int   `json:"sync_interval"`
	SyncScope    string `json:"sync_scope"`
}

type CreateCertificateConfigRequest struct {
	Name            string            `json:"name" binding:"required"`
	DNSProvider     string            `json:"dns_provider" binding:"required"`
	DNSCredentials  map[string]string `json:"dns_credentials"`
	Enabled         bool              `json:"enabled"`
}

type UpdateCertificateConfigRequest struct {
	Name            string            `json:"name"`
	DNSProvider     string            `json:"dns_provider"`
	DNSCredentials  map[string]string `json:"dns_credentials"`
	Enabled         *bool             `json:"enabled"`
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
