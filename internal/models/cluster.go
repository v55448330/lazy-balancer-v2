package models

type ClusterRegisterRequest struct {
	Token     string `json:"token" binding:"required"`
	Name      string `json:"name" binding:"required"`
	IPAddress string `json:"ip_address" binding:"required"`
	Port      int    `json:"port"`
}

type ClusterModeRequest struct {
	Mode          string `json:"mode" binding:"required,oneof=master slave"`
	MasterURL     string `json:"master_url"`
	RegisterToken string `json:"register_token"`
	NodeName      string `json:"node_name"`
}

type ClusterSettingsRequest struct {
	SyncInterval    *int  `json:"sync_interval" binding:"omitempty,min=5"`
	SyncCaddyConfig *bool `json:"sync_caddy_config"`
}

type ClusterRegistration struct {
	RegistrationID     int    `json:"registration_id"`
	RegistrationSecret string `json:"registration_secret"`
}

type ClusterRegistrationStatus struct {
	Status       string `json:"status"`
	ClusterToken string `json:"cluster_token,omitempty"`
}

type ClusterHealth struct {
	CaddyOK          bool   `json:"caddy_ok"`
	RulesCount       int    `json:"rules_count"`
	CertsExpiring30d int    `json:"certs_expiring_30d"`
	LastSyncAt       string `json:"last_sync_at"`
	LastSyncError    string `json:"last_sync_error"`
	UptimeSec        int64  `json:"uptime_sec"`
}

type ClusterReport struct {
	AppliedVersion int           `json:"applied_version" binding:"min=0"`
	ServiceStatus  string        `json:"service_status" binding:"required,oneof=ok degraded"`
	Health         ClusterHealth `json:"health"`
	LastSyncAt     string        `json:"last_sync_at"`
	LastSyncError  string        `json:"last_sync_error"`
}

type ClusterBasicSettings struct {
	LogLevel             string `json:"log_level"`
	AccessLogEnabled     bool   `json:"access_log_enabled"`
	AccessLogJSON        bool   `json:"access_log_json"`
	AccessLogFormat      string `json:"access_log_format"`
	CertJobLogSizeMB     int    `json:"cert_job_log_size_mb"`
	AuditRetentionMonths int    `json:"audit_retention_months"`
	JWTExpireMinutes     int    `json:"jwt_expire_minutes"`
	Timezone             string `json:"timezone"`
	ACMEEmail            string `json:"acme_email"`
	CertExpiryDays       int    `json:"cert_expiry_days"`
	CertRenewalDays      int    `json:"cert_renewal_days"`
	CertRenewalAttempts  int    `json:"cert_renewal_attempts"`
	DefaultCAProviderID  int    `json:"default_ca_provider_id"`
	DNSProvider          string `json:"dns_provider"`
	DNSCredentials       string `json:"dns_credentials"`
	SyncInterval         int    `json:"sync_interval"`
}

type ClusterUser struct {
	ID           int    `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Role         string `json:"role"`
	DisplayName  string `json:"display_name"`
	IsEnabled    bool   `json:"is_enabled"`
}

type ClusterAPIKey struct {
	ID        int    `json:"id"`
	Name      string `json:"name"`
	KeyHash   string `json:"key_hash"`
	KeyPrefix string `json:"key_prefix"`
	CreatedBy int    `json:"created_by"`
	ExpiresAt string `json:"expires_at"`
	IsEnabled bool   `json:"is_enabled"`
}

type ClusterCertificate struct {
	RuleID    string `json:"rule_id"`
	CertPEM   string `json:"cert_pem"`
	KeyPEM    string `json:"key_pem"`
	ExpiresAt string `json:"expires_at"`
}

type ClusterSnapshot struct {
	Version       int                  `json:"version"`
	Fingerprint   string               `json:"fingerprint"`
	Rules         []LbRule             `json:"rules"`
	Users         []ClusterUser        `json:"users"`
	APIKeys       []ClusterAPIKey      `json:"api_keys"`
	BasicSettings ClusterBasicSettings `json:"basic_settings"`
	CaddyConfig   *string              `json:"caddy_config,omitempty"`
	Certs         []ClusterCertificate `json:"certs"`
}

type ClusterNodeView struct {
	ID              int            `json:"id"`
	Name            string         `json:"name"`
	IPAddress       string         `json:"ip_address"`
	Port            int            `json:"port"`
	Status          string         `json:"status"`
	IsApproved      bool           `json:"is_approved"`
	ReportedVersion int            `json:"reported_version"`
	CurrentVersion  int            `json:"current_version"`
	Health          *ClusterHealth `json:"health"`
	LastSeen        string         `json:"last_seen"`
	CreatedAt       string         `json:"created_at"`
}

type ClusterStatus struct {
	NodeMode        string `json:"node_mode"`
	ClusterVersion  int    `json:"cluster_version"`
	MasterURL       string `json:"master_url"`
	SyncInterval    int    `json:"sync_interval"`
	SyncCaddyConfig bool   `json:"sync_caddy_config"`
	ClusterActive   bool   `json:"cluster_active"`
	AppliedVersion  int    `json:"applied_version"`
	LastSyncAt      string `json:"last_sync_at"`
	LastSyncError   string `json:"last_sync_error"`
	PendingCount    int    `json:"pending_count"`
	ApprovedCount   int    `json:"approved_count"`
}
