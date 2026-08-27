package models

import "encoding/json"

type SecurityPolicy struct {
	ID               int             `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Mode             string          `json:"mode"`
	AnomalyThreshold int             `json:"anomaly_threshold"`
	IPACLMode        string          `json:"ip_acl_mode"`
	IPACLList        string          `json:"ip_acl_list"`
	IPACLEnabled     bool            `json:"ip_acl_enabled"`
	IPWhitelist      json.RawMessage `json:"ip_whitelist"`
	IPBlacklist      json.RawMessage `json:"ip_blacklist"`
	RateLimitEnabled bool            `json:"rate_limit_enabled"`
	RateLimitRPS     int             `json:"rate_limit_rps"`
	RateLimitBurst   int             `json:"rate_limit_burst"`
	CRSRuleGroups    json.RawMessage `json:"crs_rule_groups"`
	CRSExcludedRules json.RawMessage `json:"crs_excluded_rules"`
	CustomRules      json.RawMessage `json:"custom_rules"`
	BlockPageID      int             `json:"block_page_id"`
	BlockStatusCode  int             `json:"block_status_code"`
	Enabled          bool            `json:"enabled"`
	UpdatedBy        int             `json:"updated_by"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
	GeoIPCountries   json.RawMessage `json:"geoip_countries"`
	GeoIPMode        string          `json:"geoip_mode"`
	WAFCheckResponse bool            `json:"waf_check_response"`
}

type SecurityPolicySummary struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Mode             string `json:"mode"`
	Enabled          bool   `json:"enabled"`
	RuleCount        int    `json:"rule_count"`
	HasWAF           bool   `json:"has_waf"`
	HasIPControl     bool   `json:"has_ip_control"`
	HasRateLimit     bool   `json:"has_rate_limit"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	IPACLMode        string `json:"ip_acl_mode"`
	IPACLEnabled     bool   `json:"ip_acl_enabled"`
	IPACLList        string `json:"ip_acl_list"`
	IPWhitelist      string `json:"ip_whitelist"`
	IPBlacklist      string `json:"ip_blacklist"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
	RateLimitBurst   int    `json:"rate_limit_burst"`
	CRSExcludedCount int    `json:"crs_excluded_count"`
	// D-K1：摘要携带 CRS 规则组原始 JSON——前端向导跨策略重复告警直接消费摘要，
	// 不再对每条启用策略 N+1 拉取详情。
	CRSRuleGroups json.RawMessage `json:"crs_rule_groups"`
	// R72 三十次追加（多策略绑定 Q2 根因 1）：ruleProtections 的 GeoIP/自定义
	// 规则行此前永远没有数据（接口只给 has_ip_control/has_rate_limit）。
	HasGeoIP         bool   `json:"has_geoip"`
	HasCustomRules   bool   `json:"has_custom_rules"`
	CustomRulesCount int    `json:"custom_rules_count"`
	UpdatedBy        int    `json:"updated_by"`
	UpdatedAt        string `json:"updated_at"`
	GeoIPCountries   string `json:"geoip_countries"`
	GeoIPMode        string `json:"geoip_mode"`
	WAFCheckResponse bool   `json:"waf_check_response"`
}

type CreateSecurityPolicyRequest struct {
	Name             string `json:"name" binding:"required"`
	Description      string `json:"description"`
	Mode             string `json:"mode"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	IPACLMode        string `json:"ip_acl_mode"`
	IPACLList        string `json:"ip_acl_list"`
	IPACLEnabled     bool   `json:"ip_acl_enabled"`
	IPWhitelist      string `json:"ip_whitelist"`
	IPBlacklist      string `json:"ip_blacklist"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
	RateLimitBurst   int    `json:"rate_limit_burst"`
	CRSRuleGroups    string `json:"crs_rule_groups"`
	CRSExcludedRules string `json:"crs_excluded_rules"`
	CustomRules      string `json:"custom_rules"`
	BlockPageID      int    `json:"block_page_id"`
	BlockStatusCode  int    `json:"block_status_code"`
	Enabled          *bool  `json:"enabled"`
	GeoIPCountries   string `json:"geoip_countries"`
	GeoIPMode        string `json:"geoip_mode"`
	WAFCheckResponse bool   `json:"waf_check_response"`
}

type UpdateSecurityPolicyRequest struct {
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Mode             *string `json:"mode"`
	AnomalyThreshold *int    `json:"anomaly_threshold"`
	IPACLMode        *string `json:"ip_acl_mode"`
	IPACLList        *string `json:"ip_acl_list"`
	IPACLEnabled     *bool   `json:"ip_acl_enabled"`
	IPWhitelist      *string `json:"ip_whitelist"`
	IPBlacklist      *string `json:"ip_blacklist"`
	RateLimitEnabled *bool   `json:"rate_limit_enabled"`
	RateLimitRPS     *int    `json:"rate_limit_rps"`
	RateLimitBurst   *int    `json:"rate_limit_burst"`
	CRSRuleGroups    *string `json:"crs_rule_groups"`
	CRSExcludedRules *string `json:"crs_excluded_rules"`
	CustomRules      *string `json:"custom_rules"`
	BlockPageID      *int    `json:"block_page_id"`
	BlockStatusCode  *int    `json:"block_status_code"`
	Enabled          *bool   `json:"enabled"`
	GeoIPCountries   *string `json:"geoip_countries"`
	GeoIPMode        *string `json:"geoip_mode"`
	WAFCheckResponse *bool   `json:"waf_check_response"`
}

type SecurityEvent struct {
	ID            int    `json:"id"`
	EventTime     string `json:"event_time"`
	RuleCaddyID   string `json:"rule_caddy_id"`
	PolicyID      int    `json:"policy_id"`
	ClientIP      string `json:"client_ip"`
	Method        string `json:"method"`
	URI           string `json:"uri"`
	EventType     string `json:"event_type"`
	RuleTriggered string `json:"rule_triggered"`
	RuleMsg       string `json:"rule_msg"`
	Action        string `json:"action"`
	AnomalyScore  int    `json:"anomaly_score"`
	RuleName      string `json:"rule_name"`
	PolicyName    string `json:"policy_name"`
}

type SecurityOverview struct {
	TodayBlocked   int                  `json:"today_blocked"`
	TodayDetected  int                  `json:"today_detected"`
	ActivePolicies int                  `json:"active_policies"`
	CRSVersion     string               `json:"crs_version"`
	UpdateStatus   string               `json:"update_status"`
	Trend          []SecurityTrendPoint `json:"trend"`
	TopIPs         []SecurityTopIP      `json:"top_ips"`
	AttackTypes    []SecurityAttackType `json:"attack_types"`
}

type SecurityTrendPoint struct {
	Date     string `json:"date"`
	Blocked  int    `json:"blocked"`
	Detected int    `json:"detected"`
}

type SecurityTopIP struct {
	IP         string `json:"ip"`
	Blocked    int    `json:"blocked"`
	Detected   int    `json:"detected"`
	LastTime   string `json:"last_time"`
	AttackType string `json:"attack_type"`
}

type SecurityAttackType struct {
	Name  string `json:"name"`
	Value int    `json:"value"`
}

type CRSInfo struct {
	Version       string `json:"version"`
	ServerVersion string `json:"server_version"`
	AutoUpdate    bool   `json:"auto_update"`
	LastChecked   string `json:"last_checked"`
	UpdatedAt     string `json:"updated_at"`
	NextUpdate    string `json:"next_update"`
	RuleCount     int    `json:"rule_count"`
	IsLatest      bool   `json:"is_latest"`
	UpdateStatus  string `json:"update_status"`
	Message       string `json:"message"`
	Trigger       string `json:"trigger"`
}

type IP2RegionInfo struct {
	Version      string `json:"version"`
	DbSize       int    `json:"db_size"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	Trigger      string `json:"trigger"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
}

type CustomRuleCondition struct {
	Target   string `json:"target"`
	Operator string `json:"operator"`
	Pattern  string `json:"pattern"`
}

type CustomRule struct {
	ID         int                   `json:"id"`
	Name       string                `json:"name"`
	Enabled    bool                  `json:"enabled"`
	Conditions []CustomRuleCondition `json:"conditions"`
	Action     string                `json:"action"`
	Score      int                   `json:"score"`
	Target     string                `json:"target,omitempty"`
	Operator   string                `json:"operator,omitempty"`
	Pattern    string                `json:"pattern,omitempty"`
}

type SecurityCustomRule struct {
	ID          int                   `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Conditions  []CustomRuleCondition `json:"conditions"`
	Action      string                `json:"action"`
	Score       int                   `json:"score"`
	Enabled     bool                  `json:"enabled"`
	UpdatedBy   int                   `json:"updated_by"`
	CreatedAt   string                `json:"created_at"`
	UpdatedAt   string                `json:"updated_at"`
}

// UpdateCustomRuleRequest 自定义规则更新请求（R66 B-N1）：全字段指针——省略即
// 保持现值。此前直接绑定 SecurityCustomRule（bool/值类型），省略 enabled 的
// 部分更新（MCP 无约束 body 的现实路径）会把零值 false 直写落库，静默禁用
// 规则且审计无痕迹；与 UpdateSecurityPolicyRequest 同口径。
type UpdateCustomRuleRequest struct {
	Name        *string                `json:"name"`
	Description *string                `json:"description"`
	Conditions  *[]CustomRuleCondition `json:"conditions"`
	Action      *string                `json:"action"`
	Score       *int                   `json:"score"`
	Enabled     *bool                  `json:"enabled"`
}

type SecurityBlockPage struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
	IsDefault   bool   `json:"is_default"`
	CreatedBy   int    `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedBy   int    `json:"updated_by"`
	UpdatedAt   string `json:"updated_at"`
}
