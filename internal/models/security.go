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
	Enabled          bool            `json:"enabled"`
	CreatedAt        string          `json:"created_at"`
	UpdatedAt        string          `json:"updated_at"`
}

type SecurityPolicySummary struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Mode         string `json:"mode"`
	Enabled      bool   `json:"enabled"`
	RuleCount    int    `json:"rule_count"`
	HasWAF       bool   `json:"has_waf"`
	HasIPControl bool   `json:"has_ip_control"`
	HasRateLimit bool   `json:"has_rate_limit"`
}

type CreateSecurityPolicyRequest struct {
	Name             string `json:"name" binding:"required"`
	Description      string `json:"description"`
	Mode             string `json:"mode"`
	AnomalyThreshold int    `json:"anomaly_threshold"`
	IPACLMode        string `json:"ip_acl_mode"`
	IPACLList        string `json:"ip_acl_list"`
	IPACLEnabled     bool   `json:"ip_acl_enabled"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
	RateLimitBurst   int    `json:"rate_limit_burst"`
	CRSRuleGroups    string `json:"crs_rule_groups"`
	CRSExcludedRules string `json:"crs_excluded_rules"`
	CustomRules      string `json:"custom_rules"`
	BlockPageID      int    `json:"block_page_id"`
	Enabled          *bool  `json:"enabled"`
}

type UpdateSecurityPolicyRequest struct {
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Mode             *string `json:"mode"`
	AnomalyThreshold *int    `json:"anomaly_threshold"`
	IPACLMode        *string `json:"ip_acl_mode"`
	IPACLList        *string `json:"ip_acl_list"`
	IPACLEnabled     *bool   `json:"ip_acl_enabled"`
	RateLimitEnabled *bool   `json:"rate_limit_enabled"`
	RateLimitRPS     *int    `json:"rate_limit_rps"`
	RateLimitBurst   *int    `json:"rate_limit_burst"`
	CRSRuleGroups    *string `json:"crs_rule_groups"`
	CRSExcludedRules *string `json:"crs_excluded_rules"`
	CustomRules      *string `json:"custom_rules"`
	BlockPageID      *int    `json:"block_page_id"`
	Enabled          *bool   `json:"enabled"`
}

type SecurityEvent struct {
	ID             int    `json:"id"`
	EventTime      string `json:"event_time"`
	RuleCaddyID    string `json:"rule_caddy_id"`
	PolicyID       int    `json:"policy_id"`
	ClientIP       string `json:"client_ip"`
	Method         string `json:"method"`
	URI            string `json:"uri"`
	EventType      string `json:"event_type"`
	RuleTriggered  string `json:"rule_triggered"`
	RuleMsg        string `json:"rule_msg"`
	Action         string `json:"action"`
	AnomalyScore   int    `json:"anomaly_score"`
	RequestSnippet string `json:"request_snippet"`
	ResponseStatus int    `json:"response_status"`
}

type SecurityOverview struct {
	TodayBlocked   int                  `json:"today_blocked"`
	TodayDetected  int                  `json:"today_detected"`
	ActivePolicies int                  `json:"active_policies"`
	CRSVersion     string               `json:"crs_version"`
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
	StatusCode int                   `json:"status_code"`
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
	StatusCode  int                   `json:"status_code"`
	Enabled     bool                  `json:"enabled"`
	CreatedAt   string                `json:"created_at"`
	UpdatedAt   string                `json:"updated_at"`
}

type SecurityBlockPage struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
	StatusCode  int    `json:"status_code"`
	IsDefault   bool   `json:"is_default"`
	CreatedBy   int    `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedBy   int    `json:"updated_by"`
	UpdatedAt   string `json:"updated_at"`
}
