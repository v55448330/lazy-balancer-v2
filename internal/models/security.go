package models

import "encoding/json"

type SecurityPolicy struct {
	ID               int             `json:"id"`
	Name             string          `json:"name"`
	Description      string          `json:"description"`
	Mode             string          `json:"mode"`
	AnomalyThreshold int             `json:"anomaly_threshold"`
	IPWhitelist      json.RawMessage `json:"ip_whitelist"`
	IPBlacklist      json.RawMessage `json:"ip_blacklist"`
	RateLimitEnabled bool            `json:"rate_limit_enabled"`
	RateLimitRPS     int             `json:"rate_limit_rps"`
	RateLimitBurst   int             `json:"rate_limit_burst"`
	CRSRuleGroups    json.RawMessage `json:"crs_rule_groups"`
	CustomRules      json.RawMessage `json:"custom_rules"`
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
	IPWhitelist      string `json:"ip_whitelist"`
	IPBlacklist      string `json:"ip_blacklist"`
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPS     int    `json:"rate_limit_rps"`
	RateLimitBurst   int    `json:"rate_limit_burst"`
	CRSRuleGroups    string `json:"crs_rule_groups"`
	CustomRules      string `json:"custom_rules"`
	Enabled          *bool  `json:"enabled"`
}

type UpdateSecurityPolicyRequest struct {
	Name             *string `json:"name"`
	Description      *string `json:"description"`
	Mode             *string `json:"mode"`
	AnomalyThreshold *int    `json:"anomaly_threshold"`
	IPWhitelist      *string `json:"ip_whitelist"`
	IPBlacklist      *string `json:"ip_blacklist"`
	RateLimitEnabled *bool   `json:"rate_limit_enabled"`
	RateLimitRPS     *int    `json:"rate_limit_rps"`
	RateLimitBurst   *int    `json:"rate_limit_burst"`
	CRSRuleGroups    *string `json:"crs_rule_groups"`
	CustomRules      *string `json:"custom_rules"`
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
	TodayBlocked   int    `json:"today_blocked"`
	TodayDetected  int    `json:"today_detected"`
	ActivePolicies int    `json:"active_policies"`
	CRSVersion     string `json:"crs_version"`
}

type CRSInfo struct {
	Version     string `json:"version"`
	AutoUpdate  bool   `json:"auto_update"`
	LastChecked string `json:"last_checked"`
	RuleCount   int    `json:"rule_count"`
}

type CustomRule struct {
	ID         int    `json:"id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Target     string `json:"target"`
	Operator   string `json:"operator"`
	Pattern    string `json:"pattern"`
	Action     string `json:"action"`
	Score      int    `json:"score"`
	StatusCode int    `json:"status_code"`
}
