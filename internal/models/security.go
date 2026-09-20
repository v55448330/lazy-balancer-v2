package models

import "encoding/json"

// 策略实体单职化（2026-09-20 用户裁定「实体拆分」）：policy_type ∈
// stage1（IP 访问控制策略：ACL/信任/黑名单/GeoIP+拦截页）/ stage2（限流策略：
// 恒 429 不配拦截页）/ stage3（WAF 策略：模式/阈值/CRS/自定义+拦截页）/
// mixed（存量混合策略兼容组——可编辑不可新建）。类型是编辑约束与分组元数据；
// 渲染侧仍按功能字段发射（行为零变化）。
const (
	PolicyTypeStage0 = "stage0"
	PolicyTypeStage1 = "stage1"
	PolicyTypeStage2 = "stage2"
	PolicyTypeStage3 = "stage3"
	PolicyTypeMixed  = "mixed"
)

// PolicyFeatureSet 策略内容的阶段特征组：G0=信任名单（启用且内联/引用非空），
// G1=IP ACL（启用且内联/引用非空）/黑名单非空/GeoIP 生效，G2=限流（启用且
// rps>0），G3=WAF（mode∈blocking/detection/custom_only 或自定义规则引用非空）。
// 推断（InferPolicyType）与拆分迁移（split 按组生成子策略）共用同一份分组
// 判定，禁止第二份实现。阶段 0（2026-09-20 用户裁定）：信任名单独立成策略
// 类型——默认直通上游（trust_detection=0，不过后续任何流程），保留检测记录
// 时（trust_detection=1）按 DetectionOnly 全评估全记录不拦。
type PolicyFeatureSet struct {
	G0, G1, G2, G3 bool
}

// PolicyTypeFeatures 见 PolicyFeatureSet 注释。
func PolicyTypeFeatures(p *SecurityPolicy) PolicyFeatureSet {
	var fs PolicyFeatureSet
	if p == nil {
		return fs
	}
	jsonListNonEmpty := func(raw string) bool {
		var entries []json.RawMessage
		if err := json.Unmarshal([]byte(raw), &entries); err != nil {
			return false
		}
		return len(entries) > 0
	}
	fs.G0 = p.IPWhitelistEnabled && (jsonListNonEmpty(string(p.IPWhitelist)) || jsonListNonEmpty(p.IPWhitelistRefs))
	fs.G1 = (p.IPACLEnabled && (jsonListNonEmpty(p.IPACLList) || jsonListNonEmpty(p.IPACLListRefs))) ||
		jsonListNonEmpty(string(p.IPBlacklist)) ||
		(p.GeoIPMode != "" && p.GeoIPMode != "off" && jsonListNonEmpty(string(p.GeoIPCountries)))
	fs.G2 = p.RateLimitEnabled && p.RateLimitRPS > 0
	fs.G3 = p.Mode == "blocking" || p.Mode == "detection" || p.Mode == "custom_only" || jsonListNonEmpty(string(p.CustomRules))
	return fs
}

// InferPolicyType 按内容特征推断策略类型——backfill、写侧缺省提交、旧快照/
// 旧备份导入的共同单一事实源。恰好一组→对应类型（G0→stage0），多组→mixed，
// 零组→stage3（WAF 是安全策略默认心智，空策略归此）。
func InferPolicyType(p *SecurityPolicy) string {
	fs := PolicyTypeFeatures(p)
	count := 0
	for _, g := range []bool{fs.G0, fs.G1, fs.G2, fs.G3} {
		if g {
			count++
		}
	}
	switch {
	case count > 1:
		return PolicyTypeMixed
	case fs.G0:
		return PolicyTypeStage0
	case fs.G1:
		return PolicyTypeStage1
	case fs.G2:
		return PolicyTypeStage2
	default:
		return PolicyTypeStage3
	}
}

type SecurityPolicy struct {
	ID                 int             `json:"id"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Mode               string          `json:"mode"`
	AnomalyThreshold   int             `json:"anomaly_threshold"`
	IPACLMode          string          `json:"ip_acl_mode"`
	IPACLList          string          `json:"ip_acl_list"`
	IPACLEnabled       bool            `json:"ip_acl_enabled"`
	IPWhitelist        json.RawMessage `json:"ip_whitelist"`
	IPWhitelistEnabled bool            `json:"ip_whitelist_enabled"`
	// CustomRulesCache/CustomRulesCached：生成期自定义规则解析缓存（内部字段，
	// 不序列化）——批量路径对去重策略解析一次，防 (规则×策略) 对重复查询。
	CustomRulesCache  []CustomRule    `json:"-"`
	CustomRulesCached bool            `json:"-"`
	IPBlacklist       json.RawMessage `json:"ip_blacklist"`
	RateLimitEnabled  bool            `json:"rate_limit_enabled"`
	RateLimitRPS      int             `json:"rate_limit_rps"`
	RateLimitBurst    int             `json:"rate_limit_burst"`
	CRSRuleGroups     json.RawMessage `json:"crs_rule_groups"`
	CRSExcludedRules  json.RawMessage `json:"crs_excluded_rules"`
	CustomRules       json.RawMessage `json:"custom_rules"`
	BlockPageID       int             `json:"block_page_id"`
	BlockStatusCode   int             `json:"block_status_code"`
	Enabled           bool            `json:"enabled"`
	UpdatedBy         int             `json:"updated_by"`
	CreatedAt         string          `json:"created_at"`
	UpdatedAt         string          `json:"updated_at"`
	GeoIPCountries    json.RawMessage `json:"geoip_countries"`
	GeoIPMode         string          `json:"geoip_mode"`
	WAFCheckResponse  bool            `json:"waf_check_response"`
	LogRequestBody    bool            `json:"log_request_body"`
	// IPACLListRefs / IPWhitelistRefs：引用的 security_ip_lists id 数组（JSON 文本，
	// 与 IPACLList 同为原始 string 列、同扫描机制）。生成期与 inline 条目取并集。
	IPACLListRefs   string `json:"ip_acl_list_refs"`
	IPWhitelistRefs string `json:"ip_whitelist_refs"`
	// MergedACLList / MergedWhitelist 是生成期由策略加载路径附加的「inline ∪ 引用
	// IP 列表条目」合并集（去重、inline 优先）；nil 表示该策略未经引用解析
	//（无引用或非生成路径加载），发射端回退 inline-only。不参与 JSON 序列化。
	MergedACLList   []string `json:"-"`
	MergedWhitelist []string `json:"-"`
	// PolicyType：策略类型（单职化分组元数据，见 InferPolicyType 注释）；''
	// 为待推断存量态（读侧各入口/backfill 归一，不得长期滞留）。
	PolicyType string `json:"policy_type"`
	// TrustDetection：阶段 0（信任名单策略）的「保留检测记录」开关——0=信任 IP
	// 直通上游（不过后续任何流程，零安全事件）；1=保留检测（DetectionOnly
	// 全评估全记录不拦）。仅 stage0 策略消费；其他类型恒 0。
	TrustDetection bool `json:"trust_detection"`
}

type SecurityPolicySummary struct {
	ID                 int    `json:"id"`
	Name               string `json:"name"`
	Mode               string `json:"mode"`
	Enabled            bool   `json:"enabled"`
	RuleCount          int    `json:"rule_count"`
	HasWAF             bool   `json:"has_waf"`
	HasIPControl       bool   `json:"has_ip_control"`
	HasRateLimit       bool   `json:"has_rate_limit"`
	AnomalyThreshold   int    `json:"anomaly_threshold"`
	IPACLMode          string `json:"ip_acl_mode"`
	IPACLEnabled       bool   `json:"ip_acl_enabled"`
	IPACLList          string `json:"ip_acl_list"`
	IPWhitelist        string `json:"ip_whitelist"`
	IPWhitelistEnabled bool   `json:"ip_whitelist_enabled"`
	IPBlacklist        string `json:"ip_blacklist"`
	RateLimitRPS       int    `json:"rate_limit_rps"`
	RateLimitBurst     int    `json:"rate_limit_burst"`
	CRSExcludedCount   int    `json:"crs_excluded_count"`
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
	LogRequestBody   bool   `json:"log_request_body"`
	IPACLListRefs    string `json:"ip_acl_list_refs"`
	IPWhitelistRefs  string `json:"ip_whitelist_refs"`
	PolicyType       string `json:"policy_type"`
	TrustDetection   bool   `json:"trust_detection"`
	Blocked24h       int    `json:"blocked_24h"`
}

type CreateSecurityPolicyRequest struct {
	Name               string `json:"name" binding:"required"`
	Description        string `json:"description"`
	Mode               string `json:"mode"`
	AnomalyThreshold   int    `json:"anomaly_threshold"`
	IPACLMode          string `json:"ip_acl_mode"`
	IPACLList          string `json:"ip_acl_list"`
	IPACLEnabled       bool   `json:"ip_acl_enabled"`
	IPWhitelist        string `json:"ip_whitelist"`
	IPWhitelistEnabled *bool  `json:"ip_whitelist_enabled"`
	IPBlacklist        string `json:"ip_blacklist"`
	RateLimitEnabled   bool   `json:"rate_limit_enabled"`
	RateLimitRPS       int    `json:"rate_limit_rps"`
	RateLimitBurst     int    `json:"rate_limit_burst"`
	CRSRuleGroups      string `json:"crs_rule_groups"`
	CRSExcludedRules   string `json:"crs_excluded_rules"`
	CustomRules        string `json:"custom_rules"`
	BlockPageID        int    `json:"block_page_id"`
	BlockStatusCode    int    `json:"block_status_code"`
	Enabled            *bool  `json:"enabled"`
	GeoIPCountries     string `json:"geoip_countries"`
	GeoIPMode          string `json:"geoip_mode"`
	WAFCheckResponse   bool   `json:"waf_check_response"`
	LogRequestBody     bool   `json:"log_request_body"`
	// PolicyType：可选，∈ {stage0,stage1,stage2,stage3}；缺省（""）按内容推断；
	// 显式提交时阶段外字段归一零值；显式 mixed 拒绝（兼容组不可新建）。
	PolicyType string `json:"policy_type"`
	// TrustDetection：阶段 0「保留检测记录」开关（默认 false=直通上游）。
	TrustDetection  bool   `json:"trust_detection"`
	IPACLListRefs   string `json:"ip_acl_list_refs"`
	IPWhitelistRefs string `json:"ip_whitelist_refs"`
}

type UpdateSecurityPolicyRequest struct {
	Name               *string `json:"name"`
	Description        *string `json:"description"`
	Mode               *string `json:"mode"`
	AnomalyThreshold   *int    `json:"anomaly_threshold"`
	IPACLMode          *string `json:"ip_acl_mode"`
	IPACLList          *string `json:"ip_acl_list"`
	IPACLEnabled       *bool   `json:"ip_acl_enabled"`
	IPWhitelist        *string `json:"ip_whitelist"`
	IPWhitelistEnabled *bool   `json:"ip_whitelist_enabled"`
	IPBlacklist        *string `json:"ip_blacklist"`
	RateLimitEnabled   *bool   `json:"rate_limit_enabled"`
	RateLimitRPS       *int    `json:"rate_limit_rps"`
	RateLimitBurst     *int    `json:"rate_limit_burst"`
	CRSRuleGroups      *string `json:"crs_rule_groups"`
	CRSExcludedRules   *string `json:"crs_excluded_rules"`
	CustomRules        *string `json:"custom_rules"`
	BlockPageID        *int    `json:"block_page_id"`
	BlockStatusCode    *int    `json:"block_status_code"`
	Enabled            *bool   `json:"enabled"`
	GeoIPCountries     *string `json:"geoip_countries"`
	GeoIPMode          *string `json:"geoip_mode"`
	WAFCheckResponse   *bool   `json:"waf_check_response"`
	LogRequestBody     *bool   `json:"log_request_body"`
	IPACLListRefs      *string `json:"ip_acl_list_refs"`
	IPWhitelistRefs    *string `json:"ip_whitelist_refs"`
	// PolicyType：nil=按合并后内容重推断；显式 stage1/2/3=切换类型并归一
	// 阶段外字段；显式 mixed 拒绝。
	PolicyType *string `json:"policy_type"`
	// TrustDetection：阶段 0「保留检测记录」开关；nil=保留现值。
	TrustDetection *bool `json:"trust_detection"`
}

type SecurityEvent struct {
	ID            int    `json:"id"`
	EventTime     string `json:"event_time"`
	RuleCaddyID   string `json:"rule_caddy_id"`
	PolicyID      int    `json:"policy_id"`
	ClientIP      string `json:"client_ip"`
	IPLocation    string `json:"ip_location"`
	Method        string `json:"method"`
	URI           string `json:"uri"`
	EventType     string `json:"event_type"`
	RuleTriggered string `json:"rule_triggered"`
	RuleMsg       string `json:"rule_msg"`
	Action        string `json:"action"`
	AnomalyScore  int    `json:"anomaly_score"`
	RuleName      string `json:"rule_name"`
	PolicyName    string `json:"policy_name"`
	// RequestHeaders：事件请求的完整头（JSON 文本，8KB 截断）——摄入恒落库；
	// RequestBody：仅策略开 log_request_body 后有值（64KB 截断，非 UTF-8 转
	// base64 并带标记前缀）。敏感头掩码是前端展示层姿态，库内为原文。
	RequestHeaders string `json:"request_headers"`
	RequestBody    string `json:"request_body"`
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
	IPLocation string `json:"ip_location"`
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
	// IsLatest 三态(N2,第 16 轮):nil=未知(冷启动未取到 latest/解析失败),
	// false=有更新, true=已是最新——此前未知态默认 true 属新鲜度信任 fail-open。
	IsLatest     *bool  `json:"is_latest,omitempty"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	Trigger      string `json:"trigger"`
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

// IPList 是可复用 IP 地址列表（security_ip_lists 行）：entries 为
// IPListEntry 对象数组的 JSON 文本；策略经 ip_acl_list_refs /
// ip_whitelist_refs 以 id 引用，生成期展开为 inline ∪ 引用条目。
type IPList struct {
	ID          int             `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Category    string          `json:"category"`
	Entries     json.RawMessage `json:"entries"`
	CreatedBy   int             `json:"created_by"`
	CreatedAt   string          `json:"created_at"`
	UpdatedBy   int             `json:"updated_by"`
	UpdatedAt   string          `json:"updated_at"`
}

// IPListEntry 是 IP 地址列表的单个条目：value 必须是合法的 IP 或 CIDR
// （netip.ParsePrefix / netip.ParseAddr 双形态），remark 为自由备注。
type IPListEntry struct {
	Value  string `json:"value"`
	Remark string `json:"remark"`
}

type CreateIPListRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Entries     string `json:"entries"`
}

type UpdateIPListRequest struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
	Category    *string `json:"category"`
	Entries     *string `json:"entries"`
}

type AddIPToListRequest struct {
	Value string `json:"value"`
}
