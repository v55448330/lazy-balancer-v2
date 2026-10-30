package models

import (
	"encoding/json"
	"net/netip"
)

// 策略实体单职化（2026-09-20 用户裁定「实体拆分」）：policy_type ∈
// stage1（IP 访问控制策略：ACL/信任/黑名单/GeoIP+拦截页）/ stage2（限流策略：
// 恒 429、可选拦截页——2026-09-25 用户裁定）/ stage3（WAF 策略：模式/阈值/CRS/自定义+拦截页）/
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
// rps>0），=WAF（mode∈blocking/detection/custom_only 或自定义规则引用非空）。
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
	// raw 统一按 []byte 接收：JSON 原生列（json.RawMessage）零转换直传，
	// 仅 TEXT 扫描的 string 列（ip_acl_list/*_refs）需 []byte 包装一次——
	// 各列 Go 类型统一（全 RawMessage）留待下一大版本，先收敛判定入口计量。
	jsonListNonEmpty := func(raw []byte) bool {
		var entries []json.RawMessage
		if err := json.Unmarshal(raw, &entries); err != nil {
			return false
		}
		return len(entries) > 0
	}
	fs.G0 = p.IPWhitelistEnabled && (jsonListNonEmpty(p.IPWhitelist) || jsonListNonEmpty([]byte(p.IPWhitelistRefs)))
	fs.G1 = (p.IPACLEnabled && (jsonListNonEmpty([]byte(p.IPACLList)) || jsonListNonEmpty([]byte(p.IPACLListRefs)))) ||
		jsonListNonEmpty(p.IPBlacklist) ||
		(p.GeoIPMode != "" && p.GeoIPMode != "off" && jsonListNonEmpty(p.GeoIPCountries))
	fs.G2 = p.RateLimitEnabled && p.RateLimitRPS > 0
	fs.G3 = p.Mode == "blocking" || p.Mode == "detection" || p.Mode == "custom_only" || CustomRulesRefCount(p.CustomRules) > 0
	return fs
}

// CustomRulesRefCount 返回策略的自定义规则引用条目数（不看启用态与发射
// 缺陷）。它只服务「阶段 3 是否成立」的判定——与 PolicyTypeFeatures 的 G3
// 「custom_rules 引用非空」同一个门；摘要的 custom_rules_count 数的是
// 启用且可发射的规则（发射侧口径），前端阶段 3 判定用它会在「mode=off 且
// 引用规则全部禁用」的边界形态少标一条子策略。
func CustomRulesRefCount(raw json.RawMessage) int {
	var entries []json.RawMessage
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return 0
	}
	return len(entries)
}

// InferPolicyType 按内容特征推断策略类型——backfill、写侧缺省提交、旧快照/
// 旧备份导入的共同单一事实源。恰好一组→对应类型，多组→mixed，
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

// SecurityPolicyIPListIndex 是事件归因成员判定的名单解析快照（内部字段，
// 不序列化，与 CRSRuleGroupsParsed 同构）：名单条目在策略首次判定时解析
// 一次并聚合为「升序、去重、不相交」前缀集，同一 tick 内「事件×候选策略」
// 循环复用，成员判定走二分（与引擎 @ipListFast 同模型），不再逐事件对
// 全名单做字符串重解析。
type SecurityPolicyIPListIndex struct {
	// Prefixes 是聚合后的前缀集（升序、去重、不相交）——二分检索的前提，
	// 由 wafiplist.AggregateParsedPrefixes 单源产出。
	Prefixes []netip.Prefix
	// Entries 是名单来源的原始条目数（含空白/不可解析条目）——归因
	// 「名单非空」判据与逐元素实现同口径。
	Entries int
	// NonEmpty 是聚合后发射面非空判据（mergedACLList 输出非空）。
	NonEmpty bool
	// Built 标记快照已构建；OK=false 表示名单来源 JSON 畸形（判定按既有的
	// 「不认领」口径，不猜测内容）。
	Built bool
	OK    bool
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
	CustomRulesCache  []CustomRule `json:"-"`
	CustomRulesCached bool         `json:"-"`
	// 事件归因 contains 判定的解析缓存（内部字段，不序列化，与
	// CustomRulesCache 同构）：crs_rule_groups/custom_rules 原始 JSON 在策略
	// 首次判定时解析一次，同 tick 内「事件×候选策略」循环复用，不再逐事件
	// 重复 Unmarshal。CRSRuleGroupsOK/CustomRuleIDsOK=false 表示原始 JSON
	// 畸形（判定按不认领）。
	CRSRuleGroupsSet    map[string]struct{} `json:"-"`
	CRSRuleGroupsParsed bool                `json:"-"`
	CRSRuleGroupsOK     bool                `json:"-"`
	CustomRuleEmitIDs   map[int]struct{}    `json:"-"`
	CustomRuleIDsParsed bool                `json:"-"`
	CustomRuleIDsOK     bool                `json:"-"`
	IPBlacklist         json.RawMessage     `json:"ip_blacklist"`
	RateLimitEnabled    bool                `json:"rate_limit_enabled"`
	RateLimitRPS        int                 `json:"rate_limit_rps"`
	RateLimitBurst      int                 `json:"rate_limit_burst"`
	CRSRuleGroups       json.RawMessage     `json:"crs_rule_groups"`
	CRSExcludedRules    json.RawMessage     `json:"crs_excluded_rules"`
	CustomRules         json.RawMessage     `json:"custom_rules"`
	BlockPageID         int                 `json:"block_page_id"`
	BlockStatusCode     int                 `json:"block_status_code"`
	Enabled             bool                `json:"enabled"`
	UpdatedBy           int                 `json:"updated_by"`
	CreatedAt           string              `json:"created_at"`
	UpdatedAt           string              `json:"updated_at"`
	GeoIPCountries      json.RawMessage     `json:"geoip_countries"`
	GeoIPMode           string              `json:"geoip_mode"`
	// v2.3.8 爬虫豁免：地域拦截豁免已验证搜索引擎/AI 爬虫（方案 B：UA+PTR
	// 双跳，360=官方 IP 段）。Engines=豁免引擎 ID 数组（geoipnames 注册表）。
	GeoIPCrawlerExempt  bool            `json:"geoip_crawler_exempt"`
	GeoIPCrawlerEngines json.RawMessage `json:"geoip_crawler_engines"`
	WAFCheckResponse    bool            `json:"waf_check_response"`
	LogRequestBody      bool            `json:"log_request_body"`
	// IPACLListRefs / IPWhitelistRefs：引用的 security_ip_lists id 数组（JSON 文本，
	// 与 IPACLList 同为原始 string 列、同扫描机制）。生成期与 inline 条目取并集。
	IPACLListRefs   string `json:"ip_acl_list_refs"`
	IPWhitelistRefs string `json:"ip_whitelist_refs"`
	// MergedACLList / MergedWhitelist 是生成期由策略加载路径附加的「inline ∪ 引用
	// IP 列表条目」合并集（去重、inline 优先）；nil 表示该策略未经引用解析
	//（无引用或非生成路径加载），发射端回退 inline-only。不参与 JSON 序列化。
	MergedACLList   []string `json:"-"`
	MergedWhitelist []string `json:"-"`
	// IPRefMissing（RDB 文件化严格模式）：引用的威胁库 .iplist 文件缺失时置位，
	// 渲染发射端跳过该策略并记 ERROR+审计——宁缺勿假（绝不以空条目集静默收窄
	// ACL 保护面）。不参与 JSON 序列化。
	IPRefMissing bool `json:"-"`
	// IPWhitelistRefsNonEmpty 是摘要/列表路径的轻量判定：引用的 IP 名单中是否
	// 有含条目的名单（只查条数，不装载条目内容）。渲染路径恒 false——那里
	// MergedWhitelist 已携带真实合并集，判定优先走合并集。不参与 JSON 序列化。
	IPWhitelistRefsNonEmpty bool `json:"-"`
	// PolicyType：策略类型（单职化分组元数据，见 InferPolicyType 注释）；''
	// 为待推断存量态（读侧各入口/backfill 归一，不得长期滞留）。
	PolicyType string `json:"policy_type"`
	// TrustDetection：阶段 0（信任名单策略）的「保留检测记录」开关——0=信任 IP
	// 直通上游（不过后续任何流程，零安全事件）；1=保留检测（DetectionOnly
	// 全评估全记录不拦）。仅 stage0 策略消费；其他类型恒 0。
	TrustDetection bool `json:"trust_detection"`
	// IP 名单成员判定的解析快照（内部字段，不序列化，与上面的 CRS 解析缓存
	// 同构）：ACLIPIndex 覆盖 ip_acl_list（inline；有 refs 合并集时取合并集），
	// IPBlacklistIPIndex 覆盖遗留 ip_blacklist。两者都在策略首次判定时构建
	// 一次，同 tick 内逐事件二分检索。
	ACLIPIndex         SecurityPolicyIPListIndex `json:"-"`
	IPBlacklistIPIndex SecurityPolicyIPListIndex `json:"-"`
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
	// 摘要携带 CRS 规则组原始 JSON——前端向导跨策略重复告警直接消费摘要，
	// 不再对每条启用策略 N+1 拉取详情。
	CRSRuleGroups json.RawMessage `json:"crs_rule_groups"`
	// CRSStaleSelections：crs_rule_groups 含本地规则索引中已不存在的组号/
	// 规则 ID（CRS 更替后的陈旧选择——该部分保护静默失效，渲染侧仅
	// skip+WARN）。列表给出可观测标记，供 UI 标注「选择已失效」。
	CRSStaleSelections bool `json:"crs_stale_selections"`
	// 追加（多策略绑定根因 1）：ruleProtections 的 GeoIP/自定义
	// 规则行此前永远没有数据（接口只给 has_ip_control/has_rate_limit）。
	HasGeoIP         bool `json:"has_geoip"`
	HasCustomRules   bool `json:"has_custom_rules"`
	CustomRulesCount int  `json:"custom_rules_count"`
	// CustomRulesRefCount 是自定义规则引用条目数（含禁用/不可发射条目）——
	// 阶段 3 判定与后端 PolicyTypeFeatures.G3 逐字对齐的消费口径；
	// CustomRulesCount（启用且可发射）只用于展示「实际生效 N 条」。
	CustomRulesRefCount int    `json:"custom_rules_ref_count"`
	UpdatedBy           int    `json:"updated_by"`
	UpdatedAt           string `json:"updated_at"`
	GeoIPCountries      string `json:"geoip_countries"`
	GeoIPMode           string `json:"geoip_mode"`
	GeoIPCrawlerExempt  bool   `json:"geoip_crawler_exempt"`
	GeoIPCrawlerEngines string `json:"geoip_crawler_engines"`
	WAFCheckResponse    bool   `json:"waf_check_response"`
	LogRequestBody      bool   `json:"log_request_body"`
	IPACLListRefs       string `json:"ip_acl_list_refs"`
	IPWhitelistRefs     string `json:"ip_whitelist_refs"`
	PolicyType          string `json:"policy_type"`
	TrustDetection      bool   `json:"trust_detection"`
	Blocked24h          int    `json:"blocked_24h"`
	// Trigger24h：近 24h 归因该策略的 blocked+logged 事件数（「24h 触发」列，
	// 归因口径同 Blocked24h：policy_id>0）。
	Trigger24h int `json:"trigger_24h"`
}

type CreateSecurityPolicyRequest struct {
	Name                string `json:"name" binding:"required"`
	Description         string `json:"description"`
	Mode                string `json:"mode"`
	AnomalyThreshold    int    `json:"anomaly_threshold"`
	IPACLMode           string `json:"ip_acl_mode"`
	IPACLList           string `json:"ip_acl_list"`
	IPACLEnabled        bool   `json:"ip_acl_enabled"`
	IPWhitelist         string `json:"ip_whitelist"`
	IPWhitelistEnabled  *bool  `json:"ip_whitelist_enabled"`
	IPBlacklist         string `json:"ip_blacklist"`
	RateLimitEnabled    bool   `json:"rate_limit_enabled"`
	RateLimitRPS        int    `json:"rate_limit_rps"`
	RateLimitBurst      int    `json:"rate_limit_burst"`
	CRSRuleGroups       string `json:"crs_rule_groups"`
	CRSExcludedRules    string `json:"crs_excluded_rules"`
	CustomRules         string `json:"custom_rules"`
	BlockPageID         int    `json:"block_page_id"`
	BlockStatusCode     int    `json:"block_status_code"`
	Enabled             *bool  `json:"enabled"`
	GeoIPCountries      string `json:"geoip_countries"`
	GeoIPMode           string `json:"geoip_mode"`
	GeoIPCrawlerExempt  bool   `json:"geoip_crawler_exempt"`
	GeoIPCrawlerEngines string `json:"geoip_crawler_engines"`
	WAFCheckResponse    bool   `json:"waf_check_response"`
	LogRequestBody      bool   `json:"log_request_body"`
	// PolicyType：可选，∈ {stage0,stage1,stage2,stage3}；缺省（""）按内容推断；
	// 显式提交时阶段外字段归一零值；显式 mixed 拒绝（兼容组不可新建）。
	PolicyType string `json:"policy_type"`
	// TrustDetection：阶段 0「保留检测记录」开关（默认 false=直通上游）。
	TrustDetection  bool   `json:"trust_detection"`
	IPACLListRefs   string `json:"ip_acl_list_refs"`
	IPWhitelistRefs string `json:"ip_whitelist_refs"`
}

type UpdateSecurityPolicyRequest struct {
	Name                *string `json:"name"`
	Description         *string `json:"description"`
	Mode                *string `json:"mode"`
	AnomalyThreshold    *int    `json:"anomaly_threshold"`
	IPACLMode           *string `json:"ip_acl_mode"`
	IPACLList           *string `json:"ip_acl_list"`
	IPACLEnabled        *bool   `json:"ip_acl_enabled"`
	IPWhitelist         *string `json:"ip_whitelist"`
	IPWhitelistEnabled  *bool   `json:"ip_whitelist_enabled"`
	IPBlacklist         *string `json:"ip_blacklist"`
	RateLimitEnabled    *bool   `json:"rate_limit_enabled"`
	RateLimitRPS        *int    `json:"rate_limit_rps"`
	RateLimitBurst      *int    `json:"rate_limit_burst"`
	CRSRuleGroups       *string `json:"crs_rule_groups"`
	CRSExcludedRules    *string `json:"crs_excluded_rules"`
	CustomRules         *string `json:"custom_rules"`
	BlockPageID         *int    `json:"block_page_id"`
	BlockStatusCode     *int    `json:"block_status_code"`
	Enabled             *bool   `json:"enabled"`
	GeoIPCountries      *string `json:"geoip_countries"`
	GeoIPMode           *string `json:"geoip_mode"`
	GeoIPCrawlerExempt  *bool   `json:"geoip_crawler_exempt"`
	GeoIPCrawlerEngines *string `json:"geoip_crawler_engines"`
	WAFCheckResponse    *bool   `json:"waf_check_response"`
	LogRequestBody      *bool   `json:"log_request_body"`
	IPACLListRefs       *string `json:"ip_acl_list_refs"`
	IPWhitelistRefs     *string `json:"ip_whitelist_refs"`
	// PolicyType：nil=按合并后内容重推断；显式 stage1/2/3=切换类型并归一
	// 阶段外字段；显式 mixed 拒绝。
	PolicyType *string `json:"policy_type"`
	// TrustDetection：阶段 0「保留检测记录」开关；nil=保留现值。
	TrustDetection *bool `json:"trust_detection"`
}

// SecurityEventFeedItem 威胁大屏增量事件流条目（GET /security/events/feed）：
// 仅携带大屏渲染富化字段；攻击族经 categorizeAttack 后端单源归因（前端零复制
// 家族逻辑），同时下发 trigger_type 与 rule_triggered；rule_msg 不下发。
type SecurityEventFeedItem struct {
	ID         int    `json:"id"`
	EventTime  string `json:"event_time"`
	ClientIP   string `json:"client_ip"`
	IPLocation string `json:"ip_location"`
	Action     string `json:"action"`
	RuleName   string `json:"rule_name"`
	AttackType string `json:"attack_type"`
	// v2.3.8 大屏攻击弹框：event_type 保留原始事件类别，阶段权威=trigger_type；
	// 处理耗时（μs→ms）/异常分（危险等级真实数据源：≥12 高危、6-11 中危、<6 低危）
	EventType     string `json:"event_type"`
	DurationUs    int64  `json:"duration_us"`
	AnomalyScore  int    `json:"anomaly_score"`
	RuleTriggered string `json:"rule_triggered"`
	// TriggerType 触发类型显示语义（爬虫Bot/地域拦截/限流/IP 访问控制/WAF/请求体异常）
	TriggerType string `json:"trigger_type"`
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
	// DurationUs：安全链处理耗时（微秒；审计写插件注入本行顶层 lb_timing 字段
	// 直取——历史侧车退役;历史行/缺席为 0，前端显示为「—」;亚毫秒精度
	// 0.xxx ms 展示）。
	DurationUs int64 `json:"duration_us"`
	// PrecheckUs：该请求预检段耗时快照（µs）——WAF 事件的触发详情弹框显示
	// 「预检+WAF」完整分解;预检事件与 DurationUs 同值。
	PrecheckUs int64 `json:"precheck_us"`
	// RequestHeaders：事件请求的完整头（JSON 文本，64KB 截断——上限见
	// services.securityEventsHeadersCap；本字段**原文落库**，敏感头掩码只发生在前端
	// 展示层，备份/导出/库内读取均为原文）——
	// 摄入恒落库；
	// RequestBody：仅策略开 log_request_body 后有值（64KB 截断，非 UTF-8 转
	// base64 并带标记前缀）。敏感头掩码是前端展示层姿态，库内为原文。
	RequestHeaders string `json:"request_headers"`
	RequestBody    string `json:"request_body"`
	// TriggerType 触发类型显示语义（爬虫Bot/地域拦截/限流/IP 访问控制/WAF/请求体异常）
	TriggerType string `json:"trigger_type"`
}

type SecurityOverview struct {
	TodayBlocked  int `json:"today_blocked"`
	TodayDetected int `json:"today_detected"`
	// TodayBlockedTCP 是今日拦截的 TCP 协议拆分（event_type='tcp'，原始表
	// 直算——rollup 表无 event_type 维度；TCP 为新增事件族，行帽裁剪对历史
	// 无影响）。HTTP 拆分由消费方按 合计−TCP 计算（契约 C5）。
	TodayBlockedTCP int    `json:"today_blocked_tcp"`
	ActivePolicies  int    `json:"active_policies"`
	CRSVersion      string `json:"crs_version"`
	// CRSAvailable/IP2RegionAvailable：库文件级可用性（缺库降级感知面，
	// 2026-09-24 裁定）——版本号是历史更新记录，库缺失时前端状态标签改「缺失」
	CRSAvailable       bool                 `json:"crs_available"`
	IP2RegionAvailable bool                 `json:"ip2region_available"`
	UpdateStatus       string               `json:"update_status"`
	Trend              []SecurityTrendPoint `json:"trend"`
	TopIPs             []SecurityTopIP      `json:"top_ips"`
	AttackTypes        []SecurityAttackType `json:"attack_types"`
	// AttackTypesStage 阶段五桶（信任名单/IP 访问控制/WAF/请求体异常/其他）——
	// 历史用户裁定：总览分布图默认按阶段，取消勾选切回具体分类
	AttackTypesStage []SecurityAttackType `json:"attack_types_stage"`
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
	// Recent10m / Recent1h / Recent24h 是该 IP 在近 10 分钟 / 1 小时 / 24 小时
	// 窗口内的事件数（与 Top 10 的 7 天排序窗口独立）：用于展示攻击频率，避免
	// 只看 7 天总量无法判断“最近是否仍在活跃”。
	Recent10m  int    `json:"recent_10m"`
	Recent1h   int    `json:"recent_1h"`
	Recent24h  int    `json:"recent_24h"`
	LastTime   string `json:"last_time"`
	AttackType string `json:"attack_type"`
	// AttackTypeStage 是该 IP 的阶段化攻击类型（后端 stageCategorizeAttack
	// 单源产出,消除前端 familyToStage 硬编码映射——后端新增 family 时不再静默
	// 落「其他」)。
	AttackTypeStage string `json:"attack_type_stage"`
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
	// IsLatest 三态:nil=未知(冷启动未取到 latest/解析失败),
	// false=有更新, true=已是最新——此前未知态默认 true 属新鲜度信任 fail-open。
	IsLatest     *bool  `json:"is_latest,omitempty"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	// Available：规则目录真实可用（探针文件在）——缺库降级（2026-09-24 裁定）
	// 的前端感知面；false 时安全链整体不渲染（渲染门判据见
	// services.SecurityLibraryStatus 的两类库布尔）。
	Available bool   `json:"available"`
	Trigger   string `json:"trigger"`
	// 定时更新排程（v2.3.x）：星期集（1=周一…7=周日）+ HH:MM，时区遵循基础设置。
	ScheduleDays []int  `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

type IP2RegionInfo struct {
	Version string `json:"version"`
	// Available：库文件存在非空（缺库降级感知面，同 CRSInfo.Available）
	Available    bool   `json:"available"`
	DbSize       int    `json:"db_size"`
	UpdatedAt    string `json:"updated_at"`
	AutoUpdate   bool   `json:"auto_update"`
	UpdateStatus string `json:"update_status"`
	Message      string `json:"message"`
	Trigger      string `json:"trigger"`
	LastChecked  string `json:"last_checked"`
	NextUpdate   string `json:"next_update"`
	// 定时更新排程（v2.3.x）：同 CRSInfo。
	ScheduleDays []int  `json:"schedule_days"`
	ScheduleTime string `json:"schedule_time"`
}

type CustomRuleCondition struct {
	Target   string `json:"target"`
	Operator string `json:"operator"`
	Pattern  string `json:"pattern"`
}

type CustomRule struct {
	ID             int                   `json:"id"`
	Name           string                `json:"name"`
	Enabled        bool                  `json:"enabled"`
	Conditions     []CustomRuleCondition `json:"conditions"`
	ConditionLogic string                `json:"condition_logic"`
	Action         string                `json:"action"`
	Score          int                   `json:"score"`
	Target         string                `json:"target,omitempty"`
	Operator       string                `json:"operator,omitempty"`
	Pattern        string                `json:"pattern,omitempty"`
}

type SecurityCustomRule struct {
	ID             int                   `json:"id"`
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	Conditions     []CustomRuleCondition `json:"conditions"`
	ConditionLogic string                `json:"condition_logic"`
	Action         string                `json:"action"`
	Score          int                   `json:"score"`
	Enabled        bool                  `json:"enabled"`
	UpdatedBy      int                   `json:"updated_by"`
	CreatedAt      string                `json:"created_at"`
	UpdatedAt      string                `json:"updated_at"`
}

// CreateCustomRuleRequest 自定义规则创建请求：enabled 用
// 指针——JSON 省略即按「启用」落库（与 CreateSecurityPolicy 的 enabled 默认
// true 同口径）。此前直接绑定 SecurityCustomRule 的 bool，MCP 无约束 body
// （server.go create_custom_rule）省略 enabled 会创建一条静默禁用的 WAF 规则，
// 而审计显示创建成功；UI 恒发送 enabled=true 故仅 API/MCP 面可达。
type CreateCustomRuleRequest struct {
	Name           string                `json:"name"`
	Description    string                `json:"description"`
	Conditions     []CustomRuleCondition `json:"conditions"`
	ConditionLogic *string               `json:"condition_logic"`
	Action         string                `json:"action"`
	Score          int                   `json:"score"`
	Enabled        *bool                 `json:"enabled"`
}

// UpdateCustomRuleRequest 自定义规则更新请求：全字段指针——省略即
// 保持现值。此前直接绑定 SecurityCustomRule（bool/值类型），省略 enabled 的
// 部分更新（MCP 无约束 body 的现实路径）会把零值 false 直写落库，静默禁用
// 规则且审计无痕迹；与 UpdateSecurityPolicyRequest 同口径。
type UpdateCustomRuleRequest struct {
	Name           *string                `json:"name"`
	Description    *string                `json:"description"`
	Conditions     *[]CustomRuleCondition `json:"conditions"`
	ConditionLogic *string                `json:"condition_logic"`
	Action         *string                `json:"action"`
	Score          *int                   `json:"score"`
	Enabled        *bool                  `json:"enabled"`
}

type SecurityBlockPage struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Content     string `json:"content"`
	// ContentType 拦截响应的内容类型，可配置（2026-09-25 用户裁定）；
	// 白名单见 BlockPageContentTypeWhitelist，空值按 DefaultBlockPageContentType 归一。
	ContentType string `json:"content_type"`
	IsDefault   bool   `json:"is_default"`
	IsBuiltin   bool   `json:"is_builtin"`
	CreatedBy   int    `json:"created_by"`
	CreatedAt   string `json:"created_at"`
	UpdatedBy   int    `json:"updated_by"`
	UpdatedAt   string `json:"updated_at"`
	// RuleRefCount 规则引用数（仅列表端点返回）：引用本页的规则去重计数
	// （启用策略经绑定 ∪ 规则级阶段 1/3 覆盖）。
	RuleRefCount int `json:"rule_ref_count"`
}

// DefaultBlockPageContentType 拦截页默认 （内置三页同此）。
const DefaultBlockPageContentType = "text/html; charset=utf-8"

// 拦截页可选内容类型白名单（含编码；创建/更新写侧校验）。
//
// 白名单以常量声明而不是导出可变切片：切片形态下任意包都能
// append/改写，ValidBlockPageContentType 的封闭性随之失效且无测试会红。
const (
	BlockPageContentTypeJSON  = "application/json; charset=utf-8"
	BlockPageContentTypeXML   = "application/xml; charset=utf-8"
	BlockPageContentTypePlain = "text/plain; charset=utf-8"
)

// BlockPageContentTypeWhitelist 返回白名单副本（调用方可遍历/对表，
// 但无法经返回值改写白名单本身）。
func BlockPageContentTypeWhitelist() []string {
	return []string{
		DefaultBlockPageContentType,
		BlockPageContentTypeJSON,
		BlockPageContentTypeXML,
		BlockPageContentTypePlain,
	}
}

// ValidBlockPageContentType 报告 contentType 是否在白名单内（空串视为默认合法）。
func ValidBlockPageContentType(contentType string) bool {
	if contentType == "" {
		return true
	}
	switch contentType {
	case DefaultBlockPageContentType, BlockPageContentTypeJSON, BlockPageContentTypeXML, BlockPageContentTypePlain:
		return true
	}
	return false
}

// IPListEntry 是 IP 地址列表的单个条目：value 必须是合法的 IP 或 CIDR
// （netip.ParsePrefix / netip.ParseAddr 双形态），remark 为自由备注。
// created_at/expires_at可选：expires_at 非空且
// 已到期时投影层（loadIPListEntriesVia）不再下发该条目（到期即自动解封）；
// 手动条目两者留空。
type IPListEntry struct {
	Value     string `json:"value"`
	Remark    string `json:"remark"`
	CreatedAt string `json:"created_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
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
