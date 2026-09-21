package services

// allow: SIZE_OK — single cohesive WAF audit-log ingestion module; the
// deliverable is mandated as this one file and splitting is not authorized.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// Security event ingestion: tails the Coraza WAF audit log (consecutive
// pretty-printed JSON transactions) and inserts parsed rows into the
// security_events table. All identifiers carry the securityEvents prefix to
// avoid package-level symbol clashes inside services.

var (
	securityEventsOffsetPath   = "/app/data/security_events.offset"
	securityEventsPollInterval = 2 * time.Second
)

// securityEventRecord is one parsed audit transaction ready for insertion.
type securityEventRecord struct {
	TransactionID string
	EventTime     string
	Host          string
	// AttributionRuleID 是链首注入的 X-LB-Rule-ID 请求头值（F3）：规则归因的
	// 一等信号，优先于 host 反查；注入头缺失/指向已删除规则时回退 host 映射。
	AttributionRuleID string
	ClientIP          string
	Method            string
	URI               string
	EventType         string
	RuleTriggered     string
	RuleMsg           string
	Action            string
	AnomalyScore      int
	RequestHeaders    string
	RequestBody       string
}

// securityEventsAuditMessage 是一条审计消息：message 为宏展开后的规则 msg，
// data.id 是规则 ID（数字），data.raw 是发射的 SecRule 原文。
type securityEventsAuditMessage struct {
	Message string `json:"message"`
	Data    struct {
		ID  json.Number `json:"id"`
		Raw string      `json:"raw"`
	} `json:"data"`
}

// securityEventsAuditTransaction mirrors the Coraza JSON audit envelope:
// messages is a TOP-LEVEL sibling of transaction, not nested inside it.
// coraza v3 审计格式没有 data.score 字段——异常评分藏在两处（见
// securityEventsExtractAnomalyScore）。
type securityEventsAuditTransaction struct {
	Transaction struct {
		UnixTimestamp int64  `json:"unix_timestamp"`
		ID            string `json:"id"`
		ClientIP      string `json:"client_ip"`
		ServerID      string `json:"server_id"`
		Request       struct {
			Method  string              `json:"method"`
			URI     string              `json:"uri"`
			Headers map[string][]string `json:"headers"`
			// Body 仅当策略 handler 的 SecAuditLogParts 含 C（策略开
			// log_request_body）时由 coraza 输出；其余事务为零值空串。
			Body string `json:"body"`
		} `json:"request"`
		IsInterrupted bool `json:"is_interrupted"`
	} `json:"transaction"`
	Messages []securityEventsAuditMessage `json:"messages"`
}

// securityEventsTotalScoreRe 匹配 CRS 阻断/检测评估规则（949110/949111/959100
// 等）msg 宏展开后的累计总分："Inbound Anomaly Score Exceeded [in phase 1]
// (Total Score: 7)" / "Outbound Anomaly Score Exceeded (Total Score: 3)"。
var securityEventsTotalScoreRe = regexp.MustCompile(`Total Score:\s*(\d+)`)

// securityEventsSetvarScoreRe 匹配自定义规则 raw 动作串里的分值注入：
// setvar:tx.inbound_anomaly_score_pl1=+5（outbound_… 同型）。CRS 规则的 raw 里
// 是宏（+%{tx.critical_anomaly_score}），数字字面量只有自定义规则会发。
var securityEventsSetvarScoreRe = regexp.MustCompile(`setvar:tx\.(?:inbound|outbound)_anomaly_score_pl\d+=\+(\d+)`)

// securityEventsExtractAnomalyScore 从审计消息里提取异常评分。coraza v3 的
// 审计 JSON 不携带任何 score 字段，可提取的信号有两个：
//  1. 阻断评估规则的 msg 文本（宏已展开）携带事务累计总分——入站/出站是两个
//     独立累加器，取最大值即该事务的异常总分；
//  2. 自定义规则消息的 data.raw（发射的 SecRule 原文）携带 setvar:+N 字面量，
//     逐条求和——phase 1 直接 deny 的事务（自定义规则拦截）不会执行 949 评估，
//     这是它唯一的评分信号。
//
// 两信号并存时取 max：949 文本报告的本身就是含自定义贡献的累计值，正常两者
// 相等；不等时（评估规则被排除等边缘）宁大勿小。无可提取信号返回 0（IP ACL
// 拒绝等非评分事件）。
func securityEventsExtractAnomalyScore(messages []securityEventsAuditMessage) int {
	totalFromMsg, setvarSum := 0, 0
	for _, msg := range messages {
		for _, m := range securityEventsTotalScoreRe.FindAllStringSubmatch(msg.Message, -1) {
			if v, err := strconv.Atoi(m[1]); err == nil && v > totalFromMsg {
				totalFromMsg = v
			}
		}
		for _, m := range securityEventsSetvarScoreRe.FindAllStringSubmatch(msg.Data.Raw, -1) {
			if v, err := strconv.Atoi(m[1]); err == nil {
				setvarSum += v
			}
		}
	}
	return max(totalFromMsg, setvarSum)
}

// errSecurityEventsEmptyID 标记无 transaction_id 的事务：去重唯一索引是部分索引
// （谓词排除空 transaction_id，DDL 见 db/metrics.go 的 idx_security_events_transaction；
// gofmt 会把 doc 注释内的空串字面量两单引号改写为全角右引号，故以文字代字面量）。
// 空 id 没有幂等键，重试路径（tick 失败重放、轮转补采与 tick 重叠）会重复插入，
// 因此视为解析失败跳过。
var errSecurityEventsEmptyID = errors.New("transaction has no id")

// errSecurityEventsStalled 标记「残缺文档等待补写」的停等状态（SECLB35-1）：
// 非故障，但必须以非 nil 错误返回——tick 的 lastPassClean 会因此置假，空闲
// tick 提前返回被禁用，停等计数才能在文件不再增长时（真·崩溃残片）继续
// 递增直至触发跳过；告警侧由 60s 同消息限流兜底。
var errSecurityEventsStalled = errors.New("security events: audit data incomplete, waiting for writer")

// securityEventsParseTransaction maps one Coraza audit transaction into a
// record. Rule fields come from the first message; the anomaly score sums all
// message scores. host = server_id, falling back to the request host header
// with any port stripped.
func securityEventsParseTransaction(raw json.RawMessage) (*securityEventRecord, error) {
	var doc securityEventsAuditTransaction
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("invalid audit transaction JSON: %w", err)
	}
	tx := doc.Transaction
	if tx.UnixTimestamp == 0 {
		return nil, errors.New("transaction has no unix_timestamp")
	}
	if tx.ID == "" {
		return nil, errSecurityEventsEmptyID
	}
	rec := &securityEventRecord{
		TransactionID: tx.ID,
		EventTime:     securityEventsUnixTimestampUTC(tx.UnixTimestamp),
		Host:          tx.ServerID,
		ClientIP:      tx.ClientIP,
		Method:        tx.Request.Method,
		URI:           tx.Request.URI,
		EventType:     "waf",
		Action:        "logged",
	}
	rec.AttributionRuleID = securityEventsFirstHeader(tx.Request.Headers, "x-lb-rule-id")
	rec.RequestHeaders = securityEventsSerializeHeaders(tx.Request.Headers)
	rec.RequestBody = securityEventsEncodeBody(tx.Request.Body)
	if tx.IsInterrupted {
		rec.Action = "blocked"
	}
	if rec.Host == "" {
		rec.Host = securityEventsHostWithoutPort(securityEventsFirstHeader(tx.Request.Headers, "host"))
	}
	if len(doc.Messages) > 0 {
		rec.RuleTriggered = doc.Messages[0].Data.ID.String()
		rec.RuleMsg = doc.Messages[0].Message
	}
	rec.AnomalyScore = securityEventsExtractAnomalyScore(doc.Messages)
	return rec, nil
}

// securityEventsUnixTimestampUTC renders a unix timestamp as UTC
// "2006-01-02 15:04:05". Coraza builds emit different units (the live audit
// log writes nanoseconds); the magnitude selects the unit.
func securityEventsUnixTimestampUTC(ts int64) string {
	var sec, nsec int64
	switch {
	case ts >= 1e17: // nanoseconds
		sec, nsec = ts/1e9, ts%1e9
	case ts >= 1e14: // microseconds
		sec, nsec = ts/1e6, (ts%1e6)*1e3
	case ts >= 1e11: // milliseconds
		sec, nsec = ts/1e3, (ts%1e3)*1e6
	default: // seconds
		sec = ts
	}
	return time.Unix(sec, nsec).UTC().Format("2006-01-02 15:04:05")
}

func securityEventsFirstHeader(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

func securityEventsHostWithoutPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}

const (
	securityEventsHeadersCap = 8192
	securityEventsBodyCap    = 65536
)

// securityEventsSerializeHeaders 落库事件请求头：JSON 文本，8KB 上限——超限按
// 值体积从大到小逐条丢弃，并以 _dropped 键记录丢弃条数（始终保持合法 JSON，
// 前端无需容错解析）。头名/值原文保留，敏感值掩码是展示层姿态。
func securityEventsSerializeHeaders(headers map[string][]string) string {
	if len(headers) == 0 {
		return ""
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		return ""
	}
	if len(raw) <= securityEventsHeadersCap {
		return string(raw)
	}
	trimmed := make(map[string][]string, len(headers)+1)
	for k, v := range headers {
		trimmed[k] = v
	}
	keys := make([]string, 0, len(trimmed))
	for k := range trimmed {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return securityEventsHeaderValueSize(trimmed[keys[i]]) > securityEventsHeaderValueSize(trimmed[keys[j]])
	})
	dropped := 0
	for _, k := range keys {
		delete(trimmed, k)
		dropped++
		trimmed["_dropped"] = []string{strconv.Itoa(dropped)}
		raw, err = json.Marshal(trimmed)
		if err != nil {
			return ""
		}
		if len(raw) <= securityEventsHeadersCap {
			break
		}
	}
	return string(raw)
}

func securityEventsHeaderValueSize(values []string) int {
	n := 0
	for _, v := range values {
		n += len(v)
	}
	return n
}

// securityEventsEncodeBody 落库事件请求体：64KB 上限。UTF-8 文本原样存储，
// 超限截到符文边界（不劈开多字节字符）并追加 \n...[TRUNCATED]；二进制整体
// base64 并加 base64: 前缀，超限只编码前 64KB 原始字节、前缀改为
// base64-truncated:。空体存空串。
func securityEventsEncodeBody(body string) string {
	if body == "" {
		return ""
	}
	if utf8.ValidString(body) {
		if len(body) <= securityEventsBodyCap {
			return body
		}
		cut := securityEventsBodyCap
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		return body[:cut] + "\n...[TRUNCATED]"
	}
	raw := body
	truncated := false
	if len(body) > securityEventsBodyCap {
		raw = body[:securityEventsBodyCap]
		truncated = true
	}
	if truncated {
		return "base64-truncated:" + base64.StdEncoding.EncodeToString([]byte(raw))
	}
	return "base64:" + base64.StdEncoding.EncodeToString([]byte(raw))
}

// securityEventsRuleRef is an lb_rules identity resolved for one event:
// the caddy id plus the rule name snapshotted at ingest time.
type securityEventsRuleRef struct {
	caddyID string
	name    string
}

// securityEventsLoadMappings batch-loads per-tick indexes: host→rule, plus the
// v2.2.0 multi-policy attribution inputs — rule→bound policy ids (policy_id ASC
// so "first bound" is well-defined) and policy id→policy for custom_rules /
// crs_rule_groups membership checks. Domain canonicalization matches handlers'
// normalizedRuleDomains (db.CanonicalDomains).
func securityEventsLoadMappings() (map[string]securityEventsRuleRef, map[string][]int, map[int]*models.SecurityPolicy, error) {
	if db.DB == nil {
		return nil, nil, nil, errors.New("security events: database not initialized")
	}
	rules := make(map[string]securityEventsRuleRef)
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,''), COALESCE(name,''), listen_port FROM lb_rules WHERE protocol='http' AND COALESCE(domain,'') != ''`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var caddyID, domain, name string
		var listenPort int
		if err := rows.Scan(&caddyID, &domain, &name, &listenPort); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan rule: %w", err)
		}
		canonical, err := db.CanonicalDomains(domain)
		if err != nil {
			continue // a domain that cannot be canonicalized can never match
		}
		for _, host := range strings.Split(canonical, ",") {
			// 端口维度(2026-09-15 用户裁定):同域名 http:80+https:443 双规则
			// 时,纯域名键被后创建规则覆盖(创建序),兜底错配。双写纯域名
			// (向后兼容单规则)+host:port(精确),MapHost 按端口优先。
			rules[host] = securityEventsRuleRef{caddyID: caddyID, name: name}
			if listenPort > 0 {
				rules[host+":"+fmt.Sprint(listenPort)] = securityEventsRuleRef{caddyID: caddyID, name: name}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: iterate rules: %w", err)
	}

	// v2.2.0 多策略归因：一个 lb_rule 可绑多个策略，按 policy_id ASC 排序，
	// 重叠时归因到「绑定顺序第一条」= 最小 policy_id。
	bindings := make(map[string][]int)
	bindRows, err := db.DB.Query(`SELECT rule_caddy_id, policy_id FROM security_policy_bindings ORDER BY policy_id ASC`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load policy bindings: %w", err)
	}
	defer bindRows.Close()
	for bindRows.Next() {
		var caddyID string
		var policyID int
		if err := bindRows.Scan(&caddyID, &policyID); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan binding: %w", err)
		}
		bindings[caddyID] = append(bindings[caddyID], policyID)
	}
	if err := bindRows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: iterate bindings: %w", err)
	}

	// 策略的 mode / custom_rules / crs_rule_groups / ip_blacklist / ip_acl_* 用于
	// 「rule_triggered 属于哪个策略」判定（mode 供 A1-S6 off 门：mode=off 策略
	// 不发射 CRS，不得认领 CRS 事件）；仅加载启用策略（disabled 策略不应再
	// 接收事件归因）。
	policyByID := make(map[int]*models.SecurityPolicy)
	polRows, err := db.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(mode,'off'), COALESCE(custom_rules,'[]'), COALESCE(crs_rule_groups,'[]'), COALESCE(ip_blacklist,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_enabled,0), COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0), COALESCE(policy_type,''), COALESCE(trust_detection,0) FROM security_policies WHERE enabled=1`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load policies: %w", err)
	}
	defer polRows.Close()
	var policies []*models.SecurityPolicy
	for polRows.Next() {
		p := &models.SecurityPolicy{}
		var customJSON, crsJSON, blacklistJSON, geoipJSON, whitelistJSON, whitelistRefsJSON string
		if err := polRows.Scan(&p.ID, &p.Name, &p.Mode, &customJSON, &crsJSON, &blacklistJSON, &p.IPACLEnabled, &p.IPACLMode, &p.IPACLList, &p.IPACLListRefs, &p.IPWhitelistEnabled, &whitelistJSON, &whitelistRefsJSON, &geoipJSON, &p.GeoIPMode, &p.WAFCheckResponse, &p.PolicyType, &p.TrustDetection); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan policy: %w", err)
		}
		p.CustomRules = json.RawMessage(customJSON)
		p.GeoIPCountries = json.RawMessage(geoipJSON)
		p.CRSRuleGroups = json.RawMessage(crsJSON)
		p.IPBlacklist = json.RawMessage(blacklistJSON)
		// 信任名单（IP 族 fallback 能力首选层的 logged 语义能力判定）：
		// 既有 SELECT 未携带，能力层不读库补查（摄入 tick 热路径），在此装载。
		p.IPWhitelist = json.RawMessage(whitelistJSON)
		p.IPWhitelistRefs = whitelistRefsJSON
		// 策略类型 / 保留检测（F-47-5，第 47 轮）：IP 族能力首选层的信任分支须镜像
		// 引擎信任门（security.go:166 `PolicyType != stage0`；预检 id:3 排除 stage0，
		// 保留检测由 id:12 承载）——不装载则摄入态恒空值，镜像判定失效（stage0 直通
		// 策略会凭「whitelist 非空」抢认它物理上产不出的 logged IP 族事件）。
		policyByID[p.ID] = p
		policies = append(policies, p)
	}
	// deny 归因需要 refs 合并集（inline ∪ ip_acl_list_refs 解析集）——不解析则
	// refs-only deny 策略无法认领自己的 id:2 事件（MergedACLList 恒空，回退
	// inline 判定失败，事件错挂到绑定顺序首条启用策略）。
	resolvePolicyIPListRefs(policies, nil)
	if err := polRows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: iterate policies: %w", err)
	}
	return rules, bindings, policyByID, nil
}

// securityEventsPolicyContainsRule reports whether the given rule id belongs to
// the policy's active rule set. 自定义规则（10000+，且 <800000）：查 custom_rules
// JSON（兼容 ID 数组与内嵌对象数组两种形状）。注意 ID 空间：custom_rules JSON
// 存的是 security_custom_rules 的 DB 主键 id，而 audit 的 rule_triggered 是
// emit id（DB id + 10000，见 emitCustomRules），因此归属判定在 emit 空间比较
// （DB id + 10000 == n）。CRS 规则（9xxxxx）：crs_rule_groups 条目为两位数字
// 代码（如 "42" 对应 942xxx，与 BuildCorazaDirectives 的 `REQUEST-9<code>-*.conf`
// Include 同款口径）；空数组按发射端语义视为「包含全部 REQUEST-*」，即所有 CRS
// 规则均属于该策略。IP ACL 拒绝带（A3 I-6）：id 4 = 遗留 ip_blacklist 拒绝，
// BuildCorazaDirectives 仅对黑名单非空的策略发射；id 2 = IP ACL 列表外拒绝——
// 发射端对 allow 与 deny 两种模式都发 id 2（security.go「IP 白名单拒绝」/
// 「IP 黑名单拒绝」）；归属端有意只认 deny 模式策略（allow 模式事件经回退归到
// 首个启用策略，仅展示层影响——IPACLAllowModeDoesNotOwnDenyEvent 钉住该口径）。
// 成员精确归因（2026-09-21 生产事故，A-3 ①「名单命中者优先」）：clientIP 非空
// 且可解析时，id 2/4 在名单非空基础上追加成员判定——名单未命中事件源 IP 的
// deny/黑名单策略不认领（多 deny 策略绑定下，首绑非属主凭「名单非空」曾误夺
// 真属主的归属）；名单命中判定内联优先、缺失时回退 IPACLList（mergedACLList
// 同一读法）。事件源 IP 不在任何名单＝名单在发射后被编辑的漂移形状，contains
// 让位、由 fallback 能力首选层归属（绝不归零）。clientIP 为空（历史调用形状/
// 记录缺 IP）保持既有「名单非空即认领」口径。
func securityEventsPolicyContainsRule(policy *models.SecurityPolicy, ruleTriggered, clientIP string) bool {
	if policy == nil || ruleTriggered == "" {
		return false
	}
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	switch {
	case n >= geoipPrecheckRuleBase && n < geoipPrecheckRuleBase+100000:
		// GeoIP 预检精确段（阶段化模型：id=800000+policyID，buildIPPrecheckDirectives
		// 逐策略链）——直接解码属主策略，取代共享 id:8 的「首个 geoip 启用策略」
		// 非精确归因。发射侧只对 PolicyHasGeoIP 策略发射，属主不在绑定集（配置
		// 已在发射后变更）时自然落空走 fallback。
		return policy.ID == n-geoipPrecheckRuleBase
	case n == 8:
		// GeoIP 拦截（遗留共享 id:8，策略引擎时代的历史事件）：所有权与发射门
		// （PolicyHasGeoIP）同口径——mode!='off' 且名单非空。off 态名单仅为
		// 保留数据（不发射 id:8），不得抢走真实发射策略的归因（审计 B1-IA：
		// off+保留名单的首绑定策略曾错夺 id:8 归因）。
		if policy.GeoIPMode == "off" {
			return false
		}
		var geoCountries []string
		if err := json.Unmarshal(policy.GeoIPCountries, &geoCountries); err != nil {
			return false
		}
		return len(geoCountries) > 0
	case n == 4:
		var blacklist []string
		if err := json.Unmarshal(policy.IPBlacklist, &blacklist); err != nil {
			return false
		}
		if len(blacklist) == 0 {
			return false
		}
		return clientIP == "" || securityEventsIPInList(clientIP, blacklist)
	case n == 2:
		if !policy.IPACLEnabled || policy.IPACLMode != "deny" {
			return false
		}
		// 审计 V1-S2（第五轮）：deny 归因应含 refs 合并集（inline ∪ ip_acl_list_refs），
		// 否则 refs-only deny 策略无法认领自己的 id:2 事件。
		aclList := policy.MergedACLList
		if len(aclList) == 0 {
			var inline []string
			if err := json.Unmarshal([]byte(policy.IPACLList), &inline); err != nil {
				return false
			}
			aclList = inline
		}
		if len(aclList) == 0 {
			return false
		}
		return clientIP == "" || securityEventsIPInList(clientIP, aclList)
	case n >= 900000 && n < 1000000:
		// 审计 V1-S1（第五轮）+ W-I1（第六轮回归修复）：v2.2.2 混合选择——
		// crs_rule_groups 可含六位 CRS ID 正选；六位 ID 触发的 CRS 事件应先按
		// 六位正选归因，未命中时回落既有组号归因（空组=全部 CRS）。
		// 第五轮的本分支在组号分支（:371）之前且直接 return false，使后者成为
		// 死代码——用两位组号（常规配置）的策略其 CRS 事件归因失效。
		// A1-S6：mode=off 不发射任何 CRS（engine 分支不成立或零 Include），
		// 不得认领 CRS 事件（与 GeoIP 分支的 off 门同口径）。2026-09-09 四态化:
		// custom_only 同样零 CRS Include,口径收紧为「CRS 生效模式」——否则
		// 同规则多策略绑定时 custom_only 策略会抢走 blocking 策略的 CRS 事件归属。
		if policy.Mode != "blocking" && policy.Mode != "detection" {
			return false
		}
		// A1-I2：949 评估规则自 v2.2.3 起对全部启用 WAF 的策略强制包含（F0
		// 基础设施去重强制 Include），959 对开启响应检查的策略强制包含——均与
		// 存储的 crs_rule_groups 无关（写入面已剥离 49/59 组号，组号匹配恒
		// false），须按各自发射门先行放行。
		if strings.HasPrefix(ruleTriggered, "949") {
			return true
		}
		if strings.HasPrefix(ruleTriggered, "959") {
			return policy.WAFCheckResponse
		}
		var groups []string
		if err := json.Unmarshal(policy.CRSRuleGroups, &groups); err != nil {
			return false
		}
		for _, g := range groups {
			if strings.TrimSpace(g) == fmt.Sprintf("%d", n) {
				return true
			}
		}
		if len(groups) == 0 {
			return true
		}
		code := ruleTriggered[1:3]
		for _, g := range groups {
			if strings.TrimSpace(g) == code {
				return true
			}
		}
		return false
	case n >= 10000 && n < geoipPrecheckRuleBase:
		// S2(2026-09-10 审计):off=全关(四态化)零发射,不得认领自定义规则事件
		//(与 CRS 分支 blocking/detection 门同口径;custom_only/blocking/detection
		// 三态的自定义规则发射由 customActive 保证)。
		if policy.Mode == "off" {
			return false
		}
		var ids []int
		if err := json.Unmarshal(policy.CustomRules, &ids); err == nil {
			for _, id := range ids {
				if id+10000 == n {
					return true
				}
			}
			return false
		}
		var embedded []struct {
			ID int `json:"id"`
		}
		if err := json.Unmarshal(policy.CustomRules, &embedded); err == nil {
			for _, e := range embedded {
				if e.ID+10000 == n {
					return true
				}
			}
		}
		return false
	}
	return false
}

// securityEventsFallbackCanProduce(A34-CORE-F1/F2 第 34 轮 + A35-SECLB-1/2/3
// 第 35 轮误拒修正):fallback 归因的模式/动作可行性门。只核「该策略的当前模式
// 在物理上能否产出此 (动作,规则 id) 事件」,不核名单成员(fallback 的存在理由
// 正是配置可能已在发射后变更)。门禁表逐格对照发射侧单一事实:
//
//	· IP 控制/GeoIP(id:2/4/8)+预检 allow 交集(id:7):与 WAF 模式无关独立
//	  发射(security.go:179-181 明文「runs independently of the WAF mode」,
//	  :220-222 emitIPControl||geoipActive → SecRuleEngine On)——off 模式亦可产
//	  blocked(A35-SECLB-1:初版门「off 零发射」与发射侧设计明文矛盾,误拒);
//	· detection 的 id:6 DetectionOnly 切换(security.go:351)发射于 IP 控制/
//	  自定义规则之后、CRS 之前——phase:1 拦截规则真实阻断(:668 明文保障),
//	  blocked 可产={2,4,7,8}+自定义;CRS 在切换后评估,DetectionOnly 零中断
//	  (A35-SECLB-2:初版门 detection+blocked 全量误拒);
//	· custom_only 零 CRS Include(contains :459 同口径)——CRS 事件全拒;
//	  无 949 评分链,id:11 守卫(phase:2 pass)恒不产 blocked(F1 标靶保持);
//	  自定义规则无 id:6 切换任意相位可拦;预检 id:7 与模式无关(:927-935)
//	  (A35-SECLB-3:初版门允许集漏 7,误拒);
//	· id:11 发射面(2026-09-21 实证,维持现状):emitBodyProcessorRules 在
//	  custom_only/blocking/detection 三模式恒发射(security.go :347/:408,
//	  请求体处理器激活与畸形 body 守卫不依赖自定义规则)——logged 事件三模式
//	  物理可能,门放行格与发射面一致;blocked 任何模式均不可产(phase:2 pass
//	  恒不中断),blocking 的 blocked 11 保持可行格(物理上该形状事件不存在,
//	  恒真格无害);
//	· 自定义族(10000-799999/1000000+)的物理发射面能力维度由上层首选层
//	  securityEventsCustomRulesEventSurface 承担(emitCustomRules 对 Disabled
//	  整条跳过的镜像):无启用自定义规则的策略不得凭候选顺序抢先认领本族事件;
//	  本门对该族维持 off 拒/custom_only/detection/blocking 放行的模式口径;
//	· blocking:全域。
//
// 合成 id(1000000+)按自定义族同等对待(物理同形;豁免①钉的是 contains
// 覆盖区间,fallback 门不扩不缩)。
//
// 本门只核「模式 × 动作」可行性;IP 族(2/4/7/8/800xxx)的物理发射面能力维度
// 由上层首选层 securityEventsIPFamilyEventSurface 承担(2026-09-21 生产事故:
// 无 IP 能力策略凭候选顺序抢先认领 id:2),自定义族(10000-799999/1000000+)的
// 由 securityEventsCustomRulesEventSurface 承担(2026-09-21:无启用自定义规则
// 的策略凭候选顺序抢先认领自定义族事件),能力首选层落空后仍按本门归属
// (摄取必有归属,禁止归零)。
func securityEventsFallbackCanProduce(policy *models.SecurityPolicy, action, ruleTriggered string) bool {
	if policy == nil {
		return false
	}
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	ipControl := securityEventsRuleIsIPFamily(ruleTriggered)
	crs := n >= 900000 && n < 1000000
	customFam := securityEventsRuleIsCustomFamily(ruleTriggered)
	switch policy.Mode {
	case "off":
		// off=CRS/自定义/body 守卫全关,但 IP 控制/GeoIP 独立发射照常阻断。
		return ipControl
	case "detection":
		if action != "blocked" {
			return true
		}
		return ipControl || customFam
	case "custom_only":
		if crs {
			return false
		}
		if action == "blocked" && n == 11 {
			return false
		}
		return true
	default: // blocking 全域
		return true
	}
}

// securityEventsRuleIsIPFamily 报告规则 id 是否属于 IP 控制/GeoIP 族（2/4/7/8 +
// GeoIP 预检 800xxx 段）。单一事实源：fallback 门（securityEventsFallbackCanProduce
// 的 ipControl 维度）与能力首选层（securityEventsIPFamilyEventSurface）共用，
// 禁止各自复写字面量。
func securityEventsRuleIsIPFamily(ruleTriggered string) bool {
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	return n == 2 || n == 4 || n == 7 || n == 8 || IsGeoIPPrecheckID(n)
}

// securityEventsRuleIsCustomFamily 报告规则 id 是否属于自定义规则族（5 位发射
// id 10000-799999 = DB id+10000，及无 id 旧版规则的合成段 1000000+）。单一事实
// 源：fallback 门与能力首选层共用，禁止各自复写字面量。
func securityEventsRuleIsCustomFamily(ruleTriggered string) bool {
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	return (n >= 10000 && n < geoipPrecheckRuleBase) || n >= 1000000
}

// securityEventsCustomRulesEventSurface（2026-09-21，IP 族能力首选层同模式扩展）：
// 自定义族事件 fallback 首选层的物理发射面判定——emitCustomRules 对 Disabled
// 规则整条跳过（security.go「if !cr.Enabled { continue }」，合成段 1000000+ 同
// 一循环同一过滤），无启用自定义规则的策略物理上不产任何自定义族事件
// （blocked/logged 同判）。策略粒度能力，与 IP 族 surface 同口径：规则 id 归属
// 与名单成员一样归 contains（custom_rules 引用集比对），此处只核「是否存在启用
// 规则」——停用/悬空引用均不计能力。读取经 policyCustomRulesCached（store=nil
// 回退 db.DB，与 contains 读 CustomRules 原文同库同口径；摄取 tick 单线程、
// 策略对象每 tick 重载，惰性解析单 tick 内按策略记忆化，零事件 tick 零查询）。
// 返回 false 不代表事件归零：attribute 层能力首选层落空后仍经「模式/动作门」
// 归属（摄取必有归属）。
func securityEventsCustomRulesEventSurface(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	for _, cr := range policyCustomRulesCached(p, nil) {
		if cr.Enabled {
			return true
		}
	}
	return false
}

// securityEventsIPFamilyEventSurface（2026-09-21 生产事故，A-3 ②能力维度）：
// IP 族事件 fallback 首选层的物理发射面判定，逐 id 对照发射侧单一事实——
//
//	· id 8/800xxx（GeoIP）：PolicyHasGeoIP（mode!=off 且名单非空），与发射门
//	  （buildIPPrecheckDirectives :964/:1043、contains id:8 分支）同源；
//	· id 2（ACL 拒绝带）：deny 模式且合并名单非空（BuildCorazaDirectives :287
//	  「IPACLEnabled && len(ipACLList)>0」+ :306 deny 分支；allow 模式发射的
//	  id:2 归属口径有意不认（A3 I-6，IPACLAllowModeDoesNotOwnDenyEvent 钉）；
//	· id 4（遗留黑名单）：黑名单非空（:322 无模式门）；
//	· id 7（预检 allow 交集）：allow 模式且合并名单非空（buildIPPrecheckDirectives
//	  仅 allow 参与交集）；
//	· 信任名单（ip_whitelist）：仅 logged（检测）语义计入 id 2/4/7 能力——信任
//	  只以 DetectionOnly 降级事务、令 deny 规则以检测动作留痕，自身发射的
//	  id:3/5/12 为 nolog pass 永不产事件，更不可能产 blocked。**镜像引擎/预检
//	  信任门（2026-09-21 第 47 轮 F-47-5）**：stage0 + trust_detection=0（直通）
//	  的信任 IP 走路由层 subroute 短路（零 coraza 事务）、非信任 IP 全链评估且
//	  无 DetectionOnly 降级 ⇒ 该策略物理上不产任何 logged IP 族事件，故要求
//	  `PolicyType != stage0 || TrustDetection`（对齐 security.go:166 引擎门与
//	  security.go:990-1005 预检 id:3 排除 / id:12 承载保留检测）；无 policy_type
//	  的存量信任策略（mixed 语义，走 id:3 并集）不受影响。
//
// 名单读取与 SecurityPolicyHasIPControl 同源（inline ∪ refs；MergedACLList 为
// 摄入映射解析集，缺失回退 inline）。返回 false 不代表事件归零：attribute
// 层的能力首选层落空后仍经「模式/动作门」归属（摄取必有归属）。
func securityEventsIPFamilyEventSurface(p *models.SecurityPolicy, action, ruleTriggered string) bool {
	if p == nil {
		return false
	}
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	if n == 8 || IsGeoIPPrecheckID(n) {
		return PolicyHasGeoIP(p)
	}
	aclEntries := mergedACLList(p)
	aclCapable := p.IPACLEnabled && (len(aclEntries) > 0 || ipListRefsNonEmpty(p.IPACLListRefs))
	switch n {
	case 2:
		if p.IPACLMode == "deny" && aclCapable {
			return true
		}
	case 4:
		var blacklist []string
		if err := json.Unmarshal(p.IPBlacklist, &blacklist); err == nil && len(blacklist) > 0 {
			return true
		}
	case 7:
		if p.IPACLMode == "allow" && aclCapable {
			return true
		}
	}
	if action != "blocked" && p.IPWhitelistEnabled && (p.PolicyType != models.PolicyTypeStage0 || p.TrustDetection) {
		var wl []string
		if err := json.Unmarshal(p.IPWhitelist, &wl); err == nil &&
			(len(wl) > 0 || ipListRefsNonEmpty(p.IPWhitelistRefs)) {
			return true
		}
	}
	return false
}

// securityEventsIPInList 报告事件源 IP 是否命中名单条目（精确或 CIDR 包含）。
// 条目解析失败按不命中跳过（与渲染端 @ipMatch 的宽松容忍一致——坏条目在
// 生成期告警，不在此重复报）。IPv4-mapped IPv6 归一后比较。
func securityEventsIPInList(ip string, list []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, entry := range list {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == ip {
			return true
		}
		if prefix, perr := netip.ParsePrefix(entry); perr == nil {
			if prefix.Contains(addr) {
				return true
			}
			continue
		}
		if entryAddr, aerr := netip.ParseAddr(entry); aerr == nil && entryAddr.Unmap() == addr {
			return true
		}
	}
	return false
}

// securityEventsAttributePolicy v2.2.0 多策略事件归因：rule_triggered → 查该规则
// ID 属于哪个策略（custom_rules / CRS 组 / IP ACL 拒绝带匹配，IP 族带事件源 IP
// 成员精确判定），重叠时取绑定顺序第一条（policy_id ASC 的第一个）。策略均未
// 显式包含时走 fallback，两层判定：
//
//  1. 能力首选层（2026-09-21 生产事故）：模式/动作门（A34-CORE-F1/F2，
//     securityEventsFallbackCanProduce）+ IP 族物理发射面
//     （securityEventsIPFamilyEventSurface）——无任何 IP 控制能力的策略不得凭
//     候选顺序抢先认领 id:2/4/7/8/800xxx 事件；+ 自定义族物理发射面
//     （securityEventsCustomRulesEventSurface，同日扩展）——无启用自定义规则
//     的策略不得凭候选顺序抢先认领自定义族事件（10000-799999/1000000+）；
//  2. 摄取必有归属层：仅模式/动作门（IP 族与自定义族能力维度豁免）——绑定集
//     内不存在有能力策略（绑定/规则启停在发射后变更等漂移形状）时事件仍归到
//     首个可行绑定，禁止归零。
//
// policyByID 仅含启用策略：禁用/悬空的首绑定被跳过，事件仍归到该
// lb_rule 的可用主策略。无任何启用且可行绑定策略、或 lb_rule 完全未绑定（无
// security_policy_bindings 行）返回零值 (0, "")。ACL 拒绝带（id 4/2）无属主时
// 同样走该回退而非归零：事件既已被摄取，必是某绑定策略在发射时的配置发出了它
// （当前配置可能已变更），归到首启用绑定是最接近发射现实的归属。
func securityEventsAttributePolicy(ruleCaddyID, ruleTriggered, action, clientIP string, policyByID map[int]*models.SecurityPolicy, bindings map[string][]int) (int, string) {
	policyIDs := bindings[ruleCaddyID]
	if len(policyIDs) == 0 {
		return 0, ""
	}
	for _, pid := range policyIDs {
		p := policyByID[pid]
		if p == nil {
			continue
		}
		if securityEventsPolicyContainsRule(p, ruleTriggered, clientIP) {
			return pid, p.Name
		}
	}
	ipFamily := securityEventsRuleIsIPFamily(ruleTriggered)
	customFam := securityEventsRuleIsCustomFamily(ruleTriggered)
	for _, pid := range policyIDs {
		p := policyByID[pid]
		if p == nil {
			continue
		}
		if !securityEventsFallbackCanProduce(p, action, ruleTriggered) {
			continue
		}
		if ipFamily && !securityEventsIPFamilyEventSurface(p, action, ruleTriggered) {
			continue
		}
		if customFam && !securityEventsCustomRulesEventSurface(p) {
			continue
		}
		return pid, p.Name
	}
	for _, pid := range policyIDs {
		p := policyByID[pid]
		if p == nil {
			continue
		}
		if securityEventsFallbackCanProduce(p, action, ruleTriggered) {
			return pid, p.Name
		}
	}
	return 0, ""
}

// securityEventsMapHost resolves a request host to its lb_rule; zero-value ref
// when nothing matches. Policy attribution is handled separately by
// securityEventsAttributePolicy, which needs the triggered rule id from the
// parsed record.
func securityEventsMapHost(host string, rules map[string]securityEventsRuleRef) securityEventsRuleRef {
	// 端口优先(2026-09-15):host:port 原文先试精确键(防御性——coraza-caddy
	// parseServerName 剥离端口,rec.Host 生产恒无端口,该分支不可达但零成本;
	// 真正修复是 loader 双写保住 rulesByID 两 ref,注入头路径覆盖全部现行事件)。
	// 无命中走 canonical 纯域名(单规则兼容)。
	if rule, ok := rules[host]; ok {
		return rule
	}
	canonical, err := db.CanonicalDomains(host)
	if err != nil {
		return securityEventsRuleRef{} // IPs and invalid domains never match a domain rule
	}
	for _, candidate := range strings.Split(canonical, ",") {
		if rule, ok := rules[candidate]; ok {
			return rule
		}
	}
	return securityEventsRuleRef{}
}

// securityEventsReadOffset loads the persisted byte offset; a missing or
// corrupt file means "start from the beginning" rather than an error.
func securityEventsReadOffset(path string) (int64, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	offset, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || offset < 0 {
		return 0, nil
	}
	return offset, nil
}

// securityEventsWriteOffset persists the byte offset atomically (plain integer).
func securityEventsWriteOffset(path string, offset int64) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(offset, 10)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// securityEventsShouldReset reports whether the tailer must restart at offset
// 0: the file shrank below the persisted offset (truncation) or was replaced
// (rotation: inode change detected via os.SameFile on the stat results).
func securityEventsShouldReset(offset, size int64, prev, curr os.FileInfo) bool {
	if size < offset {
		return true
	}
	return prev != nil && curr != nil && !os.SameFile(prev, curr)
}

// securityEventsScanWindowLimit 是一次解码失败后前向扫描文档头的最大字节数：
// 扫描窗口内没有下一个 "\n{" 且窗口外仍有数据，即判定为无法自愈的畸形区。
const securityEventsScanWindowLimit = 4 << 20

// securityEventsDecodeStallLimit 是解码失败后原地等待重试的最大连续 tick 数：
// 并发事务的审计追加对 2s tick 呈现「暂时性中段残缺」（写入进行中的字节，随后
// 补全），连续本数值个 tick 仍在同一偏移失败，才按崩溃残片走跳过路径。
const securityEventsDecodeStallLimit = 5

// securityEventsFindNextDocument scans forward from `from` for the next `{`
// at column 0, which in the pretty-printed multi-line format marks the start
// of the next top-level transaction. found=false when none exists yet.
// N+11 D3-F2: the scan buffer is sized min(scanLimit, size-from) via f.Stat
// — a small residual tail (post hard-kill) previously allocated the full 4MB
// window on every 2s tick decode error (~2MB/s sustained churn). The caller's
// malformed-region decision uses the scanLimit constant, not the buffer size,
// so decisions are unchanged.
func securityEventsFindNextDocument(f *os.File, from int64) (int64, bool, error) {
	const scanLimit = securityEventsScanWindowLimit
	info, err := f.Stat()
	if err != nil {
		return 0, false, err
	}
	remaining := info.Size() - from
	if remaining <= 0 {
		return 0, false, nil
	}
	if remaining > scanLimit {
		remaining = scanLimit
	}
	buf := make([]byte, remaining)
	n, err := f.ReadAt(buf, from)
	if n > 0 {
		if idx := bytes.Index(buf[:n], []byte("\n{")); idx >= 0 {
			return from + int64(idx) + 1, true, nil
		}
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return 0, false, err
	}
	return 0, false, nil
}

// securityEventsGapAllWhitespace reports whether the byte range [from, to) of
// f consists solely of JSON whitespace — the harmless document-boundary advance
// （上一完整文档的行尾换行等）。SECLB35-1：跳过窗口含非空白字节时才可能丢
// 数据（进入停等/跳过路径）；纯空白窗口直接推进，与旧语义等价。窗口大于
// 4KB 按非空白保守处理（真实残缺数据不可能被 4KB 纯空白分隔）。
func securityEventsGapAllWhitespace(f *os.File, from, to int64) bool {
	gap := to - from
	if gap <= 0 || gap > 4096 {
		return false
	}
	buf := make([]byte, gap)
	if _, err := f.ReadAt(buf, from); err != nil {
		return false
	}
	for _, b := range buf {
		switch b {
		case ' ', '\t', '\n', '\r':
		default:
			return false
		}
	}
	return true
}

// securityEventsScanNextDocumentBounded 有界前向扫描 [from, limit) 内下一个
// "\n{" 文档头（返回 `{` 的字节位置）：供归档 pass（文件大小有界、不再增长）
// 在 4MB 扫描窗口之外继续找文档头，跳过畸形区恢复摄取其后的事件。
func securityEventsScanNextDocumentBounded(f *os.File, from, limit int64) (int64, bool, error) {
	const chunkSize = 1 << 20
	if from >= limit {
		return 0, false, nil
	}
	pos := from
	var prev byte
	first := true
	for pos < limit {
		chunk := int64(chunkSize)
		if limit-pos < chunk {
			chunk = limit - pos
		}
		buf := make([]byte, chunk)
		n, err := f.ReadAt(buf, pos)
		if n > 0 {
			if !first && prev == '\n' && buf[0] == '{' {
				return pos, true, nil // "\n{" 跨块边界，返回 `{` 的位置
			}
			if idx := bytes.Index(buf[:n], []byte("\n{")); idx >= 0 {
				return pos + int64(idx) + 1, true, nil
			}
			prev = buf[n-1]
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return 0, false, err
		}
		if int64(n) < chunk {
			break
		}
		pos += int64(n)
		first = false
	}
	return 0, false, nil
}

// securityEventsTailer streams new audit transactions from the log file,
// persisting its byte offset between passes so restarts resume in place.
type securityEventsTailer struct {
	logPath    string
	offsetPath string
	lastInfo   os.FileInfo
	// lastPassClean 标记上一次 pass 是否无错误结束（N+11 D3-F5a 空闲 tick 判定
	// 用）：失败 pass（F1 停摆、DB 错误）的下一 tick 必须重跑——停摆限流告警与
	// DB 重试都依赖 2s 周期持续转动，不得被空闲跳过吞掉。
	lastPassClean bool
	// stallOffset/stallCount 是 SECLB35-1 停等状态：最近一次「残缺文档等待
	// 补写」的偏移与连续失败次数。键为残缺文档起始偏移（每次 pass 从该处
	// 重启，稳定）；偏移推进即数据已补全/已跳过，下次失败自然重置。
	stallOffset int64
	stallCount  int
	// failOffset 是本 pass 中 F1 停摆（畸形区）的偏移，仅 F1 错误路径设置；
	// -1 表示本次 tick 未触发 F1。
	failOffset  int64
	archivePass bool
	// S1: F1 停摆告警限流——上次 warn 的畸形区偏移与时间，偏移不变时每分钟
	// 最多一条 warn，偏移前进即重置立即告警。
	lastWarnOffset int64
	lastWarnTime   time.Time
}

func securityEventsNewTailer(logPath, offsetPath string) *securityEventsTailer {
	return &securityEventsTailer{logPath: logPath, offsetPath: offsetPath, failOffset: -1}
}

// securityEventsTick runs one ingest pass over the audit log.
func (t *securityEventsTailer) securityEventsTick() error {
	info, err := os.Stat(t.logPath)
	if errors.Is(err, os.ErrNotExist) {
		created, cerr := os.OpenFile(t.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if cerr != nil {
			return fmt.Errorf("security events: create audit log: %w", cerr)
		}
		_ = created.Close()
		t.lastInfo = nil
		// SYSRENDER24-1(第 24 轮审计):文件缺失=路径迁移/首启动——残留 offset
		// 来自旧路径,必须归零;否则新文件快速增长超过旧 offset 后,前缀事件
		// 被永久跳过(inode 分支 lastInfo=nil 首启动永不生效)。
		if stale, rerr := securityEventsReadOffset(t.offsetPath); rerr == nil && stale > 0 {
			Logf("info", "security events ingestion: audit log missing (path migration or first start), resetting stale offset %d to 0", stale)
			if werr := securityEventsWriteOffset(t.offsetPath, 0); werr != nil {
				return fmt.Errorf("security events: reset stale offset: %w", werr)
			}
		}
		return nil // wait for Coraza to write the first transaction
	}
	if err != nil {
		return fmt.Errorf("security events: stat audit log: %w", err)
	}
	offset, err := securityEventsReadOffset(t.offsetPath)
	if err != nil {
		return fmt.Errorf("security events: read offset: %w", err)
	}
	if securityEventsShouldReset(offset, info.Size(), t.lastInfo, info) {
		Logf("info", "security events ingestion: audit log rotated or truncated, resetting offset to 0")
		offset = 0
		if err := securityEventsWriteOffset(t.offsetPath, 0); err != nil {
			return fmt.Errorf("security events: persist reset offset: %w", err)
		}
	} else if t.lastPassClean && t.lastInfo != nil && info.Size() == t.lastInfo.Size() {
		// N+11 D3-F5a：空闲 tick 提前返回——与上一 tick 相比无新增字节且上次
		// pass 干净结束。按上一 tick 的 size 而非 offset 判定：Coraza pretty
		// 格式文件尾恒有 "\n"，稳态 offset = size-1，与 offset 比较永不成立。
		// 跳过省去每 2s 一次的映射加载（3 条主库查询 + 逐行 IDNA）与文件
		// open/seek/残空白解码。lastInfo 照常更新，下一 tick 的截断/轮转判定
		// （size<offset / os.SameFile）不受影响；失败 pass（lastPassClean=false）
		// 不满足条件，重试与限流告警照常。
		t.lastInfo = info
		return nil
	}
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		return err
	}
	f, err := os.Open(t.logPath)
	if err != nil {
		return fmt.Errorf("security events: open audit log: %w", err)
	}
	defer f.Close()
	newOffset, passErr := t.securityEventsProcessPass(f, offset, rules, bindings, policyByID)
	if newOffset != offset {
		if werr := securityEventsWriteOffset(t.offsetPath, newOffset); werr != nil {
			passErr = errors.Join(passErr, fmt.Errorf("security events: persist offset: %w", werr))
		}
	}
	t.lastPassClean = passErr == nil
	t.lastInfo = info
	return passErr
}

// securityEventsProcessPass decodes and inserts every complete transaction
// from offset to EOF, returning the furthest offset safe to persist. A
// database error stops the pass so the next tick retries the same offset; a
// malformed transaction is logged and skipped without aborting the pass.
func (t *securityEventsTailer) securityEventsProcessPass(f *os.File, offset int64, rules map[string]securityEventsRuleRef, bindings map[string][]int, policyByID map[int]*models.SecurityPolicy) (int64, error) {
	// 每个 pass 开始时重置停摆偏移：只有本 pass 实际 F1 停摆才会重新赋值，
	// 避免同偏移的新停摆被上一轮 warn 的限流状态吞掉（R33 F2）。
	t.failOffset = -1
	// F3：每 pass 一次从 host→ref 派生 caddy_id→ref 索引，供 X-LB-Rule-ID
	// 注入头优先归因（O(规则数) 一次性，避免逐事件反查）。
	rulesByID := make(map[string]securityEventsRuleRef, len(rules))
	for _, ref := range rules {
		rulesByID[ref.caddyID] = ref
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, fmt.Errorf("security events: seek audit log: %w", err)
	}
	committedOffset := offset
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return offset, fmt.Errorf("security events: begin insert transaction: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO security_events
		(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id, request_headers, request_body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return committedOffset, fmt.Errorf("security events: prepare insert: %w", err)
	}
	decoderStart := offset
	decoder := json.NewDecoder(f)
	const batchSize = 500
	count := 0
	for {
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			stmt.Close()
			if cerr := tx.Commit(); cerr != nil {
				return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
			}
			return offset, nil
		}
		if err != nil {
			next, found, rerr := securityEventsFindNextDocument(f, decoderStart+decoder.InputOffset())
			if rerr != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return committedOffset, rerr
			}
			if !found {
				// 未找到下一个文档头有两种可能：文件尾部的半条事务（正常，等待
				// Coraza 写完，下次 tick 续读）与 ≥4MB 无 "\n{" 的畸形区（崩溃时
				// 正在写入的超大残片等）。后者若原地成功返回，tick 会每 2s 从同一
				// 位置解码失败、原地打转且无任何告警，后续所有事件永不被摄取。
				// 仅当扫描窗口之外仍有数据时才判定为畸形区并返回错误，让 tick 走
				// warn 暴露停摆；已解析文档先提交，偏移照常推进。
				// 归档 pass（.1 补采 / pending 重试）的文件大小有界且不再增长，
				// F1 错误会让 pending 标记永不清除、轮转永久停摆，故改为有界
				// scan-to-EOF 找下一个 "\n{"：找到则跳过畸形区（一条 error 日志）
				// 继续摄取其后事件；找不到则记一次 error 日志并结束本 pass（该
				// 区域不可恢复，但不再阻塞轮转）。
				if info, serr := f.Stat(); serr == nil && decoderStart+decoder.InputOffset()+securityEventsScanWindowLimit < info.Size() {
					if !t.archivePass {
						_ = stmt.Close()
						if cerr := tx.Commit(); cerr != nil {
							return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
						}
						t.failOffset = decoderStart + decoder.InputOffset()
						return offset, fmt.Errorf("security events: unreadable audit data beyond %d scan window at offset %d", securityEventsScanWindowLimit, decoderStart+decoder.InputOffset())
					}
					next, found, rerr := securityEventsScanNextDocumentBounded(f, decoderStart+decoder.InputOffset(), info.Size())
					if rerr != nil {
						_ = stmt.Close()
						_ = tx.Rollback()
						return committedOffset, fmt.Errorf("security events: archive resync scan: %w", rerr)
					}
					if !found {
						_ = stmt.Close()
						if cerr := tx.Commit(); cerr != nil {
							return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
						}
						Logf("error", "security events ingestion: unrecoverable unreadable audit data at offset %d in archive, ending pass", decoderStart+decoder.InputOffset())
						return offset, nil
					}
					Logf("error", "security events ingestion: skipping unreadable audit data before offset %d: %v", next, err)
					offset = next
					decoderStart = next
					if _, err := f.Seek(offset, io.SeekStart); err != nil {
						_ = stmt.Close()
						_ = tx.Rollback()
						return committedOffset, fmt.Errorf("security events: seek after resync: %w", err)
					}
					decoder = json.NewDecoder(f)
					continue
				}
				stmt.Close()
				if cerr := tx.Commit(); cerr != nil {
					return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
				}
				return offset, nil
			}
			// 文档边界推进（跳过窗口 [offset, next) 仅含空白，典型=上一完整文档
			// 的行尾换行）：与旧语义等价的无害推进——推进到残缺文档本体起点，
			// 不计入停等、不返回停等错误（文件尾半条事务的「!found 等待」路径
			// 保持 nil 返回的旧契约）。
			if securityEventsGapAllWhitespace(f, offset, next) {
				offset = next
				decoderStart = next
				if _, err := f.Seek(offset, io.SeekStart); err != nil {
					_ = stmt.Close()
					_ = tx.Rollback()
					return committedOffset, fmt.Errorf("security events: seek after resync: %w", err)
				}
				decoder = json.NewDecoder(f)
				continue
			}
			// SECLB35-1（2026-09-18 实证）：解码失败最常见的形态不是崩溃残片，
			// 而是并发事务审计追加的「写入进行中」字节——对 2s tick 短暂可见、
			// 随后补全（生产实测审计文件最终全部行合法，但立即跳过仍把窗口内
			// 8 条事件永久丢弃）。原地等待：提交已解析文档、偏移停在残缺文档
			// 起点，下个 tick 重读；连续 securityEventsDecodeStallLimit 个 tick
			// 仍在同一偏移失败才按崩溃残片走下方跳过路径。归档补采（有界、
			// 不再增长的文件）不适用等待，保持立即跳过。
			if !t.archivePass {
				if t.stallOffset != offset {
					t.stallOffset, t.stallCount = offset, 1
				} else {
					t.stallCount++
				}
				if t.stallCount <= securityEventsDecodeStallLimit {
					stmt.Close()
					if cerr := tx.Commit(); cerr != nil {
						return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
					}
					return offset, errSecurityEventsStalled
				}
				// 跳过执行后把 epoch 饱和在新位置：同一 pass 内紧随的连续残缺点
				//（跳过后紧接的同段残缺）立即跳过，不重新等待——否则多段残缺要
				// 逐段各付一个完整等待周期。新位置的独立残缺文档在下一次 pass
				// 以偏移变化自然重置计数，恢复完整宽限。
				t.stallOffset, t.stallCount = next, securityEventsDecodeStallLimit+1
			}
			Logf("error", "security events ingestion: skipping unreadable audit data before offset %d (stalled %d ticks): %v", next, t.stallCount, err)
			offset = next
			decoderStart = next
			if _, err := f.Seek(offset, io.SeekStart); err != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return committedOffset, fmt.Errorf("security events: seek after resync: %w", err)
			}
			decoder = json.NewDecoder(f)
			continue
		}
		docEnd := decoderStart + decoder.InputOffset()
		rec, perr := securityEventsParseTransaction(raw)
		if perr != nil {
			// 空 transaction_id 是数据质量问题而非摄取故障，debug 级记录即可；
			// 其余畸形事务仍按 error 级提示。
			level := "error"
			if errors.Is(perr, errSecurityEventsEmptyID) {
				level = "debug"
			}
			Logf(level, "security events ingestion: skipping malformed transaction id=%s: %v", securityEventsTransactionID(raw), perr)
		} else {
			rule := securityEventsRuleRef{}
			if rec.AttributionRuleID != "" {
				rule = rulesByID[rec.AttributionRuleID]
			}
			if rule.caddyID == "" {
				rule = securityEventsMapHost(rec.Host, rules)
			}
			policyID, policyName := securityEventsAttributePolicy(rule.caddyID, rec.RuleTriggered, rec.Action, rec.ClientIP, policyByID, bindings)
			if _, ierr := stmt.Exec(rec.EventTime, rule.caddyID, policyID, rec.ClientIP, rec.Method, rec.URI,
				rec.EventType, rec.RuleTriggered, rec.RuleMsg, rec.Action, rec.AnomalyScore,
				rule.name, policyName, rec.TransactionID, rec.RequestHeaders, rec.RequestBody); ierr != nil {
				_ = stmt.Close()
				_ = tx.Rollback()
				return committedOffset, fmt.Errorf("security events: insert event: %w", ierr)
			}
			count++
			if count >= batchSize {
				stmt.Close()
				if cerr := tx.Commit(); cerr != nil {
					return committedOffset, fmt.Errorf("security events: commit batch: %w", cerr)
				}
				committedOffset = docEnd
				tx, err = db.MetricsDB.Begin()
				if err != nil {
					return committedOffset, fmt.Errorf("security events: begin batch transaction: %w", err)
				}
				stmt, err = tx.Prepare(`INSERT OR IGNORE INTO security_events
				(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id, request_headers, request_body)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
				if err != nil {
					tx.Rollback()
					return committedOffset, fmt.Errorf("security events: prepare batch insert: %w", err)
				}
				count = 0
			}
		}
		offset = docEnd
	}
}

// securityEventsTransactionID extracts the id for skip logging on a best-effort
// basis; it returns "" when the envelope itself is unreadable.
func securityEventsTransactionID(raw json.RawMessage) string {
	var probe struct {
		Transaction struct {
			ID string `json:"id"`
		} `json:"transaction"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return ""
	}
	return probe.Transaction.ID
}

// securityEventsIngestRotatedDelta 补采轮转窗口内未摄取的安全事件：tick 读到 EOF
// 后、copytruncate 完成前 Coraza 写入的尾部事件只存在于 audit.log.1，活文件截断
// 后 tailer 重置偏移不会再读 .1，若不补采这些事件会永久丢失。复用
// securityEventsProcessPass 的解析与 INSERT OR IGNORE 插入，transaction_id 唯一
// 索引保证与 tick 已摄取内容幂等。
func securityEventsIngestRotatedDelta(persistedOffset int64) error {
	if db.DB == nil || db.MetricsDB == nil {
		return nil
	}
	archive := auditLogPath + ".1"
	info, err := os.Stat(archive)
	if err != nil {
		return fmt.Errorf("security events: stat rotated archive: %w", err)
	}
	if info.Size() <= persistedOffset {
		return nil // 归档未包含超出已摄取偏移的内容
	}
	return securityEventsIngestDeltaFrom(archive, persistedOffset, true)
}

// securityEventsIngestDeltaFrom 从 path 的 from 偏移补采到 EOF 的安全事件：
// 解析与 INSERT OR IGNORE 插入复用 securityEventsProcessPass，transaction_id
// 唯一索引保证幂等。轮转后的 .1 归档（securityEventsIngestRotatedDelta）与
// copy 完成后 truncate 前的活文件尾部（rotateAuditLogIfNeeded）共用此路径。
// archive=true 表示归档补采（.1 / pending 重试）：文件大小有界且不再增长，
// 畸形区走 scan-to-EOF 恢复而非 F1 报错（见 securityEventsProcessPass）。
func securityEventsIngestDeltaFrom(path string, from int64, archive bool) error {
	if db.DB == nil || db.MetricsDB == nil {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("security events: open delta source: %w", err)
	}
	defer f.Close()
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		return err
	}
	t := securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
	t.archivePass = archive
	_, passErr := t.securityEventsProcessPass(f, from, rules, bindings, policyByID)
	return passErr
}

// securityEventsRateLimitedWarn 输出 tick 失败告警并对 F1 停摆错误（畸形区）
// 限流：同一畸形区偏移每分钟最多一条 warn（tailer 记录 lastWarnOffset +
// lastWarnTime），偏移前进即重置立即告警；其他错误照常输出。
func (t *securityEventsTailer) securityEventsRateLimitedWarn(err error) {
	if t.failOffset < 0 || !strings.Contains(err.Error(), "scan window at offset") {
		// S-2：非 F1 错误同样按同消息 60s 限流（与 S-1 同窗口）——审计目录缺失等
		// 持久性失败不再每 2s tick 刷一条 warn，首条 warn 已暴露问题。
		if !auditFailureShouldLog(err.Error()) {
			return
		}
		Logf("warn", "security events ingestion: tick failed: %v", err)
		return
	}
	now := time.Now()
	if t.failOffset != t.lastWarnOffset || now.Sub(t.lastWarnTime) >= time.Minute {
		Logf("warn", "security events ingestion: tick failed: %v", err)
		t.lastWarnOffset = t.failOffset
		t.lastWarnTime = now
	}
}

// StartSecurityEventsIngestion tails the Coraza WAF audit log and ingests new
// transactions into security_events until ctx is cancelled. Blocking; call
// from a goroutine.
// ensureAuditLogDir 创建审计日志所在目录（os.MkdirAll，幂等）。S-2：启动时调用
// 一次——此前目录缺失时 tick 每 2s 建 audit.log 失败、永久刷屏且从不建目录。
func ensureAuditLogDir() error {
	return os.MkdirAll(filepath.Dir(auditLogPath), 0o755)
}

// EnsureWafAuditDir 是 ensureAuditLogDir 的导出版——SECLB23-P1-1（第 23 轮审计）：
// coraza v3.7.0 NewWAF→serialWriter.Init OpenFile 不建父目录，审计日志目录缺失
// =Provision 致命=/load 拒收。main.go 必须在首次 ApplyConfigOnStartup 前调用。
func EnsureWafAuditDir() error {
	return ensureAuditLogDir()
}

func StartSecurityEventsIngestion(ctx context.Context) (waitExited func()) {
	// 审计 B5-F3：返回 waitExited（循环退出时关闭的独立 done 通道）——优雅关停
	// 在 db.Close 前先 cancel 再完整 join，避免在途 tick 与已关闭 DB 竞态刷噪。
	// 每次调用独立通道，多启（测试）安全。
	ingestionDone := make(chan struct{})
	go func() {
		defer close(ingestionDone)
		runSecurityEventsIngestionLoop(ctx)
	}()
	return func() { <-ingestionDone }
}

func runSecurityEventsIngestionLoop(ctx context.Context) {
	tailer := securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
	if err := ensureAuditLogDir(); err != nil {
		// 仅创建失败时告警一次（后续 tick 的同消息失败已由 S-1 限流窗口覆盖）。
		Logf("warn", "security events ingestion: create audit log dir %s failed: %v", filepath.Dir(auditLogPath), err)
	}
	Logf("info", "security events ingestion started: audit_log=%s offset_file=%s", auditLogPath, securityEventsOffsetPath)
	ticker := time.NewTicker(securityEventsPollInterval)
	defer ticker.Stop()
	for {
		// 先采集后轮转：copytruncate 前把未摄取内容全部吃进，杜绝轮转窗口丢事件。
		if err := tailer.securityEventsTick(); err != nil {
			tailer.securityEventsRateLimitedWarn(err)
		}
		rotateAuditLogIfNeeded()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
