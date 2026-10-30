package services

// allow: SIZE_OK — single cohesive WAF audit-log ingestion module; the
// deliverable is mandated as this one file and splitting is not authorized.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/wafiplist"
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
	// AttributionRuleID 是链首注入的 X-LB-Rule-ID 请求头值：规则归因的
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
	DurationUs        int64
	// PrecheckUs 是该请求预检段耗时快照(µs)——WAF 事件的触发详情弹框显示
	// 「预检+WAF」完整分解;预检事件与 DurationUs 同值。
	PrecheckUs     int64
	RequestHeaders string
	RequestBody    string
	// customRuleScoreFallback 标记「raw 不含评分字面量」的自定义规则命中形：
	//   - 多条件链式规则的起始条（raw 以 ,chain 结尾；setvar 在链尾）；
	//   - OR 计分规则的独立分支（raw 只置命中标记，评分在父规则级评分点）。
	// 两者 AnomalyScore 都需要按发射 id 回查父规则 cr.Score 补齐——否则事件
	// 评分列/大屏危险等级显示 0（非评分事件）。
	customRuleScoreFallback bool
	// messagesDropped 是写侧单行 messages 上限截断掉的命中条数（审计行顶层
	// messages_dropped）。不落库，仅用于摄取期累计披露。
	messagesDropped int
	// requestKey 是请求级去重键：链首注入的 X-Lb-Security-Timing-Id 头值
	// （同一请求的全部引擎事务共享）。为空（旧版本审计行/注入失败）表示该行
	// 没有请求级自然键，按原样逐条入库、不参与归并。不落库，仅用于摄取期去重。
	requestKey string
}

// rowBytes 是单行大文本字段的保留字节合计——批次字节门（batchByteCap）与
// 单轮字节上限（securityEventsPassMaxBytes）的唯一口径。头/体/URI/rule_msg
// 全部计入：新增长文本字段只需在此登记，避免逐处手工相加漏算（旧实现只统计
// headers+body，长 URI/msg 洪峰不触发提前提交）。字段已在上游按各自上限
// 裁剪，此处取裁剪后的落库形态。
func (rec *securityEventRecord) rowBytes() int {
	return len(rec.RequestHeaders) + len(rec.RequestBody) + len(rec.URI) + len(rec.RuleMsg)
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
// securityEventsExtractAnomalyScore）。lb_timing 是本系统审计写插件
// （caddygeoip auditwriter.go）注入的顶层扩展字段：安全链分段耗时（µs），
// 指针区分「缺席」与 0（0µs 是合法计时值）。
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
			// BodyTruncated 是写侧（caddygeoip auditwriter）在 64KiB 硬截断
			// 时置位的标记：文本体另带 \n...[TRUNCATED] 后缀，二进制体只有
			// 本标记——不消费它，截断后的半截内容会被展示成完整内容。
			BodyTruncated bool `json:"body_truncated"`
		} `json:"request"`
		IsInterrupted bool `json:"is_interrupted"`
	} `json:"transaction"`
	Messages []securityEventsAuditMessage `json:"messages"`
	// MessagesDropped 是写侧单行 messages 上限（条数/估算字节双门）触发的截断量
	// （caddygeoip auditwriter 顶层字段，omitempty——未截断时不出现）：本行在库，
	// 但被省略的规则命中永不可回填，摄取侧累计后作为一等披露位上抛。
	MessagesDropped int `json:"messages_dropped"`
	LbTiming        struct {
		Pre *int64 `json:"pre_us"`
		End *int64 `json:"end_us"`
	} `json:"lb_timing"`
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

// securityEventsRawIsChainStarter 报告审计 raw 是否为链式规则的起始条：
// 起始条动作串以 ,chain 结尾（链子条只带 phase，不进审计 raw）。
func securityEventsRawIsChainStarter(raw string) bool {
	trimmed := strings.TrimSpace(raw)
	trimmed = strings.TrimRight(trimmed, "\"' \t\r\n")
	return strings.HasSuffix(trimmed, ",chain")
}

// securityEventsRawIsORScoringBranch 报告审计 raw 是否为 OR 计分规则的独立分支：
// 分支动作串只置父规则命中标记（setvar:tx.lb_cr_or_hit_<父 emit id>=1），评分由
// 父规则级单一评分点执行，因此分支 raw 不含评分字面量。block 动作的 OR 分支仍
// 内联评分（deny 首个命中即中断，不存在重复累加），不命中本判据。
func securityEventsRawIsORScoringBranch(raw string) bool {
	return strings.Contains(raw, "setvar:tx."+customRuleORHitVarPrefix)
}

// securityEventsRawNeedsRuleScore 汇总「raw 无评分字面量、需按父规则补分」的形态。
func securityEventsRawNeedsRuleScore(raw string) bool {
	return securityEventsRawIsChainStarter(raw) || securityEventsRawIsORScoringBranch(raw)
}

// securityEventsChainedCustomRuleScore 按发射 id 回查自定义规则分：
// 多条件 block/pass 规则的 setvar 在链尾，审计 raw 只有起始条 → 摄入侧评分恒 0。
// 普通发射 id = DB id + 10000；OR 分支由 DecodeCustomRuleEmitID 回解同一父规则。
// 合成 id 1000000+ 不带评分，GeoIP/CRS/IP 族段均不重叠。
//
// 取值顺序保证确定性：优先归因策略（attributedPolicyID，事件实际归属的策略），
// 未命中再按 policy_id 升序扫（同一规则被多策略内嵌引用且分数不同时，取最小
// policy_id 的分——与归因「最小 policy_id」口径一致）。不按 map 迭代序取值：
// 同一事件在不同 tick/重放会得到不同 anomaly_score（评分列/大屏分档抖动）。
func securityEventsChainedCustomRuleScore(ruleTriggered string, policyByID map[int]*models.SecurityPolicy, attributedPolicyID int) int {
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return 0
	}
	ruleID, ok := DecodeCustomRuleEmitID(n)
	if !ok {
		return 0
	}
	if p := policyByID[attributedPolicyID]; p != nil {
		if score, ok := chainedCustomRuleScoreInPolicy(p, ruleID); ok {
			return score
		}
	}
	ids := make([]int, 0, len(policyByID))
	for id := range policyByID {
		if id == attributedPolicyID {
			continue
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	for _, id := range ids {
		if score, ok := chainedCustomRuleScoreInPolicy(policyByID[id], ruleID); ok {
			return score
		}
	}
	return 0
}

// chainedCustomRuleScoreInPolicy 在单策略的自定义规则引用里找该 DB id 的启用
// 规则分（内嵌对象形态的 score 来自载荷，ID 数组形态来自 security_custom_rules）。
func chainedCustomRuleScoreInPolicy(p *models.SecurityPolicy, ruleID int) (int, bool) {
	if p == nil {
		return 0, false
	}
	for _, cr := range policyCustomRulesCached(p, nil) {
		if cr.ID == ruleID && cr.Enabled {
			return cr.Score, true
		}
	}
	return 0, false
}

// errSecurityEventsEmptyID 标记无 transaction_id 的事务：去重唯一索引是部分索引
// （谓词排除空 transaction_id，DDL 见 db/metrics.go 的 idx_security_events_transaction；
// gofmt 会把 doc 注释内的空串字面量两单引号改写为全角右引号，故以文字代字面量）。
// 空 id 没有幂等键，重试路径（tick 失败重放、轮转补采与 tick 重叠）会重复插入，
// 因此视为解析失败跳过。
var errSecurityEventsEmptyID = errors.New("transaction has no id")

// errSecurityEventsStalled 标记「残缺文档等待补写」的停等状态
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
	rec.messagesDropped = doc.MessagesDropped
	// 请求级去重键：链首（lb_security_blocked_counter）为每个请求注入，
	// 预检与全部绑定策略的引擎事务都携带同一值（见 securityEventsRequestDeduper）。
	rec.requestKey = securityEventsFirstHeader(tx.Request.Headers, "x-lb-security-timing-id")
	rec.RequestHeaders = securityEventsSerializeHeaders(tx.Request.Headers)
	rec.RequestBody = securityEventsRecordBody(tx.Request.Body, tx.Request.BodyTruncated)
	if tx.IsInterrupted {
		rec.Action = "blocked"
	}
	if rec.Host == "" {
		rec.Host = securityEventsHostWithoutPort(securityEventsFirstHeader(tx.Request.Headers, "host"))
	}
	if len(doc.Messages) > 0 {
		rec.RuleTriggered = doc.Messages[0].Data.ID.String()
		rec.RuleMsg = securityEventsClipTextField(doc.Messages[0].Message, securityEventsRuleMsgCap)
		rec.customRuleScoreFallback = securityEventsRawNeedsRuleScore(doc.Messages[0].Data.Raw)
	}
	// 写侧 messages 上限截断（messages_dropped）必须在事件行上可见：被省略的
	// 规则命中消息无法回填，详情页只会看到已采集的那部分——行内标记与写侧
	// 计数、进程级健康位三处同源披露，缺任一处都等于「丢失不可见」。
	if doc.MessagesDropped > 0 && rec.RuleMsg != "" {
		rec.RuleMsg = securityEventsRuleMsgWithDroppedNote(rec.RuleMsg, doc.MessagesDropped)
	}
	// URI 与 rule_msg 同门裁剪（头/体在构造期已裁剪）：单行体积契约为
	// 「解析后的记录」自身属性，插入与改判 UPDATE 两条写路径共享。
	rec.URI = securityEventsClipTextField(rec.URI, securityEventsURICap)
	rec.AnomalyScore = securityEventsExtractAnomalyScore(doc.Messages)
	// v2.3.8（用户裁定 2026-10-17）：阶段 1/2 事件（IP 名单/预检/GeoIP/限流）
	// 审计消息不含 coraza 评分段——入库时补固定语义分，全管线统一评分驱动
	// （事件日志评分列与威胁大屏危险等级同源）：IP 名单/预检=12（高危），
	// GeoIP/限流=6（中危）；WAF 事件不受影响。
	// 爬虫两族必须先判（否则普通 GeoIP 的 8xxxxx 被当
	// 爬虫豁免得 0 分）；普通 GeoIP（id 8 / 8xxxxx 非爬虫族）的 6 分必须先于
	// 通用预检 12 分判定；429 不在预检谓词内，保持 6。分支内不重复 2/3 字面量
	// （securityEventsIsPrecheckRule 已含）。
	if rec.AnomalyScore == 0 {
		switch {
		case securityEventsIsCrawlerExemptRule(rec.RuleTriggered):
			rec.AnomalyScore = 0 // 已验证爬虫放行：审计轨迹，不计威胁分
		case securityEventsIsCrawlerSpoofRule(rec.RuleTriggered):
			rec.AnomalyScore = 12 // 爬虫伪装（验证确定否定）：高危
		case securityEventsIsGeoIPScoringRule(rec.RuleTriggered):
			rec.AnomalyScore = 6 // GeoIP 区域拦截：中危
		case securityEventsIsPrecheckRule(rec.RuleTriggered):
			rec.AnomalyScore = 12
		case rec.RuleTriggered == "429":
			rec.AnomalyScore = 6
		}
	}
	// 安全处理耗时（2026-09-27 分段计时；历史侧车退役）：耗时由审计写插件
	// （caddygeoip auditwriter.go）注入本行顶层 lb_timing 字段，直接取值。
	// 选值规则:预检段规则(IP ACL/GeoIP/信任/威胁,id 1-14 与 800xxx)取 pre_us
	// (预检拦由拦截写点代记,决策口径);WAF 段规则(CRS 9xxxxx/自定义)拦截
	// 事件取 end_us-pre_us、logged 事件取 end_us(=预检后锚点起算的 WAF 段值,
	// 见 securityEventsStageDurationEmbedded)。缺席字段保持 0,UI 显示「—」。
	rec.DurationUs = securityEventsStageDurationEmbedded(doc.LbTiming.Pre, doc.LbTiming.End, rec.RuleTriggered, tx.IsInterrupted)
	if doc.LbTiming.Pre != nil && *doc.LbTiming.Pre >= 0 {
		rec.PrecheckUs = *doc.LbTiming.Pre
	} else if securityEventsIsPrecheckRule(rec.RuleTriggered) {
		// 降级形态(pre 缺席,头对缺失/竞态):预检族 duration=兜底值,预检耗时同值
		rec.PrecheckUs = rec.DurationUs
	}
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
	securityEventsHeadersCap = 65536 // 64KB(2026-09-28 用户裁定:service mesh 用户携带大量 x-b3/x-envoy 等追踪头,8KB 截断影响调试体验;此上限仅约束事件详情弹框存储,不影响请求本身)
	securityEventsBodyCap    = 65536
	// URI / rule_msg 与头体同门：头部字段已是攻击者可控输入（长 URI、
	// 规则 msg 宏展开内嵌匹配数据），无上限时单行可达 MB 级——行帽按行裁剪
	// 会放大磁盘/内存，且批次字节门对它们不成立。上限取列表读侧单字段
	// 16KiB 裁剪预算之内（8KiB/2KiB），超限按 UTF-8 边界截断并追加标记。
	securityEventsURICap     = 8192
	securityEventsRuleMsgCap = 2048
	// securityEventsTruncatedMarker 是文本字段超限截断标记（与列表读侧
	// handlers.truncateEventListField 同形态）——落库值自带标记，展示层与
	// 导出可直接观测「该字段被裁剪」，不静默截断。
	securityEventsTruncatedMarker = "\n...[TRUNCATED]"
	// SecurityEventsDroppedHeadersKey 是写侧合成的 64KB 采集裁剪丢弃计数键；
	// 客户端同名头一律剥离，避免伪造字段被展示层当作真实丢弃数。导出供
	// handlers 列表侧裁剪原样保留该键（跨包字符串契约，禁止各包再写字面量）。
	SecurityEventsDroppedHeadersKey = "_lb_dropped_headers"
	// securityEventsDroppedHeadersKey 是包内别名（写侧多处引用保持简短）。
	securityEventsDroppedHeadersKey  = SecurityEventsDroppedHeadersKey
	securityEventsB64Prefix          = "base64:"
	securityEventsB64TruncatedPrefix = "base64-truncated:"
	securityEventsTextPrefix         = "utf8:"
)

// securityEventsRowMaxBytes 是单行理论最大体积：头/体/URI/rule_msg 各自
// 采集上限 + 文本截断标记。保留策略披露（securityevents_retention.go）与
// 批次/单轮字节口径同源，禁止在披露侧复算上限（分叉即失真）。
func securityEventsRowMaxBytes() int64 {
	caps := int64(securityEventsHeadersCap + securityEventsBodyCap + securityEventsURICap + securityEventsRuleMsgCap)
	return caps + 3*int64(len(securityEventsTruncatedMarker))
}

// securityEventsSerializeHeaders 落库事件请求头：JSON 文本，64KB 上限——超限按
// 值体积从大到小逐条丢弃，并以 _lb_dropped_headers 键记录丢弃条数（始终保持合法 JSON，
// 前端无需容错解析）。头名/值原文保留，敏感值掩码是展示层姿态。合成键保留给
// 写侧：快照插件（caddygeoip snapshotAuditHeaders）已在客户端头的首个受信
// 触点剥离伪造同名头、并把自身 64KiB 快照裁剪计数写入该键——此处把既有计数
// 视为写侧真实丢弃数，与本次落库裁剪计数合并（不剥离、不清零）。
func securityEventsSerializeHeaders(headers map[string][]string) string {
	if len(headers) == 0 {
		return ""
	}
	priorDrops := 0
	if existing, ok := headers[securityEventsDroppedHeadersKey]; ok && len(existing) > 0 {
		if parsed, err := strconv.Atoi(existing[0]); err == nil && parsed > 0 {
			priorDrops = parsed
		}
	}
	if _, ok := headers[securityEventsDroppedHeadersKey]; ok {
		clean := make(map[string][]string, len(headers))
		for key, values := range headers {
			if !strings.EqualFold(key, securityEventsDroppedHeadersKey) {
				clean[key] = values
			}
		}
		headers = clean
	}
	if len(headers) == 0 {
		if priorDrops > 0 {
			raw, err := json.Marshal(map[string][]string{securityEventsDroppedHeadersKey: {strconv.Itoa(priorDrops)}})
			if err == nil {
				return string(raw)
			}
		}
		return ""
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		return ""
	}
	if len(raw) <= securityEventsHeadersCap {
		if priorDrops == 0 {
			return string(raw)
		}
		headers[securityEventsDroppedHeadersKey] = []string{strconv.Itoa(priorDrops)}
		if merged, merr := json.Marshal(headers); merr == nil && len(merged) <= securityEventsHeadersCap {
			return string(merged)
		}
		// 恰贴上限的罕见形态：并入标记后超限——落入下方裁剪路径统一处理。
		delete(headers, securityEventsDroppedHeadersKey)
	}
	// 旧实现「删一个键 → 整表 json.Marshal」是
	// O(n²)——单请求头总量上限 1MB 时可有数千个短头，一次请求即让摄取单线程
	// 循环数千次全量编码（审计面 DoS 放大）。改为预计算每个键的序列化字节
	// （键/值各自 marshal，转义已计入），按体积降序一次扣除到目标以下，正常
	// 路径只做一次整表 marshal；估算偏差仅由下方兜底分支处理（每次至少丢
	// 一半剩余键，迭代次数对数级）。
	type headerKeySize struct {
		key  string
		size int
	}
	keys := make([]headerKeySize, 0, len(headers))
	total := 2 // 外层 {}
	for k, v := range headers {
		kb, kerr := json.Marshal(k)
		vb, verr := json.Marshal(v)
		if kerr != nil || verr != nil {
			return ""
		}
		size := len(kb) + len(vb) + 2 // "key":value + 分隔逗号/冒号
		keys = append(keys, headerKeySize{key: k, size: size})
		total += size
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].size > keys[j].size })
	trimmed := make(map[string][]string, len(headers)+1)
	for k, v := range headers {
		trimmed[k] = v
	}
	// 丢弃标记键的精确形态开销（dropped 位数按 6 位上限预留）。
	markerOverhead := len(`"_lb_dropped_headers":["000000"]`) + 1
	estimated := total
	newDropped := 0
	for _, ks := range keys {
		if estimated+markerOverhead <= securityEventsHeadersCap {
			break
		}
		delete(trimmed, ks.key)
		estimated -= ks.size
		newDropped++
	}
	if newDropped == 0 && priorDrops == 0 {
		return string(raw)
	}
	trimmed[securityEventsDroppedHeadersKey] = []string{strconv.Itoa(priorDrops + newDropped)}
	raw, err = json.Marshal(trimmed)
	if err != nil {
		return ""
	}
	for len(raw) > securityEventsHeadersCap && newDropped < len(keys) {
		batch := (len(keys) - newDropped) / 2
		if batch < 1 {
			batch = 1
		}
		for i := 0; i < batch && newDropped < len(keys); i++ {
			delete(trimmed, keys[newDropped].key)
			newDropped++
		}
		trimmed[securityEventsDroppedHeadersKey] = []string{strconv.Itoa(priorDrops + newDropped)}
		raw, err = json.Marshal(trimmed)
		if err != nil {
			return ""
		}
	}
	return string(raw)
}

// securityEventsRecordBody 把审计请求体编码进事件行，并消费写侧的
// body_truncated 标记（caddygeoip auditwriter 在 64KiB 硬截断时置位；文本体
// 另会自带 \n...[TRUNCATED] 后缀，二进制体不带）。只看长度的旧口径对二进制体
// 失效：coraza 的 JSON 格式化器把非法 UTF-8 替换为 U+FFFD，摄取拿到的是合法
// UTF-8 字符串，长度与是否截断不再一一对应——标记位是唯一可靠信号。
// 展示层已识别该后缀（SecurityEvents.vue），此处补齐落库契约。
func securityEventsRecordBody(body string, truncated bool) string {
	encoded := securityEventsEncodeBody(body)
	if !truncated || encoded == "" {
		return encoded
	}
	// 二进制体走 base64 前缀契约（文本标记会破坏解码）：把前缀升级为
	// base64-truncated 表达同一事实，展示层按该前缀渲染截断提示。
	if strings.HasPrefix(encoded, securityEventsB64TruncatedPrefix) {
		return encoded
	}
	if payload, ok := strings.CutPrefix(encoded, securityEventsB64Prefix); ok {
		return securityEventsB64TruncatedPrefix + payload
	}
	if !strings.HasSuffix(encoded, securityEventsTruncatedMarker) {
		encoded += securityEventsTruncatedMarker
	}
	return encoded
}

// securityEventsEncodeBody 落库事件请求体：64KB 上限。UTF-8 文本原样存储，
// 超限截到符文边界（不劈开多字节字符）并追加 \n...[TRUNCATED]；二进制整体
// base64 并加 base64: 前缀，超限只编码前 64KB 原始字节、前缀改为
// 文本若本身以任一保留前缀开头，先加 utf8: 转义，
// 消除「明文被展示层误当二进制」的歧义。空体存空串。
//
// base64/base64-truncated 两分支在真实管线中**防御性不可达**：coraza 的 JSON
// 审计格式化器（json.Marshal）把非法 UTF-8 字节替换为 U+FFFD，解码后的字符串
// 恒为合法 UTF-8，不会进入非 UTF-8 分支。保留它们是为了直接函数调用（单测/
// 未来非 JSON 管线）仍能安全处理二进制体。
func securityEventsEncodeBody(body string) string {
	if body == "" {
		return ""
	}
	if utf8.ValidString(body) {
		if strings.HasPrefix(body, securityEventsB64TruncatedPrefix) ||
			strings.HasPrefix(body, securityEventsB64Prefix) ||
			strings.HasPrefix(body, securityEventsTextPrefix) {
			body = securityEventsTextPrefix + body
		}
		if len(body) <= securityEventsBodyCap {
			return body
		}
		cut := securityEventsBodyCap
		for cut > 0 && !utf8.RuneStart(body[cut]) {
			cut--
		}
		return body[:cut] + securityEventsTruncatedMarker
	}
	raw := body
	truncated := false
	if len(body) > securityEventsBodyCap {
		raw = body[:securityEventsBodyCap]
		truncated = true
	}
	if truncated {
		return securityEventsB64TruncatedPrefix + base64.StdEncoding.EncodeToString([]byte(raw))
	}
	return securityEventsB64Prefix + base64.StdEncoding.EncodeToString([]byte(raw))
}

// securityEventsClipTextField 把单行文本字段截到 capBytes 字节内：不劈开多字节
// 字符（回退到符文起点），超限追加截断标记——标记随值落库，展示/导出可观测
// 「该字段被裁剪」。空值与上限内值原样返回（零拷贝）。
func securityEventsClipTextField(value string, capBytes int) string {
	if len(value) <= capBytes {
		return value
	}
	cut := capBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + securityEventsTruncatedMarker
}

// securityEventsRuleMsgWithDroppedNote 在本行命中明细被写侧上限截断时给
// rule_msg（= 首条消息文本）追加披露后缀：先按「上限 − 后缀」裁正文再拼接，
// 后缀永远不被裁剪吃掉；拼好的字段仍不超过 securityEventsRuleMsgCap（行体积
// 披露 securityEventsRowMaxBytes 的口径因此不变）。
func securityEventsRuleMsgWithDroppedNote(msg string, dropped int) string {
	note := fmt.Sprintf("\n（另有 %d 条规则命中消息未采集）", dropped)
	budget := securityEventsRuleMsgCap - len(note)
	if budget <= len(securityEventsTruncatedMarker) {
		return note
	}
	return securityEventsClipTextField(msg, budget-len(securityEventsTruncatedMarker)) + note
}

// securityEventsRuleRef is an lb_rules identity resolved for one event:
// the caddy id plus the rule name snapshotted at ingest time.
type securityEventsRuleRef struct {
	caddyID string
	name    string
}

// securityEventsTrustMatcher 摄取期「规则→启用策略信任并集」匹配器。只收录
// 引擎真实发射信任降级面的策略：非 stage0 的信任名单（id:3/5）与 stage0
// 保留检测（id:12）；直通 stage0（trust_detection=0）零事件，不构成豁免。
type securityEventsTrustMatcher struct {
	byRule map[string][]netip.Prefix
	global []netip.Prefix
}

func securityEventsBuildTrustMatcher(bindings map[string][]int, policyByID map[int]*models.SecurityPolicy) *securityEventsTrustMatcher {
	eligible := func(p *models.SecurityPolicy) bool {
		return p != nil && p.IPWhitelistEnabled && !p.IPRefMissing &&
			(p.PolicyType != models.PolicyTypeStage0 || p.TrustDetection)
	}
	m := &securityEventsTrustMatcher{byRule: make(map[string][]netip.Prefix, len(bindings))}
	var globalEntries []string
	for _, p := range policyByID {
		if eligible(p) {
			globalEntries = append(globalEntries, mergedWhitelist(p)...)
		}
	}
	m.global = wafiplist.AggregatePrefixes(globalEntries)
	for rule, ids := range bindings {
		var entries []string
		for _, id := range ids {
			if p := policyByID[id]; eligible(p) {
				entries = append(entries, mergedWhitelist(p)...)
			}
		}
		m.byRule[rule] = wafiplist.AggregatePrefixes(entries)
	}
	return m
}

func (m *securityEventsTrustMatcher) trusted(ruleCaddyID, ip string) bool {
	if m == nil {
		return false
	}
	prefixes, known := m.byRule[ruleCaddyID]
	if ruleCaddyID == "" || !known {
		// 规则已在发射后被删除/改名：无法确定逐规则信任集，退回启用策略信任
		// 并集，保证“已信任 IP 不因不可归因的下游 logged 事件被封”。
		prefixes = m.global
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	// 信任并集与 securityEventsIPPrefixSet 同形态（升序、去重、不相交），
	// 逐事件二分判定，不随名单规模线性放大。
	return securityEventsPrefixSetContains(prefixes, addr)
}

type securityEventsMappingsCacheEntry struct {
	database   *sql.DB
	version    int
	loaded     bool
	rules      map[string]securityEventsRuleRef
	bindings   map[string][]int
	policyByID map[int]*models.SecurityPolicy
}

var securityEventsMappingsCache = struct {
	sync.Mutex
	entry securityEventsMappingsCacheEntry
}{}

// securityEventsMappingLoadsForTest 统计实际全量装载次数（缓存命中不计）。
var securityEventsMappingLoadsForTest atomic.Int64

func resetSecurityEventsMappingsCacheForTest() {
	securityEventsMappingsCache.Lock()
	securityEventsMappingsCache.entry = securityEventsMappingsCacheEntry{}
	securityEventsMappingsCache.Unlock()
}

// securityEventsLoadMappings batch-loads per-tick indexes: host→rule, plus the
// v2.2.0 multi-policy attribution inputs — rule→bound policy ids (policy_id ASC
// so "first bound" is well-defined) and policy id→policy for custom_rules /
// crs_rule_groups membership checks. Domain canonicalization matches handlers'
// normalizedRuleDomains (db.CanonicalDomains). 同一 (DB,cluster_version) 复用
// 只读快照；配置写推进版本后重建，失败不缓存。
func securityEventsLoadMappings() (map[string]securityEventsRuleRef, map[string][]int, map[int]*models.SecurityPolicy, error) {
	database := db.DB
	if database == nil {
		return nil, nil, nil, errors.New("security events: database not initialized")
	}
	var version int
	if err := database.QueryRow(`SELECT COALESCE(cluster_version,0) FROM global_config WHERE id=1`).Scan(&version); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: read mapping version: %w", err)
	}
	securityEventsMappingsCache.Lock()
	defer securityEventsMappingsCache.Unlock()
	if cached := &securityEventsMappingsCache.entry; cached.loaded && cached.database == database && cached.version == version {
		// 快照内 map 只读；任何配置写推进 cluster_version 后才重建。
		return cached.rules, cached.bindings, cached.policyByID, nil
	}
	securityEventsMappingLoadsForTest.Add(1)
	rules := make(map[string]securityEventsRuleRef)
	// 显式排序键——同域名多规则（如 http/https 双规则）的纯域名键覆盖序此前
	// 依赖 SQLite 未定义返回序。不得消费 lb_rules.id（主键迁移前历史列，新行
	// 恒 NULL、镜像行为 0，ORDER BY 下旧行反而最后赋值）：排序键用
	// created_at 升序把「后创建覆盖」显式化，caddy_id 兜底确定序（同秒创建也
	// 可复现）；enabled 升序让启用规则最后赋值（覆盖禁用重名规则）。
	// MapHost 对 host:port 精确键仍优先。
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,''), COALESCE(name,''), listen_port FROM lb_rules WHERE protocol='http' AND COALESCE(domain,'') != '' ORDER BY COALESCE(enabled,0) ASC, COALESCE(created_at,'') ASC, caddy_id ASC`)
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
	// 「rule_triggered 属于哪个策略」判定（mode 供 off 门：mode=off 策略
	// 不发射 CRS，不得认领 CRS 事件）；仅加载启用策略（disabled 策略不应再
	// 接收事件归因）。
	policyByID := make(map[int]*models.SecurityPolicy)
	polRows, err := db.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(mode,'off'), COALESCE(custom_rules,'[]'), COALESCE(crs_rule_groups,'[]'), COALESCE(crs_excluded_rules,'[]'), COALESCE(ip_blacklist,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]'), COALESCE(ip_acl_list_refs,'[]'), COALESCE(ip_whitelist_enabled,1), COALESCE(ip_whitelist,'[]'), COALESCE(ip_whitelist_refs,'[]'), COALESCE(geoip_countries,'[]'), COALESCE(geoip_mode,'off'), COALESCE(waf_check_response,0), COALESCE(policy_type,''), COALESCE(trust_detection,0) FROM security_policies WHERE enabled=1`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load policies: %w", err)
	}
	defer polRows.Close()
	var policies []*models.SecurityPolicy
	for polRows.Next() {
		p := &models.SecurityPolicy{}
		var customJSON, crsJSON, crsExcludedJSON, blacklistJSON, geoipJSON, whitelistJSON, whitelistRefsJSON string
		if err := polRows.Scan(&p.ID, &p.Name, &p.Mode, &customJSON, &crsJSON, &crsExcludedJSON, &blacklistJSON, &p.IPACLEnabled, &p.IPACLMode, &p.IPACLList, &p.IPACLListRefs, &p.IPWhitelistEnabled, &whitelistJSON, &whitelistRefsJSON, &geoipJSON, &p.GeoIPMode, &p.WAFCheckResponse, &p.PolicyType, &p.TrustDetection); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan policy: %w", err)
		}
		p.CustomRules = json.RawMessage(customJSON)
		p.GeoIPCountries = json.RawMessage(geoipJSON)
		p.CRSRuleGroups = json.RawMessage(crsJSON)
		p.CRSExcludedRules = json.RawMessage(crsExcludedJSON)
		p.IPBlacklist = json.RawMessage(blacklistJSON)
		// 信任名单（IP 族 fallback 能力首选层的 logged 语义能力判定）：
		// 既有 SELECT 未携带，能力层不读库补查（摄入 tick 热路径），在此装载。
		p.IPWhitelist = json.RawMessage(whitelistJSON)
		p.IPWhitelistRefs = whitelistRefsJSON
		// 策略类型 / 保留检测：IP 族能力首选层的信任分支须镜像
		// 引擎信任门（emitTrustControl 一族的 `PolicyType != stage0` 条件；
		// 预检 id:3 排除 stage0，保留检测由 id:12 承载）——不装载则摄入态恒空值，
		// 镜像判定失效（stage0 直通
		// 策略会凭「whitelist 非空」抢认它物理上产不出的 logged IP 族事件）。
		policyByID[p.ID] = p
		policies = append(policies, p)
	}
	// deny 归因需要 refs 合并集（inline ∪ ip_acl_list_refs 解析集）——不解析则
	// refs-only deny 策略无法认领自己的 id:2 事件（MergedACLList 恒空，回退
	// inline 判定失败，事件错挂到绑定顺序首条启用策略）。
	resolvePolicyIPListRefs(policies, nil)
	// 映射会同时交给 IPC 批摄取与 live 尾读。所有懒解析字段必须在代际
	// 发布前构建完成；之后共享策略及其分析结果只读，跨通道命中同一份缓存，
	// 不引入第二份分析缓存，也不让首事件读者看到半初始化状态。
	for _, p := range policies {
		securityEventsPolicyCRSGroups(p)
		policyCustomRulesCached(p, nil)
		securityEventsPolicyCustomEmitIDs(p)
		securityEventsPolicyACLIndex(p)
		securityEventsPolicyBlacklistIndex(p)
	}
	if err := polRows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: iterate policies: %w", err)
	}
	securityEventsMappingsCache.entry = securityEventsMappingsCacheEntry{database: database, version: version, loaded: true, rules: rules, bindings: bindings, policyByID: policyByID}
	return rules, bindings, policyByID, nil
}

// securityEventsPolicyCRSExclusions 是摄取热路径的排除判定快照：JSON 只在
// tick 装载时解析一次，scope=list 的引用条目同批加载，避免逐事件查库。
// entrySets 与 entries 等长：scope=ip/list 条目的成员集（entry.IPs ∪ 引用
// 名单）在装载期解析为「升序、去重、不相交」前缀集，事件侧二分判定，
// 不再逐事件重解析 IP 串。
type securityEventsPolicyCRSExclusions struct {
	entries   []CRSExcludedEntry
	lists     map[int64][]string
	entrySets [][]netip.Prefix
}

// securityEventsBuildCRSExclusionIPIndex 为每条排除条目构建成员前缀集：
// 条目作用域不是 ip/list 时留空集（该条目无需 IP 判定）。集合来源与逐事件
// 实现同口径——entry.IPs 逗号串 ∪ ListRefs 引用的名单条目。
func securityEventsBuildCRSExclusionIPIndex(entries []CRSExcludedEntry, lists map[int64][]string) [][]netip.Prefix {
	out := make([][]netip.Prefix, len(entries))
	for i, entry := range entries {
		if entry.Scope != "ip" && entry.Scope != "list" {
			continue
		}
		match := strings.Split(entry.IPs, ",")
		for _, ref := range entry.ListRefs {
			match = append(match, lists[ref]...)
		}
		out[i] = securityEventsIPPrefixSet(match)
	}
	return out
}

func securityEventsBuildCRSExclusionMatcher(policyByID map[int]*models.SecurityPolicy) map[int]securityEventsPolicyCRSExclusions {
	out := make(map[int]securityEventsPolicyCRSExclusions, len(policyByID))
	var refIDs []int64
	seen := make(map[int64]struct{})
	for id, p := range policyByID {
		if p == nil {
			continue
		}
		entries := ParseCRSExcludedRules(string(p.CRSExcludedRules))
		if len(entries) == 0 {
			continue
		}
		set := securityEventsPolicyCRSExclusions{entries: entries}
		for _, entry := range entries {
			if entry.Scope != "ip" && entry.Scope != "list" {
				continue
			}
			for _, ref := range entry.ListRefs {
				if _, ok := seen[ref]; ok {
					continue
				}
				seen[ref] = struct{}{}
				refIDs = append(refIDs, ref)
			}
		}
		out[id] = set
	}
	var lists map[int64][]string
	if len(refIDs) > 0 {
		loaded, _, err := loadIPListEntriesVia(nil, refIDs)
		if err != nil {
			// 与发射端一致：列表不可读时该引用不形成排除（宁可记录，不误排除）。
			Logf("warn", "security events attribution: load CRS exclusion IP lists failed: %v", err)
		}
		lists = loaded
	}
	for id, set := range out {
		set.lists = lists
		set.entrySets = securityEventsBuildCRSExclusionIPIndex(set.entries, lists)
		out[id] = set
	}
	return out
}

func securityEventsCRSExclusionTargetMatches(target, ruleID string) bool {
	target = strings.TrimSpace(target)
	n, err := strconv.Atoi(ruleID)
	if err != nil || n < 900000 || n >= 1000000 {
		return false
	}
	if IsCRSGroupCode(target) {
		return len(ruleID) == 6 && strings.HasPrefix(ruleID, "9"+target)
	}
	mapped := crsFilenameToRuleIDRange(target)
	if !validSecRuleRemoveTarget(mapped) {
		return false
	}
	loRaw, hiRaw, single := strings.Cut(mapped, "-")
	if !single {
		hiRaw = loRaw
	}
	lo, loErr := strconv.Atoi(loRaw)
	hi, hiErr := strconv.Atoi(hiRaw)
	return loErr == nil && hiErr == nil && n >= lo && n <= hi
}

func securityEventsCRSExclusionRemovesRule(set securityEventsPolicyCRSExclusions, ruleID, clientIP string) bool {
	// 装载期已构建的成员集直接用；手工构造的快照（测试/非生产路径）按同一
	// 构建函数补齐，保证两条路径的判定逐点一致。
	sets := set.entrySets
	if sets == nil {
		sets = securityEventsBuildCRSExclusionIPIndex(set.entries, set.lists)
	}
	for i, entry := range set.entries {
		if CRSExclusionTargetRemovesInfra(entry.Target) {
			continue
		}
		if entry.Scope == "ip" || entry.Scope == "list" {
			// 作用域限定只支持组号与 6 位 ID（发射端 expandCRSScopedExclusionTargets
			// 同口径）；空/无法判定的客户端 IP 不构成命中。
			if clientIP == "" || !(IsCRSGroupCode(entry.Target) || IsCRSRuleIDTarget(entry.Target)) {
				continue
			}
			if i >= len(sets) || !securityEventsIPInPrefixSet(clientIP, sets[i]) {
				continue
			}
		} else if entry.Scope != "" && entry.Scope != "all" {
			// 未知 scope 不认领移除——与渲染侧同口径（未知 scope 跳过、
			// 不降级为 scope=all 全局排除）：渲染未排除该规则，归因侧也不得
			// 按「已排除」把事件从候选策略上摘走（两侧口径漂移会让「策略
			// 实际拦截的事件」被误判为「该策略不可能产出」）。
			continue
		}
		if securityEventsCRSExclusionTargetMatches(entry.Target, ruleID) {
			return true
		}
	}
	return false
}

// securityEventsPolicyCRSGroups 返回策略 crs_rule_groups 的解析缓存
// （trimmed 条目集 + 解析成功与否），与 policyCustomRulesCached 同构的
// tick 级预算化——contains 判定按「事件×候选策略」执行，原始 JSON 每策略
// 只解析一次，不再逐事件重复 Unmarshal。
func securityEventsPolicyCRSGroups(policy *models.SecurityPolicy) (map[string]struct{}, bool) {
	if policy.CRSRuleGroupsParsed {
		return policy.CRSRuleGroupsSet, policy.CRSRuleGroupsOK
	}
	policy.CRSRuleGroupsParsed = true
	var groups []string
	if err := json.Unmarshal(policy.CRSRuleGroups, &groups); err != nil {
		return nil, false
	}
	set := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		set[strings.TrimSpace(g)] = struct{}{}
	}
	policy.CRSRuleGroupsSet = set
	policy.CRSRuleGroupsOK = true
	return set, true
}

// securityEventsPolicyCustomEmitIDs 返回策略自定义规则发射 id 集合的解析缓存。
// ID 数组先保留普通发射 id 的原始快照归因能力，再用已加载规则补充 OR 分支；
// 内嵌对象直接按渲染时的合成 id 顺序展开。
func securityEventsPolicyCustomEmitIDs(policy *models.SecurityPolicy) (map[int]struct{}, bool) {
	if policy.CustomRuleIDsParsed {
		return policy.CustomRuleEmitIDs, policy.CustomRuleIDsOK
	}
	policy.CustomRuleIDsParsed = true
	var ids []int
	if err := json.Unmarshal(policy.CustomRules, &ids); err == nil {
		set := make(map[int]struct{}, len(ids))
		for _, id := range ids {
			set[id+10000] = struct{}{}
		}
		addResolvedCustomRuleEmitIDs(set, policyCustomRulesCached(policy, nil))
		policy.CustomRuleEmitIDs = set
		policy.CustomRuleIDsOK = true
		return set, true
	}
	var embedded []models.CustomRule
	if err := json.Unmarshal(policy.CustomRules, &embedded); err == nil {
		set := make(map[int]struct{}, len(embedded))
		addResolvedCustomRuleEmitIDs(set, embedded)
		policy.CustomRuleEmitIDs = set
		policy.CustomRuleIDsOK = true
		return set, true
	}
	return nil, false
}

func addResolvedCustomRuleEmitIDs(set map[int]struct{}, rules []models.CustomRule) {
	synthetic := 0
	for _, cr := range rules {
		if !customRuleEmittable(cr) {
			continue
		}
		emitID := cr.ID + 10000
		if cr.ID == 0 {
			synthetic++
			emitID = SyntheticCustomRuleIDBase + synthetic
		}
		if cr.ConditionLogic != "or" {
			set[emitID] = struct{}{}
			continue
		}
		delete(set, emitID)
		conditionCount := len(cr.Conditions)
		if conditionCount == 0 {
			conditionCount = 1
		}
		for idx := range conditionCount {
			set[customRuleORConditionEmitID(emitID, idx)] = struct{}{}
		}
	}
}

// securityEventsPolicyContainsRuleWithExclusions 归属判定的单一生产实现
// （无排除快照的测试包装在 securityevents_test.go）。
//
// reports whether the given rule id belongs to
// the policy's active rule set. 自定义规则（10000+，且 <800000）：查 custom_rules
// JSON（兼容 ID 数组与内嵌对象数组两种形状）。注意 ID 空间：custom_rules JSON
// 存的是 security_custom_rules 的 DB 主键 id，而 audit 的 rule_triggered 是
// emit id（DB id + 10000，见 emitCustomRules），因此归属判定在 emit 空间比较
// （DB id + 10000 == n）。CRS 规则（9xxxxx）：crs_rule_groups 条目为两位数字
// 代码（如 "42" 对应 942xxx，与 BuildCorazaDirectives 的 `REQUEST-9<code>-*.conf`
// Include 同款口径）；空数组按发射端语义视为「包含全部 REQUEST-*」，即所有 CRS
// 规则均属于该策略。IP ACL 拒绝带：id 4 = 遗留 ip_blacklist 拒绝，
// BuildCorazaDirectives 仅对黑名单非空的策略发射；id 2 = IP ACL 列表外拒绝——
// 发射端对 allow 与 deny 两种模式都发 id 2（security.go「IP 白名单拒绝」/
// 「IP 黑名单拒绝」）；归属端有意只认 deny 模式策略（allow 模式事件经回退归到
// 首个启用策略，仅展示层影响——IPACLAllowModeDoesNotOwnDenyEvent 钉住该口径）。
// 成员精确归因（2026-09-21 生产事故，「名单命中者优先」）：clientIP 非空
// 且可解析时，id 2/4 在名单非空基础上追加成员判定——名单未命中事件源 IP 的
// deny/黑名单策略不认领（多 deny 策略绑定下，首绑非属主凭「名单非空」曾误夺
// 真属主的归属）；名单命中判定内联优先、缺失时回退 IPACLList（mergedACLList
// 同一读法）。事件源 IP 不在任何名单＝名单在发射后被编辑的漂移形状，contains
// 让位、由 fallback 能力首选层归属（绝不归零）。clientIP 为空（调用形状/
// 记录缺 IP）保持既有「名单非空即认领」口径。
// crsExclusions 为配置期/运行时 CRS 排除快照：被本策略删除的规则不可能是其
// 发射面（生产归因链一律走本函数；无排除快照的测试包装在
// securityevents_test.go）。
func securityEventsPolicyContainsRuleWithExclusions(policy *models.SecurityPolicy, ruleTriggered, clientIP string, crsExclusions securityEventsPolicyCRSExclusions) bool {
	if policy == nil || ruleTriggered == "" {
		return false
	}
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	switch {
	case n > geoipPrecheckRuleBase && n < geoipPrecheckRuleLimit:
		// 阶段 1 预检 8xxxxx 段：普通 GeoIP
		// [800001,810000)、爬虫豁免 [810000,850000)、爬虫伪装 [850000,900000)
		// 三族互斥，属主由 decodePrecheckRuleID 唯一解码——不再用
		// policy.ID == n-800000 猜属主（该公式把 crawler id 解成万级策略编号）。
		// 无法唯一解码（p=0 边界值/历史越界行）返回 false，由能力首选层
		// fallback 归属，绝不伪造属主。
		family, pid, _, ok := decodePrecheckRuleID(ruleTriggered)
		if !ok || family == precheckRuleFamilyUnknown {
			return false
		}
		return policy.ID == pid
	case n == 8:
		// GeoIP 拦截（遗留共享 id:8，策略引擎时代的历史事件）：所有权与发射门
		// （PolicyHasGeoIP）同口径——mode!='off' 且名单非空。off 态名单仅为
		// 保留数据（不发射 id:8），不得抢走真实发射策略的归因（mode=off 但
		// 名单非空的首绑定策略不得凭候选顺序认领 id:8 事件）。
		if policy.GeoIPMode == "off" {
			return false
		}
		var geoCountries []string
		if err := json.Unmarshal(policy.GeoIPCountries, &geoCountries); err != nil {
			return false
		}
		return len(geoCountries) > 0
	case n == 4:
		blacklist := securityEventsPolicyBlacklistIndex(policy)
		if !blacklist.OK || blacklist.Entries == 0 {
			return false
		}
		return clientIP == "" || securityEventsIPInPrefixSet(clientIP, blacklist.Prefixes)
	case n == 2:
		if !policy.IPACLEnabled {
			return false
		}
		// deny 归因应含 refs 合并集（inline ∪ ip_acl_list_refs），
		// 否则 refs-only deny 策略无法认领自己的 id:2 事件。名单解析快照
		// 每个策略只构建一次（前缀集 + 原始条目数），成员判定二分。
		acl := securityEventsPolicyACLIndex(policy)
		if !acl.OK {
			return false
		}
		nonEmpty := acl.NonEmpty
		if policy.IPACLMode == "allow" {
			// 空 allow 名单发射的是 fail-closed 恒拒面，事件应由该策略认领；
			// 非空 allow 的 id:2 仍保持既有「不拥有」口径。
			return !nonEmpty
		}
		if policy.IPACLMode != "deny" || !nonEmpty {
			return false
		}
		return clientIP == "" || securityEventsIPInPrefixSet(clientIP, acl.Prefixes)
	case n == 7:
		// 预检 allow 交集外拒绝（含空名单 fail-closed 恒拒）属于 allow 策略。
		return policy.IPACLEnabled && policy.IPACLMode == "allow"
	case n == 14:
		// 历史威胁情报库共享 id:14：由带 ACL 引用/内联名单的 IP 控制策略认领。
		return policy.IPACLEnabled && (len(policy.MergedACLList) > 0 || ipListRefsNonEmpty(policy.IPACLListRefs))
	case securityEventsRuleIsCRSFamily(ruleTriggered):
		// v2.2.2 混合选择——crs_rule_groups 可含六位 CRS ID 正选；六位 ID 触发的
		// CRS 事件应先按六位正选归因，未命中时回落既有组号归因（空组=全部 CRS）。
		// 早期实现把本分支放在组号分支（:371）之前且直接 return false，使后者成为
		// 死代码——用两位组号（常规配置）的策略其 CRS 事件归因失效。
		// mode=off 不发射任何 CRS（engine 分支不成立或零 Include），
		// 不得认领 CRS 事件（与 GeoIP 分支的 off 门同口径）。2026-09-09 四态化:
		// custom_only 同样零 CRS Include,口径收紧为「CRS 生效模式」——否则
		// 同规则多策略绑定时 custom_only 策略会抢走 blocking 策略的 CRS 事件归属。
		if policy.Mode != "blocking" && policy.Mode != "detection" {
			return false
		}
		// 配置期 SecRuleRemoveById / 运行时 ctl 已删除的规则不可能是本策略
		// 的发射面；先判排除，避免 949/959 强制包含分支与组号分支误认领。
		if securityEventsCRSExclusionRemovesRule(crsExclusions, ruleTriggered, clientIP) {
			return false
		}
		// RESPONSE-95x/98x 文件只在响应检查开启时 Include；关闭时
		// 默认全量、组号或单 ID 选择都不能让该策略认领响应事件。
		if !policy.WAFCheckResponse && (strings.HasPrefix(ruleTriggered, "95") || strings.HasPrefix(ruleTriggered, "98")) {
			return false
		}
		// 949 评估规则自 v2.2.3 起对全部启用 WAF 的策略强制包含
		// 基础设施去重强制 Include），959 对开启响应检查的策略强制包含——均与
		// 存储的 crs_rule_groups 无关（写入面已剥离 49/59 组号，组号匹配恒
		// false），须按各自发射门先行放行。
		if strings.HasPrefix(ruleTriggered, "949") {
			return true
		}
		if strings.HasPrefix(ruleTriggered, "959") {
			return policy.WAFCheckResponse
		}
		groups, groupsOK := securityEventsPolicyCRSGroups(policy)
		if !groupsOK {
			return false
		}
		if _, hit := groups[strconv.Itoa(n)]; hit {
			return true
		}
		if len(groups) == 0 {
			return true
		}
		// 切片前长度防御——六位是 CRS 规则 ID 的规范
		// 形态；前导零等畸形串（Atoi 可解析入区间但长度≠6，如 "0942100"）
		// 的 [1:3] 切片错位（切出 "94" 而非真实组号 21），会误认领存量/带外
		// 携带对应错位组号的策略。组号不可解码即保守不认领——事件归属由
		// fallback 层兜底（摄取必有归属不破），生产不可达纯防御。
		if len(ruleTriggered) != 6 {
			return false
		}
		_, codeHit := groups[ruleTriggered[1:3]]
		return codeHit
	case securityEventsRuleIsCustomFamily(ruleTriggered):
		// (2026-09-10 审计):off=全关(四态化)零发射,不得认领自定义规则事件
		//(与 CRS 分支 blocking/detection 门同口径;custom_only/blocking/detection
		// 三态的自定义规则发射由 customActive 保证)。
		if policy.Mode == "off" {
			return false
		}
		emitIDs, idsOK := securityEventsPolicyCustomEmitIDs(policy)
		if !idsOK {
			return false
		}
		_, idHit := emitIDs[n]
		return idHit
	}
	return false
}

// securityEventsFallbackCanProduce(fallback 归因门 + 误拒修正):
// fallback 归因的模式/动作可行性门。只核「该策略的当前模式
// 在物理上能否产出此 (动作,规则 id) 事件」,不核名单成员(fallback 的存在理由
// 正是配置可能已在发射后变更)。门禁表逐格对照发射侧单一事实:
//
//	· IP 控制/GeoIP(id:2/4/8)+预检 allow 交集(id:7):与 WAF 模式无关独立
//	  发射（BuildCorazaDirectives 的 emitIPControl/geoipActive 段，注释原文
//	  「runs independently of the WAF mode」；引擎按 emitIPControl||geoipActive
//	  置 SecRuleEngine On）——off 模式亦可产
//	  blocked（初版门「off 零发射」与发射侧设计明文矛盾,误拒);
//	· detection 的 id:6 DetectionOnly 切换发射于 IP 控制/
//	  自定义规则之后、CRS 之前——phase:1 拦截规则真实阻断（见
//	  buildCorazaDirectives 的 detection 分支明文保障）,
//	  blocked 可产={2,4,7,8}+自定义;CRS 在切换后评估,DetectionOnly 零中断
//	  （初版门 detection+blocked 全量误拒);
//	· custom_only 零 CRS Include（同一构建函数的 custom_only 分支）——CRS 事件全拒;
//	  无 949 评分链,id:11 守卫(phase:2 pass)恒不产 blocked;
//	  自定义规则无 id:6 切换任意相位可拦;预检 id:7 与模式无关
//	  (buildIPPrecheckDirectives)(初版门允许集漏 7,误拒);
//	· id:11 发射面(2026-09-21 实证;收紧):emitBodyProcessorRules
//	  在 blocking/detection 恒发射,custom_only 收紧为存在启用自定义规则才发射
//	  (BuildCorazaDirectives 的 body 处理器调用点,零规则+仅 IP 控制形状 body
//	  access 恒 Off、发射即死
//	  指令)——logged 事件三模式物理可能,门放行格与发射面一致(模式粒度,
//	  custom_only 零规则策略的物理不可能由 fallback 归属兜底吸收);blocked
//	  任何模式均不可产(phase:2 pass 恒不中断),blocking 的 blocked 11 保持
//	  可行格(物理上该形状事件不存在,恒真格无害);
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
	crs := securityEventsRuleIsCRSFamily(ruleTriggered)
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
	return IsStage1PrecheckID(n) // 消费单一事实源（原第三处字面量复写）
}

// securityEventsRuleIsCustomFamily 报告规则 id 是否属于自定义规则族（普通
// id+10000、旧版合成段及 OR 分支高段）。单一事实源：fallback 门与能力首选层共用。
func securityEventsRuleIsCustomFamily(ruleTriggered string) bool {
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	return (n >= 10000 && n < geoipPrecheckRuleBase) || n >= 1000000
}

// securityEventsRuleIsCRSFamily 报告规则 id 是否落在 CRS 9xxxxx 段（排除判定
// 只对该段有意义；IP/自定义族不受 SecRuleRemoveById 影响）。
func securityEventsRuleIsCRSFamily(ruleTriggered string) bool {
	n, err := strconv.Atoi(ruleTriggered)
	return err == nil && n >= 900000 && n < 1000000
}

// securityEventsCustomRulesEventSurface（2026-09-21，IP 族能力首选层同模式扩展）：
// 自定义族事件 fallback 首选层的物理发射面判定——emitCustomRules 对 Disabled
// 规则整条跳过（security.go「if !cr.Enabled { continue }」，合成段 1000000+ 同
// 一循环同一过滤），无启用自定义规则的策略物理上不产任何自定义族事件
// （blocked/logged 同判）。策略粒度能力，与 IP 族 surface 同口径：规则 id 归属
// 规则」——停用/悬空引用均不计能力。共享映射在代际发布前已构建该缓存；
// 独立策略仍在首次调用时解析并复用，读取统一经 policyCustomRulesCached
// （store=nil 回退 db.DB，与 contains 读 CustomRules 原文同库同口径）。
// 返回 false 不代表事件归零：attribute 层能力首选层落空后仍经「模式/动作门」
// 归属（摄取必有归属）。
func securityEventsCustomRulesEventSurface(p *models.SecurityPolicy) bool {
	if p == nil {
		return false
	}
	for _, cr := range policyCustomRulesCached(p, nil) {
		if customRuleEmittable(cr) {
			return true
		}
	}
	return false
}

// securityEventsIPFamilyEventSurface（2026-09-21 生产事故，能力维度）
// IP 族事件 fallback 首选层的物理发射面判定，逐 id 对照发射侧单一事实——
//
//	· id 8/800xxx（GeoIP）：PolicyHasGeoIP（mode!=off 且名单非空），与发射门
//	  （buildIPPrecheckDirectives 的 GeoIP 段、BuildCorazaDirectives 的
//	  GeoIP 交接）同源；
//	· id 2（ACL 拒绝带）：deny 模式且合并名单非空（BuildCorazaDirectives 的
//	  「IPACLEnabled && len(ipACLList)>0」门与其 deny 分支；allow 模式发射的
//	  id:2 归属口径有意不认（问题，IPACLAllowModeDoesNotOwnDenyEvent 钉）；
//	· id 4（遗留黑名单）：黑名单非空（同一构建函数的黑名单段，无模式门）；
//	· id 7（预检 allow 交集）：allow 模式且合并名单非空（buildIPPrecheckDirectives
//	  仅 allow 参与交集）；
//	· 信任名单（ip_whitelist）：仅 logged（检测）语义计入 id 2/4/7 能力——信任
//	  只以 DetectionOnly 降级事务、令 deny 规则以检测动作留痕，自身发射的
//	  id:3/5/12 为 nolog pass 永不产事件，更不可能产 blocked。**镜像引擎/预检
//	  信任门（2026-09-21）**：stage0 + trust_detection=0（直通）
//	  的信任 IP 走路由层 subroute 短路（零 coraza 事务）、非信任 IP 全链评估且
//	  无 DetectionOnly 降级 ⇒ 该策略物理上不产任何 logged IP 族事件，故要求
//	  `PolicyType != stage0 || TrustDetection`（对齐 BuildCorazaDirectives 的
//	  信任发射门与 buildIPPrecheckDirectives 的 id:3 排除 / id:12 承载保留检测）；无 policy_type
//	  的存量信任策略（mixed 语义，走 id:3 并集）不受影响。
//
// 名单读取与 SecurityPolicyHasIPControl 同源（inline ∪ refs；MergedACLList 为
// 摄入映射解析集，缺失回退 inline）。信任名单分支额外要求**合并后内容非空**
// （mergedWhitelist 与渲染侧 trusted 集同源）：引用存在但内容为空/条目全部
// 到期/列表已删（悬空引用仅 warn）的策略渲染时零发射，不得凭 refs 认领事件。
// 返回 false 不代表事件归零：attribute
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
	// 名单判据走每 tick 一次的解析快照（ACL 前缀集/原始条目数），逐事件
	// 不再重解析名单或重复 Unmarshal 黑名单；NonEmpty 与 mergedACLList 同源。
	aclIndex := securityEventsPolicyACLIndex(p)
	aclCapable := p.IPACLEnabled && (p.IPACLMode == "allow" || aclIndex.NonEmpty)
	switch n {
	case 2:
		if p.IPACLMode == "deny" && aclCapable {
			return true
		}
	case 4:
		if blacklist := securityEventsPolicyBlacklistIndex(p); blacklist.OK && blacklist.Entries > 0 {
			return true
		}
	case 7:
		if p.IPACLMode == "allow" && aclCapable {
			return true
		}
	}
	if action != "blocked" && p.IPWhitelistEnabled && (p.PolicyType != models.PolicyTypeStage0 || p.TrustDetection) {
		// 与发射面同源（mergedWhitelist 即渲染侧 trusted 集的唯一取法）：渲染
		// 侧是**内容门控**——空信任集不发射 id:3/12，物理上产不出本事件；而
		// 「引用了名单（refs 非空）」并不等于会发射：名单为空集/条目全部到期/
		// 列表已被删除（悬空引用仅 warn）都渲染为空信任集。旧实现按 refs 存在
		// 判定，多策略绑定同一规则时回退归因会把 logged IP 族事件错挂到空信任
		// 集的策略（policy_id 更小时先命中），事件「策略」列与 24h 计数错挂。
		// 只读投影/解析失败方向：mergedWhitelist 取不到内容时返回空集 → 不认领，
		// 与「无发射面」同向（归因仍会落到模式/动作门，绝不归零）。
		return len(mergedWhitelist(p)) > 0
	}
	return false
}

// securityEventsIPPrefixSet 把名单条目解析为「升序、去重、不相交」前缀集
// （wafiplist.AggregateParsedPrefixes 单一事实源，与 @ipListFast 加载形态
// 相同）：条目只在此处解析一次，成员判定走二分。条目解析走引擎侧单一事实源
// wafiplist.ParseIPEntry（4in6 归一 / zone 拒绝与 @ipListFast 完全同口径）
// ——裸 netip.ParsePrefix 不归一 4in6 条目，写侧允许的 ::ffff:a.b.c.d/120
// 在引擎侧命中、归因侧会判不命中。解析失败/空白条目按不命中跳过（与渲染端
// @ipMatch 的宽松容忍一致——坏条目在生成期告警，不在此重复报）；聚合前后
// 匹配集合逐点相等，故二分结果与逐条扫描等价。
func securityEventsIPPrefixSet(entries []string) []netip.Prefix {
	parsed := make([]netip.Prefix, 0, len(entries))
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if prefix, err := wafiplist.ParseIPEntry(entry); err == nil {
			parsed = append(parsed, prefix)
		}
	}
	return wafiplist.AggregateParsedPrefixes(parsed)
}

// securityEventsIPInPrefixSet 报告事件源 IP 是否落在前缀集内：集合满足
// 「升序、去重、不相交」不变量（securityEventsIPPrefixSet 产物），含目标的
// 前缀必为最后一个起始地址 ≤ 目标的条目，单次 sort.Search 即判定。
// IP 解析口径与引擎一致：4in6 归一后匹配（查询侧 Unmap，前缀侧已在
// ParseIPEntry 归一）。
func securityEventsIPInPrefixSet(ip string, set []netip.Prefix) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return securityEventsPrefixSetContains(set, addr)
}

// securityEventsPrefixSetContains 是 addr 形态的二分判定（集合不变量同
// securityEventsIPInPrefixSet）：调用方已持有解析后的地址时避免重复解析。
// 查询侧先 Unmap——4in6 形态地址与 v4 前缀在归一后才可比。
func securityEventsPrefixSetContains(set []netip.Prefix, addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	i := sort.Search(len(set), func(i int) bool { return set[i].Addr().Compare(addr) > 0 }) - 1
	return i >= 0 && set[i].Contains(addr)
}

// securityEventsPolicyACLIndex 返回策略 IP ACL 名单的解析快照（每个策略在
// 首次判定时构建一次，同 tick 内「事件×候选策略」复用）。来源选择与逐事件
// 实现同口径：合并集（inline ∪ refs）非空取合并集，否则回退 inline JSON；
// inline JSON 畸形时 OK=false（调用方按既有「不认领」口径）。NonEmpty 与
// mergedACLList 同源（该调用亦负责内联畸形诊断），Entries 是原始条目数。
func securityEventsPolicyACLIndex(p *models.SecurityPolicy) models.SecurityPolicyIPListIndex {
	if p.ACLIPIndex.Built {
		return p.ACLIPIndex
	}
	idx := models.SecurityPolicyIPListIndex{Built: true}
	idx.NonEmpty = len(mergedACLList(p)) > 0
	idx.OK = true
	list := p.MergedACLList
	var rawInline []string
	inlineErr := json.Unmarshal([]byte(p.IPACLList), &rawInline)
	if len(list) == 0 {
		if inlineErr != nil {
			idx.OK = false
		} else {
			list = rawInline
		}
	}
	if idx.OK {
		idx.Entries = len(list)
		// 无引用形态：合并集只来自 inline 且已在加载期做过 CIDR 归并（同族
		// 兄弟归并/覆盖剔除）——「原始条目数」口径必须取 inline 原始条目，
		// 否则条目数随归并缩水；带引用时取合并集（含引用条目）。
		if !ipListRefsNonEmpty(p.IPACLListRefs) {
			idx.Entries = len(rawInline)
		}
		idx.Prefixes = securityEventsIPPrefixSet(list)
	}
	p.ACLIPIndex = idx
	return idx
}

// securityEventsPolicyBlacklistIndex 返回遗留 ip_blacklist 的解析快照
// （构建时机/复用语义同 securityEventsPolicyACLIndex）：原始 JSON 与条目
// 解析都不再逐事件重复；JSON 畸形时 OK=false（判定按不命中）。
func securityEventsPolicyBlacklistIndex(p *models.SecurityPolicy) models.SecurityPolicyIPListIndex {
	if p.IPBlacklistIPIndex.Built {
		return p.IPBlacklistIPIndex
	}
	idx := models.SecurityPolicyIPListIndex{Built: true}
	var list []string
	if err := json.Unmarshal(p.IPBlacklist, &list); err == nil {
		idx.Entries = len(list)
		idx.Prefixes = securityEventsIPPrefixSet(list)
		idx.OK = true
	}
	p.IPBlacklistIPIndex = idx
	return idx
}

// securityEventsAttributePolicy v2.2.0 多策略事件归因：rule_triggered → 查该规则
// ID 属于哪个策略（custom_rules / CRS 组 / IP ACL 拒绝带匹配，IP 族带事件源 IP
// 成员精确判定），重叠时取绑定顺序第一条（policy_id ASC 的第一个）——
// 语义声明：多策略 CRS 重叠时实际执行拦截的引擎实例在 coraza 审计
// 日志中不可恢复（各策略引擎对同一 CRS 规则 ID 均可产出中断），首绑定归因是摄
// 取期约定的最接近发射现实的稳定口径，是记账语义而非 forensic 判定；事件页与
// 24h 计数消费同一口径。策略均未
// 显式包含时走 fallback，两层判定：
//
//  1. 能力首选层（2026-09-21 生产事故）：模式/动作门
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
//
// securityEventsAttributePolicy（本函数）是「无排除快照」形态的测试包装：
// 生产归因必须携带 crsExclusions（经 securityEventsAttributePolicyWithExclusions
// 传入摄取路径解析的排除快照），缺省 nil 会把配置了 crs_excluded_rules 的策略
// 误归因。仅测试调用、生产零调用是有意形态，不是可删除的死代码——新增测试
// 用例也一律走本包装即可。
func securityEventsAttributePolicy(ruleCaddyID, ruleTriggered, action, clientIP string, policyByID map[int]*models.SecurityPolicy, bindings map[string][]int) (int, string) {
	return securityEventsAttributePolicyWithExclusions(ruleCaddyID, ruleTriggered, action, clientIP, policyByID, bindings, nil)
}

func securityEventsAttributePolicyWithExclusions(ruleCaddyID, ruleTriggered, action, clientIP string, policyByID map[int]*models.SecurityPolicy, bindings map[string][]int, crsExclusions map[int]securityEventsPolicyCRSExclusions) (int, string) {
	policyIDs := bindings[ruleCaddyID]
	if len(policyIDs) == 0 {
		return 0, ""
	}
	for _, pid := range policyIDs {
		p := policyByID[pid]
		if p == nil {
			continue
		}
		// 渲染被跳过（引用名单缺失）的策略不参与成员归因。
		if p.IPRefMissing {
			continue
		}
		if securityEventsPolicyContainsRuleWithExclusions(p, ruleTriggered, clientIP, crsExclusions[p.ID]) {
			return pid, p.Name
		}
	}
	ipFamily := securityEventsRuleIsIPFamily(ruleTriggered)
	customFam := securityEventsRuleIsCustomFamily(ruleTriggered)
	// IPRefMissing=该策略因引用名单缺失被渲染跳过——物理上不可能
	// 产出本事件，不得凭规则 ID/能力门抢走真实属主。但「发射后配置漂移」的
	// 既有 fallback 语义保留：已渲染候选全部不匹配时，仍归到未渲染候选
	// （绝不归零），仅让其退居末位。
	fallbackMatch := func(p *models.SecurityPolicy, requireCapability bool) bool {
		if !securityEventsFallbackCanProduce(p, action, ruleTriggered) {
			return false
		}
		if !requireCapability {
			return true
		}
		if ipFamily && !securityEventsIPFamilyEventSurface(p, action, ruleTriggered) {
			return false
		}
		if customFam && !securityEventsCustomRulesEventSurface(p) {
			return false
		}
		if securityEventsRuleIsCRSFamily(ruleTriggered) && securityEventsCRSExclusionRemovesRule(crsExclusions[p.ID], ruleTriggered, clientIP) {
			return false
		}
		return true
	}
	for _, skipMissing := range []bool{true, false} {
		for _, requireCapability := range []bool{true, false} {
			for _, pid := range policyIDs {
				p := policyByID[pid]
				if p == nil {
					continue
				}
				if skipMissing == p.IPRefMissing {
					continue
				}
				if fallbackMatch(p, requireCapability) {
					return pid, p.Name
				}
			}
		}
	}
	return 0, ""
}

// securityEventsCanonicalDomains host 规范化（IDNA/端口剥离）的调用缝
// （db.CanonicalDomains）——var 供测试观测调用次数（pass 内记忆化钉测）。
var securityEventsCanonicalDomains = db.CanonicalDomains

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
	canonical, err := securityEventsCanonicalDomains(host)
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
	// 单源原子落盘（tmp+fsync+父目录 fsync）——0 字节偏移文件会让
	// 尾读从头重放（重复摄取），掉电丢失则可能跳读窗口。
	return writeFileAtomicSynced(path, []byte(strconv.FormatInt(offset, 10)), 0o644)
}

// securityEventsGenerationPath 返回摄取 offset 所属 metrics 库代际的标记文件
// 路径（与 offset 同目录，随 offset 一起生命周期）。
func securityEventsGenerationPath(offsetPath string) string { return offsetPath + ".generation" }

// securityEventsReadGeneration 读取已记录的库代际；文件缺失（首装/升级首启）
// 返回空串，与「代际未知」同义。
func securityEventsReadGeneration(path string) (string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// securityEventsWriteGeneration 原子持久化库代际（与 offset 落盘同源 helper）。
func securityEventsWriteGeneration(path, generation string) error {
	return writeFileAtomicSynced(path, []byte(generation), 0o644)
}

// securityEventsGenerationGuard 把 offset 与 metrics 库代际绑定：库被隔离重建
// （损坏自愈=新库文件=新代际）后，旧 offset/inode 状态属于已丢弃的旧库，必须
// 按「新库」语义归零从头摄取——否则新库永久跳过文件中段之前的事件。
//
// 库定性（Ruling）：安全事件历史存放在 metrics 库（security_events /
// security_event_rollup / security_event_target_rollup），它**不是**可丢弃
// 遥测——同库的 metrics_history 可再生，安全事件历史不可再生。db 层的损坏
// 隔离重建因此必须显式披露「指标历史与安全事件历史一并丢弃」（进程日志 +
// 系统审计留痕，见 db.reportMetricsQuarantine）；唯一有意的删除路径是保留
// 策略清理（securityevents_retention.go：天数 + 行帽双口径）。
//
// 语义取舍（Ruling）：新库没有旧库的任何记录，无法知道哪些行「已入旧库」；
// 从头摄取是唯一不丢事件的策略。同一库内的重复摄取由 transaction_id 唯一
// 索引（INSERT OR IGNORE）幂等吸收，且重建后旧库文件已隔离，不存在向同一
// 库重放的问题。首次见到代际（升级首启/新装）只登记代际、保留 offset——存量
// 库本就持有这些事件，复位会整文件重放。
func (t *securityEventsTailer) securityEventsGenerationGuard(offset int64) (int64, error) {
	current := db.MetricsDBGeneration()
	if current == "" {
		return offset, nil // 库未装配（测试/嵌入形态）：无代际可判
	}
	if !t.generationLoaded {
		stored, err := securityEventsReadGeneration(t.generationPath)
		if err != nil {
			return offset, fmt.Errorf("security events: read generation marker: %w", err)
		}
		t.generation = stored
		t.generationLoaded = true
	}
	if t.generation == current {
		return offset, nil
	}
	if t.generation != "" {
		var serr error
		if offset, serr = t.securityEventsSwitchMetricsGeneration(current, offset); serr != nil {
			return offset, serr
		}
	}
	if err := securityEventsWriteGeneration(t.generationPath, current); err != nil {
		return offset, fmt.Errorf("security events: persist generation marker: %w", err)
	}
	t.generation = current
	return offset, nil
}

// securityEventsSwitchMetricsGeneration 是「metrics 库代际已变」的全部内存态
// 复位（库隔离重建=新库文件=新代际）：offset/inode 状态、停摆簿记、自动封禁
// 计数、攻击光流环、请求级去重表与 messages_dropped 累计都属于旧库代数，
// 必须在新库上从头重建。返回复位后的 offset（恒为 0）。
func (t *securityEventsTailer) securityEventsSwitchMetricsGeneration(current string, offset int64) (int64, error) {
	Logf("warn", "security events ingestion: metrics database generation changed (%s -> %s), resetting offset %d to 0 (fresh metrics library, re-ingesting audit log)", t.generation, current, offset)
	offset = 0
	t.lastInfo = nil
	t.stallOffset, t.stallCount = 0, 0
	t.failOffset = -1
	// 代际重放会把整份 audit.log 重新过一遍（新库为空，每行
	// RowsAffected=1 全部再喂 autobanBatch）；自动封禁计数器在内存、
	// 不随库重置——不重置则窗口内事件被二次计数，阈值提前达成误封。
	// 重置后由重放按事件时间重建窗口计数，净效果=恰好一次。
	ResetAutobanCounters()
	// 攻击光流环同属「旧库代数」的内存态：新库为空、审计日志将从头重放，
	// 旧环保留会让重放事件与灾前弧重复入环（大屏攻击量翻倍），序号也必须
	// 复位让前端游标随代际重建。
	threatScreenAttackFlowResetRingForGeneration()
	// 去重表与会话绑定：新库为空，整份审计日志重放必须逐条重新落库——
	// 旧库时代的去重记忆会把重放事件当重复丢弃（新库永远缺这些行）。
	// 复位必须在「实例原地」完成：IPC 批摄取、spool 补采与归档补采持有同一个
	// 共享实例指针（securityEventsSharedDedupe），给 live tailer 换一张私有
	// 新表会让这些通道继续用旧代键把重放当重复丢弃，且此后 live 新登记的事件
	// 对它们不可见（跨通道去重重新分裂）。测试/嵌入形态注入的私有表同权清空。
	securityEventsSharedDedupe.reset()
	if d := t.deduper(); d != securityEventsSharedDedupe {
		d.reset()
	}
	// messages_dropped 是「本代审计日志写侧已披露的截断量」的进程级累计：
	// 代际重放会把同一份 audit.log 从头再解析一遍，不清零则历史丢弃量
	// 被二次累计（健康快照虚高到两倍，排障高估写侧截断规模）。重放后
	// 该值应等于单遍真实总量。skippedBytes/Regions 是「曾丢失」事实，
	// 与代数无关，保留。
	securityEventsMessagesDropped.Store(0)
	if err := securityEventsWriteOffset(t.offsetPath, 0); err != nil {
		return offset, fmt.Errorf("security events: persist offset reset for new library generation: %w", err)
	}
	return offset, nil
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
// the scan buffer is sized min(scanLimit） via f.Stat
// — a small residual tail (post hard-kill) previously allocated the full 4MB
// window on every 2s tick decode error (~2MB/s sustained churn). The caller's
// malformed-region decision uses the scanLimit constant, not the buffer size,
// so decisions are unchanged.
func securityEventsFindNextDocument(f securityEventsProcessFile, from int64) (int64, bool, error) {
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
// （上一完整文档的行尾换行等）。跳过窗口含非空白字节时才可能丢
// 数据（进入停等/跳过路径）；纯空白窗口直接推进，与旧语义等价。窗口大于
// 4KB 按非空白保守处理（真实残缺数据不可能被 4KB 纯空白分隔）。
func securityEventsGapAllWhitespace(f securityEventsProcessFile, from, to int64) bool {
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
func securityEventsScanNextDocumentBounded(f securityEventsProcessFile, from, limit int64) (int64, bool, error) {
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

// securityEventsRollupRewriteHook 摄取提交后的 rollup 重固钩子
// （由 main.go 装配 handlers.ThreatRollupRewindTo）。
// 停机/升级积压或轮转补采的插入事件时间可能落在 rollup 已覆盖的分钟区间
// ——warmer 在摄取首 pass 之前已推进水位时，超过 threatRollupRepairMinutes
// 的积压分钟再无重固入口，大屏永久少计。oldestMinute=本批需要重固的最旧
// 分钟（UTC，分钟截断），实现方负责把覆盖水位回退到该分钟之前。
// reclassifyMinutes=本批对**既有行**原地改判（logged→blocked，事件 id 不变）
// 的分钟集合：增量重固只重扫更大的 id，这些分钟必须全量重算；普通插入分钟
// 不需要全量重算（迟到行 id 单调更大，增量即可覆盖，避免积压恢复时把整段
// 覆盖区间退化成全量重扫）。
var securityEventsRollupRewriteHook func(oldestMinute time.Time, reclassifyMinutes []time.Time)

// SetSecurityEventsRollupRewrite 装配覆盖水位回退钩子（nil=停用，供测试）。
func SetSecurityEventsRollupRewrite(fn func(time.Time, []time.Time)) {
	securityEventsRollupRewriteHook = fn
}

// notifySecurityEventsRollupRewrite 在事务提交后通知回退钩子（无插入且无
// 原地改判=零动作）。
func notifySecurityEventsRollupRewrite(minute time.Time, reclassifyMinutes []time.Time) {
	if securityEventsRollupRewriteHook == nil {
		return
	}
	if minute.IsZero() && len(reclassifyMinutes) == 0 {
		return
	}
	securityEventsRollupRewriteHook(minute, reclassifyMinutes)
}

// securityEventsIngestCommits 摄取事务提交次数（测试观测批次节奏——行数批
// 之外的字节触发钉测；生产为单调计数器，无消费方）。
var securityEventsIngestCommits atomic.Int64

// 请求级事件去重：多策略绑定下同一请求会被每个绑定策略的 coraza 实例各写
// 一条审计事务（coraza-caddy 为每次 ServeHTTP 生成独立 transaction_id），
// 逐条入库会让事件列表成对重复、策略/总览/大屏计数与自动封禁阈值按引擎数
// 放大（N 个重叠策略=N 倍）。安全链首（lb_security_blocked_counter）为每个
// 请求注入 X-Lb-Security-Timing-Id，审计行 request.headers 天然收录——同一
// 请求的全部引擎事务共享该值，是请求级自然键。
//
// 归并语义：同一请求只落一条事件；后到的「拦截」覆盖先到的「检测」
// （检测引擎先写 logged、后续引擎才裁决拦截时，对外结论必须是拦截），触发
// 规则/评分/策略归因随之改判为拦截引擎的值（谁拦的必须自洽）；其余重复
// 一律丢弃。缺请求级计时头的审计行（旧版本日志）没有请求级自然键，逐条
// 入库——绝不按「秒+四元组」指纹猜测归并（会把独立请求误并为一条）。
const (
	// securityEventsDedupeWindow 是去重记忆窗口：同一请求的各引擎事务在写侧
	// 相邻（毫秒~秒级），窗口只需覆盖跨秒/跨 pass 的迟到事务。
	securityEventsDedupeWindow = 60 * time.Second
	// securityEventsDedupeMaxEntries 限制常驻去重表规模（每条约数十字节，
	// 26 万条约 10MB）：超限后新键不再登记（既有键照常归并），记忆退化为
	// 「新请求不漏、旧键不淘汰」——淘汰旧键会把后续同键事件重新入库。
	// 代价（已知边界）：同一请求的两个引擎事务若落在不同批次/pass 且键未
	// 登记，会各插一行并各喂一次自动封禁（事件列表成对重复、阈值按引擎数
	// 提前达成——攻击源更早被封，共享 NAT/代理后的正常用户也可能被提前
	// 误封）。触发需持续 >4.4k 事件/秒 60s 以上才把表占满；方向不是安全
	// 削弱，故不做 LRU（会牺牲「旧键不淘汰」这一归并保证），改为在告警中
	// 显式披露后果。
	securityEventsDedupeMaxEntries = 1 << 18
	// securityEventsDedupeSweepEvery 是过期清扫的插入间隔（摊销 O(表长)）。
	securityEventsDedupeSweepEvery = 4096
)

// securityEventsDedupeWindowSec 是去重窗口的秒数（记忆键按秒级 event_time 存储）。
const securityEventsDedupeWindowSec = int64(securityEventsDedupeWindow / time.Second)

// securityEventsDedupeEntry 记一条已落库事件的归并状态。
type securityEventsDedupeEntry struct {
	// transactionID 是首次落库行的幂等键（升级改判按它定位）。
	transactionID string
	// rank 是该行当前的结论强度（securityEventsActionRank）。
	rank uint8
	// atSec 是该行 event_time 的 Unix 秒（过期清扫与分钟回退通知用）。
	atSec int64
	// autobanAction 是该请求实际喂入自动封禁的动作（autobanFed* 常量）：
	// 跨 pass 改判时据此决定是否补喂 blocked——不变量「一请求只计一次」：
	// blocked 已计；logged 在 scope=all 已计、scope=blocked 未计；被信任豁免
	// 的 logged 与阶段门预筛剔除的阶段 1 事件从未计数。空值=重放行（喂入
	// 历史不可知），按「logged 未豁免」处理。
	autobanAction string
}

// 自动封禁喂入动作标记（securityEventsDedupeEntry.autobanAction 的取值域）。
const (
	// autobanFedUnknown 重放行：该 transaction_id 已在库（本表无喂入记录），
	// 喂入历史不可知——保守按「logged 未豁免」处理（scope=all 视为已计）。
	autobanFedUnknown = ""
	// autobanFedLoggedExempt 喂入的 logged 被 rule 级信任豁免（未计数）。
	autobanFedLoggedExempt = "logged-exempt"
	// autobanFedStageFiltered 喂入侧按阶段门预筛剔除（阶段 1 预检事件从未
	// 构造 feed 条目、从未计数）：跨 pass 改判时与信任豁免同判「未计须补」。
	autobanFedStageFiltered = "stage-filtered"
)

// securityEventsRequestDeduper 是跨 pass/跨摄取通道复用的请求级去重表。
// 排他持有期按「批次」划分（见 securityEventsDedupeHold）：批内的
// lookup→落库→record 必须相对其它通道原子，否则 IPC 与 live 同时 miss 会各插
// 一行；批提交后放锁，让补采期间 IPC 主路径不必排队。独立测试仍可直接调用
// lookup/record。
type securityEventsRequestDeduper struct {
	mu         sync.Mutex
	entries    map[uint64]securityEventsDedupeEntry
	maxSec     int64
	sinceSweep int
	capWarned  bool
}

// securityEventsSharedDedupe 是 IPC/spool/live/归档补采的唯一请求级去重表。
// 各通道数据库事务独立，但同一请求只能归并一次。
var securityEventsSharedDedupe = &securityEventsRequestDeduper{}

// securityEventsDedupeHold 把去重表的排他持有期收缩到「批次」粒度，并把
// acquire/release 做成显式状态（避免重复加解锁）。
//
// 跨通道原子性只需要在批内成立：批内 lookup→落库→record 必须相对其它通道
// 串行（否则 IPC 与 live 同时 miss 会各插一行），而批提交后表与库都已完整，
// 下一批重新取锁即可。整段 pass 独占到不了这个效果——活文件单轮上限 5 万条/
// 32MiB、归档补采无界，补采期间 IPC 主路径在 batchIngestState→dedupe 两级锁上
// 排队，写侧 2s 预算一到即整批转 spool（事件不丢，但实时性丢失、spool 增长）。
// 批边界（commit 之后、下一批首个 lookup 之前）是唯一安全释放点；BEGIN/Prepare
// 与解码不触碰去重表，正好让其它通道插入。
//
// 使用约定：任何读/写共享表的动作（lookup、record、pendingDedupe 归并登记）
// 都必须在 acquire 之后发生；批提交后必须 release。
type securityEventsDedupeHold struct {
	table  *securityEventsRequestDeduper
	locked bool
}

func (h *securityEventsDedupeHold) acquire() {
	if h.table == nil || h.locked {
		return
	}
	h.table.mu.Lock()
	h.locked = true
}

func (h *securityEventsDedupeHold) release() {
	if h.table == nil || !h.locked {
		return
	}
	h.locked = false
	h.table.mu.Unlock()
}

// lookup 返回该键在窗口内的既有登记；过期项按未登记处理（旧键不阻塞新请求）。
func (d *securityEventsRequestDeduper) lookup(key uint64, atSec int64) (securityEventsDedupeEntry, bool) {
	entry, ok := d.entries[key]
	if !ok || entry.atSec < atSec-securityEventsDedupeWindowSec {
		return securityEventsDedupeEntry{}, false
	}
	return entry, true
}

// record 登记/更新一条归并状态（窗口外条目按周期清扫）。
func (d *securityEventsRequestDeduper) record(key uint64, entry securityEventsDedupeEntry) {
	if d.entries == nil {
		d.entries = make(map[uint64]securityEventsDedupeEntry)
	}
	if entry.atSec > d.maxSec {
		d.maxSec = entry.atSec
	}
	d.sinceSweep++
	if d.sinceSweep >= securityEventsDedupeSweepEvery {
		d.sweep()
	}
	if _, exists := d.entries[key]; !exists && len(d.entries) >= securityEventsDedupeMaxEntries {
		if !d.capWarned {
			d.capWarned = true
			Logf("warn", "security events ingestion: request dedupe table reached %d entries, new keys are no longer tracked（后果：后续跨批多引擎事务会按引擎数重复入库并计数；既有键照常归并）", securityEventsDedupeMaxEntries)
		}
		return
	}
	d.entries[key] = entry
}

// sweep 丢弃窗口外的陈旧条目（否则长跑进程的去重表按事件量无界增长）。
func (d *securityEventsRequestDeduper) sweep() {
	d.sinceSweep = 0
	cutoff := d.maxSec - securityEventsDedupeWindowSec
	for key, entry := range d.entries {
		if entry.atSec < cutoff {
			delete(d.entries, key)
		}
	}
}

// reset 原地清空归并记忆与标量状态（自带 mu）。语义边界：清空后旧库时代的
// 重复判定全部失效——只允许在「新库为空、整份审计日志将从头重放」的代际切换
// 点（以及测试隔离）调用，否则同一请求的后续引擎事务会各自重新入库。
func (d *securityEventsRequestDeduper) reset() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.entries = nil
	d.maxSec = 0
	d.sinceSweep = 0
	d.capWarned = false
}

// securityEventsRequestDedupeKey 返回请求级去重键：仅 X-Lb-Security-Timing-Id
// 存在时可用（ok=false 表示该审计行没有请求级自然键——旧版本日志或注入失败，
// 按原样逐条入库）。绝不退化为「秒+客户端 IP+方法+URI+规则」指纹：同一秒同源
// 同 URI 同规则的独立请求会被误并为一条（真实洪峰/扫描器复访形态），宁可
// 旧日志不去重，也不丢新事件。
func securityEventsRequestDedupeKey(rec *securityEventRecord) (uint64, bool) {
	if rec.requestKey == "" {
		return 0, false
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(rec.requestKey))
	return h.Sum64(), true
}

// securityEventsActionRank 是结论强度排序：拦截 > 检测 > 其他（未知动作
// 不覆盖既有结论）。
func securityEventsActionRank(action string) uint8 {
	switch action {
	case "blocked":
		return 2
	case "logged":
		return 1
	default:
		return 0
	}
}

// securityEventsRecordSecond 取记录 event_time 的 Unix 秒（解析失败回落当前
// 时刻——仅影响去重窗口定位，不影响落库值）。
func securityEventsRecordSecond(rec *securityEventRecord) int64 {
	if t, err := time.ParseInLocation("2006-01-02 15:04:05", rec.EventTime, time.UTC); err == nil {
		return t.Unix()
	}
	return time.Now().UTC().Unix()
}

// securityEventsProcessFile 是 pass 需要的随机访问/尺寸面；*os.File 与 IPC
// 内存批输入共同实现，避免为每批事件落临时文件。
type securityEventsProcessFile interface {
	io.ReadSeeker
	io.ReaderAt
	Stat() (os.FileInfo, error)
}

// securityEventsTailer streams new audit transactions from the log file,
// persisting its byte offset between passes so restarts resume in place.
type securityEventsTailer struct {
	logPath    string
	offsetPath string
	lastInfo   os.FileInfo
	// lastPassClean 标记上一次 pass 是否无错误结束（空闲 tick 判定
	// 用）：失败 pass的下一 tick 必须重跑——停摆限流告警与
	// DB 重试都依赖 2s 周期持续转动，不得被空闲跳过吞掉。
	lastPassClean bool
	// passBoundHit 上一次 pass 是否因取消或单轮上限提前收尾：此时「无新增
	// 字节 + 上次干净」并不意味着已读到 EOF（还有未摄取内容），空闲 tick
	// 的提前返回必须让位给续跑。
	passBoundHit bool
	// lastIngested 上一 pass 摄取事件数（SecurityEventsPollOnce 消费后清零——
	// SPEC §6.5 业务摘要行：有事件才写任务日志）。
	lastIngested int
	// stallOffset/stallCount 是停等状态：最近一次「残缺文档等待
	// 补写」的偏移与连续失败次数。键为残缺文档起始偏移（每次 pass 从该处
	// 重启，稳定）；偏移推进即数据已补全/已跳过，下次失败自然重置。
	stallOffset int64
	stallCount  int
	// failOffset 是本 pass 中停摆（畸形区）的偏移，仅错误路径设置；
	// 1 表示本次 tick 未触发。
	failOffset  int64
	archivePass bool
	// tailConsumedTo 是归档 pass 主动放弃（不可恢复尾部）时的文件末尾偏移：
	// pass 返回的 offset 停在最后一条成功解码文档末尾，无法区分「等待写入的
	// 半条事务」与「已知不可恢复、整段跳过」——轮转截断判据需要该区分，否则
	// 畸形尾部会让活文件永不截断。0 表示本 pass 未放弃任何尾部字节。
	tailConsumedTo int64
	// 停摆告警限流——上次 warn 的畸形区偏移与时间，偏移不变时每分钟
	// 最多一条 warn，偏移前进即重置立即告警。
	lastWarnOffset int64
	lastWarnTime   time.Time
	// generation/generationLoaded 是 metrics 库代际绑定状态（见
	// securityEventsGenerationGuard）：代际变化即丢弃旧 offset/inode 从头摄取。
	generation       string
	generationLoaded bool
	generationPath   string
	// dedupe 是请求级事件去重表（跨 pass 复用：同一请求的引擎事务被轮转/
	// 停等拆到不同 pass 时仍归并为一条）。指针形态——补采 tailer 直接引用
	// live 表（securityEventsLiveDedupe），map 与清扫水位/告警标志等标量状态
	// 全部共享；按值副本只共享 map，标量写入落在副本上（live 侧切点滞后、
	// 容量告警重复）。首次使用时由 deduper 惰性初始化。
	dedupe *securityEventsRequestDeduper
}

// deduper 返回去重表（nil 时惰性建空表）：保证所有消费点拿到同一实例。
func (t *securityEventsTailer) deduper() *securityEventsRequestDeduper {
	if t.dedupe == nil {
		t.dedupe = &securityEventsRequestDeduper{}
	}
	return t.dedupe
}

// securityEventsLiveDedupe 返回全摄取通道共享的请求级去重表（含清扫水位
// 与告警标志）。并发安全由 securityEventsProcessPass 的整段锁保证。
func securityEventsLiveDedupe() *securityEventsRequestDeduper {
	return securityEventsSharedDedupe
}

func securityEventsNewTailer(logPath, offsetPath string) *securityEventsTailer {
	return &securityEventsTailer{
		logPath:        logPath,
		offsetPath:     offsetPath,
		generationPath: securityEventsGenerationPath(offsetPath),
		failOffset:     -1,
		dedupe:         securityEventsSharedDedupe,
	}
}

// securityEventsTick runs one ingest pass over the audit log.
func (t *securityEventsTailer) securityEventsTick() error {
	return t.securityEventsTickContext(context.Background())
}

// securityEventsTickContext 是带取消的 tick：ctx 取消时 pass 在已提交批次边界
// 收尾返回（偏移持久化、剩余量留下轮），让引擎 Stop/容器停机不被长积压拖过
// 宽限期。无取消语义的调用方（手动兜底轮转、补采）走 context.Background。
func (t *securityEventsTailer) securityEventsTickContext(ctx context.Context) error {
	info, err := os.Stat(t.logPath)
	if errors.Is(err, os.ErrNotExist) {
		created, cerr := os.OpenFile(t.logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if cerr != nil {
			return fmt.Errorf("security events: create audit log: %w", cerr)
		}
		_ = created.Close()
		t.lastInfo = nil
		// 文件缺失=路径迁移/首启动——残留 offset
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
	// 库代际绑定必须先于截断/轮转判定与空闲提前返回：库隔离重建时即使审计
	// 日志无新增字节（空闲 tick），也必须复位 offset 并触发重摄取。
	offset, err = t.securityEventsGenerationGuard(offset)
	if err != nil {
		return err
	}
	// 安全处理耗时：历史侧车退役——耗时随审计行内嵌 lb_timing 字段流转，
	// 本 tick 无需前置加载任何侧车文件；空闲提前返回的消费面语义不变。
	if securityEventsShouldReset(offset, info.Size(), t.lastInfo, info) {
		Logf("info", "security events ingestion: audit log rotated or truncated, resetting offset to 0")
		offset = 0
		if err := securityEventsWriteOffset(t.offsetPath, 0); err != nil {
			return fmt.Errorf("security events: persist reset offset: %w", err)
		}
	} else if t.lastPassClean && !t.passBoundHit && t.lastInfo != nil && info.Size() == t.lastInfo.Size() {
		// 空闲 tick 提前返回——与上一 tick 相比无新增字节且上次
		// pass 干净结束。按上一 tick 的 size 而非 offset 判定：Coraza pretty
		// 格式文件尾恒有 "\n"，稳态 offset = size-1，与 offset 比较永不成立。
		// 跳过省去每 2s 一次的映射加载（3 条主库查询 + 逐行 IDNA）与文件
		// open/seek/残空白解码。lastInfo 照常更新，下一 tick 的截断/轮转判定
		// （size<offset / os.SameFile）不受影响；失败 pass（lastPassClean=false）
		// 不满足条件，重试与限流告警照常；因取消/单轮上限提前收尾的 pass
		// （passBoundHit=true）同样不满足——它没读到 EOF，必须下一 tick 续跑。
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
	newOffset, passErr := t.securityEventsProcessPass(ctx, f, offset, rules, bindings, policyByID)
	if newOffset != offset {
		if werr := securityEventsWriteOffset(t.offsetPath, newOffset); werr != nil {
			passErr = errors.Join(passErr, fmt.Errorf("security events: persist offset: %w", werr))
		}
	}
	t.lastPassClean = passErr == nil
	t.lastInfo = info
	return passErr
}

// securityEventsRollbackLeakedTx 在批次提交失败后补发 ROLLBACK。提交失败时
// database/sql 已把 Tx 标记 done 且不再调用 driver.Rollback：SQLite 的
// deferred 约束/IO 类失败会让底层事务保持活动，连接归还池后仍持写事务
// （写锁滞留，后续 Begin/INSERT 持续 "database is locked"，摄取永久停摆）。
// 语义与 handlers 侧的 rollbackLeakedTx 同源（连接池 LIFO：泄漏连接优先被
// 取到；命中无事务连接时报 "no transaction is active"，重试至命中或用尽）。
func securityEventsRollbackLeakedTx(database *sql.DB) {
	if database == nil {
		return
	}
	for attempt := range 5 {
		if _, err := database.Exec("ROLLBACK"); err == nil {
			return
		} else if !strings.Contains(err.Error(), "no transaction is active") {
			Logf("warn", "security events ingestion: 提交失败后补发 ROLLBACK 失败（第 %d 次）: %v", attempt+1, err)
		}
	}
}

// 单 pass 处理上限（活文件摄取；var 供测试收窄）。长积压（停摆恢复/容器长时间
// 停更）按每 2s 一拍分摊到多轮：一次 tick 占用时间有界，引擎 Stop 不被大
// pass 拖过停机宽限（SIGKILL 会跳过 db.Close/WAL 落盘），轮转也不必等到整个
// 积压清空才发生。archived 补采（.1 / 活文件尾部截断前）**不受**此上限——归档
// 补采失败或部分完成会让轮转侧删除 pending 标记，截断后剩余事件永久丢失。
var (
	securityEventsPassMaxEvents = 50000
	securityEventsPassMaxBytes  = 32 << 20
)

// securityEventsProcessPass decodes and inserts complete transactions from
// offset to EOF, returning the furthest offset safe to persist. A database
// error stops the pass so the next tick retries the same offset; a malformed
// transaction is logged and skipped without aborting the pass. ctx 取消时在
// 当前批次提交后收尾返回（已提交边界随返回值持久化，剩余量留给下一 tick）；
// 活文件 pass 另受单轮事件数/字节数上限约束（archived pass 无界——见上）。
func (t *securityEventsTailer) securityEventsProcessPass(ctx context.Context, f securityEventsProcessFile, offset int64, rules map[string]securityEventsRuleRef, bindings map[string][]int, policyByID map[int]*models.SecurityPolicy) (int64, error) {
	// 去重表按批持有（见 securityEventsDedupeHold）：批提交后释放，下一批首个
	// lookup 重新取锁——补采期间其它通道（IPC/spool）不必为整段 pass 排队。
	hold := &securityEventsDedupeHold{table: t.deduper()}
	defer hold.release()
	// 每个 pass 开始时重置停摆偏移：只有本 pass 实际停摆才会重新赋值，
	// 避免同偏移的新停摆被上一轮 warn 的限流状态吞掉。
	t.failOffset = -1
	// 尾部放弃标记同样按 pass 重置（见 tailConsumedTo）。
	t.tailConsumedTo = 0
	t.passBoundHit = false
	// 每 pass 一次从 host→ref 派生 caddy_id→ref 索引，供 X-LB-Rule-ID
	// 注入头优先归因（O(规则数) 一次性，避免逐事件反查）。
	rulesByID := make(map[string]securityEventsRuleRef, len(rules))
	for _, ref := range rules {
		rulesByID[ref.caddyID] = ref
	}
	trustMatcher := securityEventsBuildTrustMatcher(bindings, policyByID)
	crsExclusionMatcher := securityEventsBuildCRSExclusionMatcher(policyByID)
	// host→rule 映射在 pass 生命周期内稳定（rules/绑定映射本 pass 一次性
	// 加载）——无注入头事件的逐事件 IDNA（CanonicalDomains 含 punycode
	// 分配）在积压补采万级事件时是纯重复劳动，pass 内记忆化（map 随
	// pass 回收，无失效问题）。
	hostRuleMemo := make(map[string]securityEventsRuleRef)
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, fmt.Errorf("security events: seek audit log: %w", err)
	}
	// 半初始化（MetricsDB=nil）时返回显式错误而非 panic；本地句柄
	// 捕获同时避免测试 teardown 并发置 nil 后的 mid-pass 解引用（同
	// securityevents_retention 的本地捕获口径）。
	metricsDB := db.MetricsDB
	if metricsDB == nil {
		return offset, fmt.Errorf("security events: metrics database unavailable")
	}
	committedOffset := offset
	tx, err := metricsDB.Begin()
	if err != nil {
		return offset, fmt.Errorf("security events: begin insert transaction: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO security_events
		(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id, duration_us, precheck_us, request_headers, request_body)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return committedOffset, fmt.Errorf("security events: prepare insert: %w", err)
	}
	decoderStart := offset
	decoder := json.NewDecoder(f)
	const batchSize = 500
	// batchBytes 当前未提交事务内 headers+body 的累计字节：行数批（500）
	// 之外加字节触发（8MiB）——大 body 洪峰下单事务驻留 ~64MiB 字符串 +
	// driver 绑定，抬高进程峰值。8MiB 上界让大 body 批次提前提交。
	const batchByteCap = 8 << 20
	batchBytes := 0
	// batchCount 只控「每 500 条尝试提交」的批次节奏；它必须与 pass 级实际
	// 插入计数分离——旧实现复用一个 count，批次提交清零后 EOF 写出的
	// lastIngested 只剩余数（1000 条→0、501 条→1），PollOnce 的任务日志条数
	// 与「本轮摄取 N 条」展示随之失真。
	batchCount := 0
	// passInsertedTotal 本 pass 实际插入行数（RowsAffected==1 才 +1）：
	// 同一事务重复行/轮转补采重叠/offset 重放的 INSERT OR IGNORE 忽略行
	// 不计入，与自动封禁喂入口径同源。
	passInsertedTotal := 0
	// passBytesTotal 本 pass 已解码的请求头+体字节（单轮上限判据之二）。
	passBytesTotal := 0
	// batchInserted 当前未提交事务内实际插入数；仅在 commit 成功后并入
	// passInsertedTotal。回滚/提交失败的行不得计入任务日志。
	batchInserted := 0
	// 健康丢失量同样属于本事务的提交后效果：忽略行/回滚/提交失败均不得
	// 累加；skip 在解析期只记录 pending，commit 成功才发布到进程级健康位。
	var batchMessagesDropped uint64
	var batchSkippedBytes int64
	var batchSkippedRegions int
	// 任何返回路径都回填本 pass 实际插入数——补采（归档/活文件尾部）
	// 的 delta 摄取同样产生 lastIngested，供任务日志「摄取 N 条」消费。
	defer func() { t.lastIngested = passInsertedTotal }()
	// 自动封禁喂入：本事务批次内成功解析的 WAF 事件随「提交点」喂计数器
	// ——commit 成功后才喂（回滚路径不喂，重试不重复计数）；feedBatch 为 nil
	// 时 autobanObserveBatch 零动作（未启用/从节点等门在函数内收敛）。
	// 按请求级去重键聚合：同一请求的多个引擎事务只喂一条；被批内改判的行
	// 用 autobanIndex 定位并替换原条目（不能一请求喂两次，否则阈值仍被放大）。
	// 阶段过滤在喂入侧按同一判据预筛：阶段 1 预检事件不构造 feed 条目，账目
	// 记 stage-filtered（从未计数）——否则跨批改判会把「被阶段门剔除」误读
	// 成「logged 已计」而漏补喂（WAF 拦截永不计数）。咽喉点的阶段 3 族门
	// （autobanStage3Eligible）保留为第二道闸，判据与本文件归因谓词
	// （securityEventsRuleIsCustomFamily/securityEventsRuleIsCRSFamily）
	// 同源，只收 WAF（阶段 3）事件。
	var autobanBatch []autobanFeedItem
	autobanIndex := map[uint64]int{}
	// pendingDedupe 是本事务内已落库/已改判的归并状态——只在 commit 成功后
	// 并入 tailer 的去重表。批次回滚/提交失败时同一偏移会重试，提前登记会把
	// 重试的行当重复丢弃（事件永久丢失）。
	pendingDedupe := map[uint64]securityEventsDedupeEntry{}
	lookupDedupe := func(key uint64, atSec int64) (securityEventsDedupeEntry, bool) {
		if entry, ok := pendingDedupe[key]; ok && entry.atSec >= atSec-securityEventsDedupeWindowSec {
			return entry, true
		}
		// 共享表读取必须持锁：本批后续的 pendingDedupe 登记与提交后的 record
		// 都依赖「从首次 lookup 到批提交」这段持有期（见 securityEventsDedupeHold）。
		hold.acquire()
		return t.deduper().lookup(key, atSec)
	}
	// crossPassUpgradeNeedsBlockedFeed 判定跨 pass 改判是否需要补喂 blocked
	// （本批缓冲里没有该请求的条目=上一 pass 已提交）。不变量「一请求只计
	// 一次」：已喂 blocked 不再补；被信任豁免与被阶段门预筛剔除的 logged
	// 从未计数必须补；其余 logged 只在 scope=blocked 下未计（scope=all 已计
	// 1，补则双计）。口径每 pass 只读一次库（升级是罕见形态，仍避免逐事件
	// SELECT）。
	crossPassAutobanScopeLoaded := false
	crossPassAutobanScope := ""
	crossPassUpgradeNeedsBlockedFeed := func(prevAction string) bool {
		switch prevAction {
		case "blocked":
			return false
		case autobanFedLoggedExempt, autobanFedStageFiltered:
			return true
		}
		if !crossPassAutobanScopeLoaded {
			cfg, err := GetAutobanConfig()
			if err == nil && cfg.Enabled {
				crossPassAutobanScope = cfg.Scope
			}
			crossPassAutobanScopeLoaded = true
		}
		return crossPassAutobanScope == "blocked"
	}
	// 攻击流光流批次：与日志事务提交点对齐，回滚路径不喂。
	var attackFlowBatch []threatScreenAttackFlowItem
	// 本批光流条目按请求去重键的索引：改判（logged→blocked）时同批条目
	// 必须原地换 action/规则——否则大屏光流显示「检测」而事件列表显示
	// 「拦截」。跨批形态已在原 pass 提交，无法回改（见改判分支注释）。
	attackFlowIndex := map[uint64]int{}
	// 本批实际插入事件的最旧分钟（UTC）——提交成功后通知 rollup
	// 回退钩子（积压事件落在已覆盖分钟区间时重固，防止大屏永久少计）。
	var batchOldestMinute time.Time
	// 本批对既有行原地改判（UPDATE，事件 id 不变）的分钟集合：这些分钟
	// 必须全量重算 rollup 维度，而普通插入分钟走增量即可。
	var batchReclassifyMinutes map[time.Time]struct{}
	markReclassifyMinute := func(m time.Time) {
		if batchReclassifyMinutes == nil {
			batchReclassifyMinutes = map[time.Time]struct{}{}
		}
		batchReclassifyMinutes[m] = struct{}{}
	}
	commit := func() error {
		if err := tx.Commit(); err != nil {
			// 提交失败必须补发 ROLLBACK（见 securityEventsRollbackLeakedTx）：
			// 泄漏的写事务会让后续 tick 永久 "database is locked"。
			securityEventsRollbackLeakedTx(metricsDB)
			return err
		}
		securityEventsIngestCommits.Add(1)
		passInsertedTotal += batchInserted
		batchInserted = 0
		securityEventsMessagesDropped.Add(batchMessagesDropped)
		if batchSkippedBytes > 0 || batchSkippedRegions > 0 {
			securityEventsRecordSkips(batchSkippedBytes, batchSkippedRegions)
		}
		batchMessagesDropped = 0
		batchSkippedBytes = 0
		batchSkippedRegions = 0
		// 归并状态并入共享表必须持锁（批内 lookup 已取锁，此处 acquire 对已持有
		// 的形态是幂等 no-op，同时把「record 必须在持有期内」钉在本函数内）。
		hold.acquire()
		for key, entry := range pendingDedupe {
			t.deduper().record(key, entry)
		}
		pendingDedupe = map[uint64]securityEventsDedupeEntry{}
		autobanObserveBatch(autobanBatch)
		autobanBatch = nil
		autobanIndex = map[uint64]int{}
		threatScreenAttackFlowRecordBatch(attackFlowBatch)
		attackFlowBatch = nil
		attackFlowIndex = map[uint64]int{}
		reclassifyMinutes := make([]time.Time, 0, len(batchReclassifyMinutes))
		for m := range batchReclassifyMinutes {
			reclassifyMinutes = append(reclassifyMinutes, m)
		}
		notifySecurityEventsRollupRewrite(batchOldestMinute, reclassifyMinutes)
		batchOldestMinute = time.Time{}
		batchReclassifyMinutes = nil
		return nil
	}
	for {
		// 取消门在每个文档边界：已解码未提交的批次先提交（offset 随返回值
		// 持久化），剩余文档留给下一轮——停机宽限内可停，且不产生半批丢失。
		if ctxErr := ctx.Err(); ctxErr != nil {
			stmt.Close()
			if cerr := commit(); cerr != nil {
				return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
			}
			t.passBoundHit = true
			return offset, nil
		}
		var raw json.RawMessage
		err := decoder.Decode(&raw)
		if errors.Is(err, io.EOF) {
			stmt.Close()
			if cerr := commit(); cerr != nil {
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
				// 错误会让 pending 标记永不清除、轮转永久停摆，故改为有界
				// scan-to-EOF 找下一个 "\n{"：找到则跳过畸形区（一条 error 日志）
				// 继续摄取其后事件；找不到则记一次 error 日志并结束本 pass（该
				// 区域不可恢复，但不再阻塞轮转）。
				if info, serr := f.Stat(); serr == nil && decoderStart+decoder.InputOffset()+securityEventsScanWindowLimit < info.Size() {
					if !t.archivePass {
						_ = stmt.Close()
						if cerr := commit(); cerr != nil {
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
						if cerr := commit(); cerr != nil {
							return committedOffset, fmt.Errorf("security events: commit inserts: %w", cerr)
						}
						// 不可恢复尾部=该段事件永久丢弃——计入跳过健康信号
						// （跳过≠失败返回，不登记则本轮三面仍显示 healthy）。
						// 字节口径=[offset, EOF)：offset=最后一条成功摄取文档的末尾
						// （每成功解码一条即推进到 docEnd）；decoderStart=本次解码流
						// 起点（pass 开始/重同步后更新）——二者仅在 pass 起点与刚
						// 重同步后相等，不得互替：用 decoderStart 会低报丢弃字节。
						// 解码已消费的前缀（decoder.InputOffset()）仍属被丢弃的畸形
						// 文档字节，必须计入。
						// malformedStart 仅用于日志定位（畸形区起点=decoderStart+已
						// 消费前缀），不参与健康计数字节口径。
						malformedStart := decoderStart + decoder.InputOffset()
						securityEventsRecordSkips(info.Size()-offset, 1)
						Logf("error", "security events ingestion: unrecoverable unreadable audit data at offset %d in archive, ending pass", malformedStart)
						// 尾部整段放弃：这些字节不会再被摄取，轮转截断判据按
						// 「已处理到文件末尾」计（否则畸形尾部让活文件永不截断）。
						t.tailConsumedTo = info.Size()
						return offset, nil
					}
					batchSkippedBytes += next - offset
					batchSkippedRegions++
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
				if cerr := commit(); cerr != nil {
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
			// （2026-09-18 实证）：解码失败最常见的形态不是崩溃残片，
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
					if cerr := commit(); cerr != nil {
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
			batchSkippedBytes += next - offset
			batchSkippedRegions++
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
			batchSkippedBytes += docEnd - offset
			batchSkippedRegions++
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
				if memo, hit := hostRuleMemo[rec.Host]; hit {
					rule = memo
				} else {
					rule = securityEventsMapHost(rec.Host, rules)
					hostRuleMemo[rec.Host] = rule
				}
			}
			policyID, policyName := securityEventsAttributePolicyWithExclusions(rule.caddyID, rec.RuleTriggered, rec.Action, rec.ClientIP, policyByID, bindings, crsExclusionMatcher)
			// 链式起始条/OR 计分分支的 raw 不含评分字面量，按发射 id 回查父规则
			// cr.Score 补齐（否则事件日志评分列/大屏危险等级显示 0=非评分事件）。
			if rec.AnomalyScore == 0 && rec.customRuleScoreFallback {
				rec.AnomalyScore = securityEventsChainedCustomRuleScore(rec.RuleTriggered, policyByID, policyID)
			}
			dedupeKey, dedupeable := securityEventsRequestDedupeKey(rec)
			atSec := securityEventsRecordSecond(rec)
			var prev securityEventsDedupeEntry
			duplicate := false
			if dedupeable {
				prev, duplicate = lookupDedupe(dedupeKey, atSec)
			}
			if duplicate {
				// 同一请求的后续引擎事务：不再落第二条事件。后到的拦截结论
				// 覆盖先到的检测行（谁拦的、按什么规则、多少分同步改判）；
				// 其余重复（同结论/更弱结论）直接丢弃。
				if securityEventsActionRank(rec.Action) > prev.rank {
					if uerr := securityEventsUpgradeDedupedEvent(tx, prev.transactionID, rec, rule, policyID, policyName); uerr != nil {
						_ = stmt.Close()
						_ = tx.Rollback()
						return committedOffset, uerr
					}
					prevAutobanAction := prev.autobanAction
					prev.rank = securityEventsActionRank(rec.Action)
					prev.autobanAction = rec.Action
					pendingDedupe[dedupeKey] = prev
					// 本批已缓冲的自动封禁条目同步改判（不追加第二条——
					// 一请求只喂一次，否则阈值放大依旧）。
					if idx, ok := autobanIndex[dedupeKey]; ok {
						autobanBatch[idx].Action = rec.Action
						autobanBatch[idx].RuleTriggered = rec.RuleTriggered
						autobanBatch[idx].TrustExempt = false
					} else if crossPassUpgradeNeedsBlockedFeed(prevAutobanAction) {
						// 跨 pass 改判：原 pass 的 feed 早已提交，不在本批缓冲里。
						// 首轮 logged 在 scope=blocked 下未计数（或被信任豁免而
						// 从未计数）时补喂一条 blocked，否则该请求永远达不到阈值
						// ——库内已是 blocked 而计数为 0，UI 无迹可查。
						autobanBatch = append(autobanBatch, autobanFeedItem{
							IP:            rec.ClientIP,
							Action:        rec.Action,
							RuleTriggered: rec.RuleTriggered,
							At:            time.Unix(prev.atSec, 0).UTC(),
							TrustExempt:   false,
						})
					}
					// 同批光流条目同步改判：大屏光流按 action 着色/计拦截，
					// 保留首次写入的 logged 会让同一请求在光流显示「检测」而
					// 事件行显示「拦截」。跨批形态原条目已在上一 pass 落入
					// 环形缓冲——本批索引看不到它，故按请求去重键交环内索引做
					// 原地改判（保留原序号，消费者游标不回退），只有环内确实没有
					// 该键（logged 且爬虫放行族=不计攻击、采样闸门当时关闭、环已
					// 淘汰）才按改判后的 blocked 补入一条——否则事件行/拦截率按
					// blocked 计而光流永远缺该拦截弧（同屏两面不一致）。
					// 是否入环由 recordBatch 的采样门决定，产生侧不得按「当下
					// 档位」预筛：租约可能在首轮入环后关闭（大屏关闭/心跳过期），
					// 此时环内还留着 logged 旧弧——预筛会连改判项一起丢掉，消费者
					// 下次 since=0 读到旧结论且不自愈。inPlace 项不消耗采样配额，
					// 档位为 0 且环内无该键时由 recordBatch 丢弃（不入环）。
					if idx, ok := attackFlowIndex[dedupeKey]; ok {
						attackFlowBatch[idx].action = rec.Action
						attackFlowBatch[idx].ruleTriggered = rec.RuleTriggered
					} else if SecurityEventCountsAsAttack(rec.Action, rec.RuleTriggered) &&
						strings.TrimSpace(rec.ClientIP) != "" && !IsReservedClientIP(rec.ClientIP) {
						attackFlowIndex[dedupeKey] = len(attackFlowBatch)
						attackFlowBatch = append(attackFlowBatch, threatScreenAttackFlowItem{
							at:            time.Unix(prev.atSec, 0).UTC(),
							clientIP:      rec.ClientIP,
							action:        rec.Action,
							ruleTriggered: rec.RuleTriggered,
							key:           dedupeKey,
							inPlace:       true,
						})
					}
					// 该分钟 rollup 可能已按 logged 固化：重固让 action/rule
					// 维度与改判后的行一致。原地 UPDATE 不改 id，增量重固扫不到
					// ——按「原地改判」来源上报，实现方对该分钟走全量重算。
					m := time.Unix(prev.atSec, 0).UTC().Truncate(time.Minute)
					markReclassifyMinute(m)
					if batchOldestMinute.IsZero() || m.Before(batchOldestMinute) {
						batchOldestMinute = m
					}
				}
			} else {
				res, ierr := stmt.Exec(rec.EventTime, rule.caddyID, policyID, rec.ClientIP, rec.Method, rec.URI,
					rec.EventType, rec.RuleTriggered, rec.RuleMsg, rec.Action, rec.AnomalyScore,
					rule.name, policyName, rec.TransactionID, rec.DurationUs, rec.PrecheckUs, rec.RequestHeaders, rec.RequestBody)
				if ierr != nil {
					_ = stmt.Close()
					_ = tx.Rollback()
					return committedOffset, fmt.Errorf("security events: insert event: %w", ierr)
				}
				// INSERT OR IGNORE 对重复 transaction_id 静默跳过——必须取
				// RowsAffected 区分「实际插入」与「忽略」，否则轮转补采/offset 重放
				// 把同一事件重复喂自动封禁计数器（阈值提前达成）。RowsAffected 失败
				// 属于未知写入结果：回滚本批、偏移不推进，下个 tick 以同一偏移重试
				// （保留批次重试语义，不猜测结果）。
				affected, aerr := res.RowsAffected()
				if aerr != nil {
					_ = stmt.Close()
					_ = tx.Rollback()
					return committedOffset, fmt.Errorf("security events: insert result: %w", aerr)
				}
				// entryAutobanAction 记录本行实际喂入的动作（跨 pass 改判决策依据）。
				entryAutobanAction := autobanFedUnknown
				if affected == 1 {
					batchMessagesDropped += uint64(rec.messagesDropped)
					eventAt, _ := time.ParseInLocation("2006-01-02 15:04:05", rec.EventTime, time.UTC)
					if eventAt.IsZero() {
						eventAt = time.Now().UTC()
					}
					// 咽喉点判据逐条回写账目：阶段 3 族事件照旧喂入；阶段 1
					// 预检事件不构造 feed 条目（咽喉点本也会剔除），账目标记
					// stage-filtered——跨批/批内改判升级为 blocked 时据此补喂
					// 且补喂条目必过阶段门（改判结论来自 WAF 引擎）。
					if autobanStage3Eligible(rec.RuleTriggered) {
						trustExempt := rec.Action == "logged" && trustMatcher.trusted(rule.caddyID, rec.ClientIP)
						if dedupeable {
							autobanIndex[dedupeKey] = len(autobanBatch)
						}
						autobanBatch = append(autobanBatch, autobanFeedItem{
							IP:            rec.ClientIP,
							Action:        rec.Action,
							RuleTriggered: rec.RuleTriggered,
							At:            eventAt,
							TrustExempt:   trustExempt,
						})
						entryAutobanAction = rec.Action
						if trustExempt {
							entryAutobanAction = autobanFedLoggedExempt
						}
					} else {
						entryAutobanAction = autobanFedStageFiltered
					}
					// 光流环只收「计入攻击」的事件：爬虫豁免是 pass,log
					// 放行（每个已验证爬虫请求都是一条 logged 事件），不过滤
					// 会把 Googlebot/Bingbot 画成攻击弹道，与同屏 feed/总量/
					// 拦截率（均已按同谓词排除）口径分叉。
					// 保留地址（内网/回环/文档示例）同样在**入环前**排除：同屏
					// 其它攻击面全在入口侧排除，唯独本环原先在端点出口才丢——
					// 高频内网扫描会占满环与单轮 limit，把真实外网攻击弧挤出
					// 窗口（静默表现为「攻击变少」）。
					if threatScreenAttackFlowSampleN.Load() > 0 && SecurityEventCountsAsAttack(rec.Action, rec.RuleTriggered) &&
						strings.TrimSpace(rec.ClientIP) != "" && !IsReservedClientIP(rec.ClientIP) {
						// key 携带请求去重键（不可去重时为 0）：跨批改判据此在环内
						// 原地更新本条目，而不是再追加一条。
						var flowKey uint64
						if dedupeable {
							flowKey = dedupeKey
							attackFlowIndex[dedupeKey] = len(attackFlowBatch)
						}
						attackFlowBatch = append(attackFlowBatch, threatScreenAttackFlowItem{
							at:            eventAt,
							clientIP:      rec.ClientIP,
							action:        rec.Action,
							ruleTriggered: rec.RuleTriggered,
							key:           flowKey,
						})
					}
					batchInserted++
					// 记录本批最旧插入分钟（event_time 恒 UTC 墙钟串；
					// 解析失败跳过——仅影响回退精度，不影响摄取）。
					if et, terr := time.ParseInLocation("2006-01-02 15:04:05", rec.EventTime, time.UTC); terr == nil {
						m := et.Truncate(time.Minute)
						if batchOldestMinute.IsZero() || m.Before(batchOldestMinute) {
							batchOldestMinute = m
						}
					}
				}
				// 登记归并状态（忽略行=重放，行已在库，同样登记以便同请求的
				// 后续引擎事务丢弃/改判）；commit 成功才并入 tailer 的去重表。
				if dedupeable {
					pendingDedupe[dedupeKey] = securityEventsDedupeEntry{
						transactionID: rec.TransactionID,
						rank:          securityEventsActionRank(rec.Action),
						atSec:         atSec,
						autobanAction: entryAutobanAction,
					}
				}
			}
			batchCount++
			batchBytes += rec.rowBytes()
			passBytesTotal += rec.rowBytes()
			if batchCount >= batchSize || batchBytes >= batchByteCap {
				stmt.Close()
				if cerr := commit(); cerr != nil {
					return committedOffset, fmt.Errorf("security events: commit batch: %w", cerr)
				}
				// 批已提交、归并状态已落表：释放去重锁。此后到下一批首个
				// lookup 之间的 BEGIN/Prepare 与解码都不触碰共享表，其它通道
				// （IPC/spool）可在此窗口插入，而不是为整段 pass 排队到 2s 超时。
				hold.release()
				committedOffset = docEnd
				// 单轮上限（仅活文件 pass）：已达上限即收尾，剩余量留下轮
				// ——offset 已推进、行幂等，续跑无重复。失败/取消优先于上限
				// 判定（上面已返回）。
				if !t.archivePass && (passInsertedTotal >= securityEventsPassMaxEvents || passBytesTotal >= securityEventsPassMaxBytes) {
					t.passBoundHit = true
					return docEnd, nil
				}
				tx, err = metricsDB.Begin()
				if err != nil {
					return committedOffset, fmt.Errorf("security events: begin batch transaction: %w", err)
				}
				stmt, err = tx.Prepare(`INSERT OR IGNORE INTO security_events
				(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id, duration_us, precheck_us, request_headers, request_body)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
				if err != nil {
					tx.Rollback()
					return committedOffset, fmt.Errorf("security events: prepare batch insert: %w", err)
				}
				batchCount = 0
				batchBytes = 0
			}
		}
		offset = docEnd
	}
}

// securityEventsUpgradeDedupedEvent 把同一请求已落库的检测行改判为拦截
// 结论：action/评分/触发规则/策略归因整体替换为拦截引擎的值（展示必须自洽
// ——谁拦的、按什么规则、多少分）。请求头与请求体保留首次落库的快照：后续
// 引擎未开请求体记录时不该把已有请求体清空。幂等（重放时重复执行同样值）。
//
// 归因列（rule_caddy_id/rule_name/policy_id/policy_name）采用保留式赋值：
// 结论列必须覆盖，但归因缺失时不得反向清空既有归因——第二引擎事务若没有
// 注入 X-LB-Rule-ID（或绑定在发射后被删），零值归因会把已落库的规则/策略
// 覆盖成空，「blocked + 无规则 + 无策略」的事件从按策略/规则的 24h 计数与
// 检索中消失。空归因=未知，不是「没有归因」。
func securityEventsUpgradeDedupedEvent(tx *sql.Tx, transactionID string, rec *securityEventRecord, rule securityEventsRuleRef, policyID int, policyName string) error {
	if _, err := tx.Exec(`UPDATE security_events
		SET action=?, anomaly_score=?,
			rule_caddy_id=COALESCE(NULLIF(?, ''), rule_caddy_id),
			rule_triggered=?,
			rule_msg=?,
			rule_name=COALESCE(NULLIF(?, ''), rule_name),
			policy_id=CASE WHEN ?>0 THEN ? ELSE policy_id END,
			policy_name=COALESCE(NULLIF(?, ''), policy_name),
			duration_us=?, precheck_us=?
		WHERE transaction_id=?`,
		rec.Action, rec.AnomalyScore, rule.caddyID, rec.RuleTriggered, rec.RuleMsg, rule.name,
		policyID, policyID, policyName, rec.DurationUs, rec.PrecheckUs, transactionID); err != nil {
		return fmt.Errorf("security events: upgrade merged event: %w", err)
	}
	return nil
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
// 索引保证与 tick 已摄取内容幂等。返回实际插入条数（补采结果须计入
// ingestion 任务日志「摄取 N 条」，此前被丢弃）。
func securityEventsIngestRotatedDelta(persistedOffset int64) (int, error) {
	if db.DB == nil || db.MetricsDB == nil {
		return 0, nil
	}
	archive := auditLogPath + ".1"
	info, err := os.Stat(archive)
	if err != nil {
		return 0, fmt.Errorf("security events: stat rotated archive: %w", err)
	}
	if info.Size() <= persistedOffset {
		return 0, nil // 归档未包含超出已摄取偏移的内容
	}
	n, _, err := securityEventsIngestDeltaFrom(archive, persistedOffset, true)
	return n, err
}

// securityEventsIngestDepsReady 报告补采所需的数据库句柄是否就绪。
// securityEventsIngestDeltaFrom 在依赖缺失时返回 (0, nil)——「未补采」不得被
// 当作「补采成功」：轮转侧据此删除 pending 安全网会让该窗口的事件永久丢失，
// 故删除标记前必须先问本函数。
func securityEventsIngestDepsReady() bool {
	return db.DB != nil && db.MetricsDB != nil
}

// securityEventsIngestDeltaFrom 从 path 的 from 偏移补采到 EOF 的安全事件：
// 解析与 INSERT OR IGNORE 插入复用 securityEventsProcessPass，transaction_id
// 唯一索引保证幂等。轮转后的 .1 归档（securityEventsIngestRotatedDelta）与
// copy 完成后 truncate 前的活文件尾部（rotateAuditLogIfNeeded）共用此路径。
// archive=true 表示归档补采（.1 / pending 重试）：文件大小有界且不再增长，
// 畸形区走 scan-to-EOF 恢复而非报错（见 securityEventsProcessPass）。
// 返回实际插入条数与摄取到达偏移 reached：reached 是本 pass 已提交文档的末尾
// （归档 pass 判定不可恢复而跳过的尾部按文件末尾计），轮转截断判据以它为
// 「已摄取到哪里」的唯一基准——不得改用调用前后的文件大小比较（持续写入下
// 会把「已摄取但文件变大」误判为「还有未摄取字节」）。
func securityEventsIngestDeltaFrom(path string, from int64, archive bool) (int, int64, error) {
	if db.DB == nil || db.MetricsDB == nil {
		return 0, from, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return 0, from, fmt.Errorf("security events: open delta source: %w", err)
	}
	defer f.Close()
	// 补采路径的耗时随审计行内嵌 lb_timing 字段自带（侧车退役，
	// 的「补采也需加载侧车」前置不再需要）。
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		return 0, from, err
	}
	t := securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
	t.archivePass = archive
	// 去重记忆跨路径共享：补采区间（.1 / truncate 前尾部）与 live tick 可能
	// 切开同一请求的两个引擎事务（预检在 live、WAF 在轮转边界后）——各自空表
	// 时第二条会以自身 transaction_id 再插一行（唯一索引不冲突），一次请求落
	// 两行事件且 blocked/logged 结论并存。直接复用 live tailer 的去重表：
	// 补采仅经 securityEventsPollOnce 持 securityEventsPollState 的同一
	// goroutine（rotateAuditLogIfNeeded）触发，故无并发写；独立调用（测试/
	// 无 live tailer）回退空表保持旧语义。
	t.dedupe = securityEventsLiveDedupe()
	// 补采（归档有界）不接收调用方取消语义：部分摄取会让轮转侧按成功删除
	// pending 标记/截断活文件，剩余事件永久丢失——必须跑到存档末尾。
	reached, passErr := t.securityEventsProcessPass(context.Background(), f, from, rules, bindings, policyByID)
	if t.tailConsumedTo > reached {
		reached = t.tailConsumedTo
	}
	return t.lastIngested, reached, passErr
}

// securityEventsRateLimitedWarn 输出 tick 失败告警并对停摆错误（畸形区）
// 限流：同一畸形区偏移每分钟最多一条 warn（tailer 记录 lastWarnOffset +
// lastWarnTime），偏移前进即重置立即告警；其他错误照常输出。
func (t *securityEventsTailer) securityEventsRateLimitedWarn(err error) {
	if t.failOffset < 0 || !strings.Contains(err.Error(), "scan window at offset") {
		// 其他错误同样按同消息 60s 限流（与畸形区同窗口）——审计目录缺失等
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

// ensureAuditLogDir 创建审计日志所在目录（os.MkdirAll，幂等）。启动时调用
// 一次——此前目录缺失时 tick 每 2s 建 audit.log 失败、永久刷屏且从不建目录。
func ensureAuditLogDir() error {
	return os.MkdirAll(filepath.Dir(auditLogPath), 0o755)
}

// EnsureWafAuditDir 是 ensureAuditLogDir 的导出版——
// coraza v3.7.0 NewWAF→serialWriter.Init OpenFile 不建父目录，审计日志目录缺失
// =Provision 致命=/load 拒收。main.go 必须在首次 ApplyConfigOnStartup 前调用。
func EnsureWafAuditDir() error {
	return ensureAuditLogDir()
}

// securityEventsPollState 引擎驱动的单轮摄取状态（tailer 跨轮复用——
// offset 连续性依赖同一 tailer 实例）。
var securityEventsPollState struct {
	sync.Mutex
	tailer *securityEventsTailer
	inited bool
}

const securityEventsIngestionFailureThreshold = 3

// SecurityEventsIngestionStatus 是采集 daemon 的进程内健康快照（不改变任务
// 调度状态）：连续非停等 tick 失败达到阈值、采集任务未运行、审计写侧累计
// 失败达阈值、或窗口内有畸形区跳过（事件永久丢弃）时健康位为 false，
// 供事件列表/安全总览/威胁大屏三处同源提示。
type SecurityEventsIngestionStatus struct {
	Observed            bool   `json:"observed"`
	Healthy             bool   `json:"healthy"`
	ConsecutiveFailures int    `json:"consecutive_failures"`
	LastError           string `json:"last_error,omitempty"`
	LastErrorAt         string `json:"last_error_at,omitempty"`
	LastSuccessAt       string `json:"last_success_at,omitempty"`
	// TaskState/TaskRunning 是 taskengine 视角的采集任务实态（running/
	// restarting/stopped/unknown，判据单源见 securityEventsIngestionTaskState）：
	// 该任务拥有「尾读存量 + spool 补采 + 审计日志轮转 + 健康记账」，任务停用/
	// 未运行时这些后台通道停摆（健康位不得继续显示 healthy），但实时 IPC 主
	// 路径不经调度、事件仍会入库——文案不得据此断言「事件不再更新」。
	// restarting 是异常退出后的有界退避重拉窗口（LoopOn 仍 true），自愈通道
	// 仍在，不降级。
	TaskState   string `json:"task_state"`
	TaskRunning bool   `json:"task_running"`
	// Writer* 是审计写侧（caddygeoip 插件）失败/丢弃计数——经插件侧车文件
	// 跨进程读取，累计自本进程启动（插件重启的计数回落按新基线续累计）。
	WriterDropped  uint64 `json:"writer_dropped"`
	WriterIOErrors uint64 `json:"writer_io_errors"`
	// WriterFormatErrors 是写侧 formatter.Format 失败累计（侧车 format_errors）：
	// 与 io_errors 分开表达——前者是代码/契约缺陷（如 coraza/custom formatter
	// 契约破裂），后者是磁盘/权限故障，两者排障方向不同。格式化失败的行整行
	// 未落盘，因此与丢弃/写盘错误共用失败窗口降级判据。
	WriterFormatErrors  uint64 `json:"writer_format_errors"`
	WriterDegraded      bool   `json:"writer_degraded"`
	WriterLastFailureAt string `json:"writer_last_failure_at,omitempty"`
	// MessagesDropped 是写侧因单行上限截断的规则命中消息累计（审计行顶层
	// messages_dropped）：事件本身在库，但部分命中明细永久缺失（如一次命中
	// 数十条规则时的尾部条目）。单独披露以免被读成「事件没丢就没损失」。
	MessagesDropped uint64 `json:"messages_dropped"`
	// WriterStatsUnavailable：侧车计数文件连续读取/解析失败达阈值——写侧
	// 丢弃/IO 计数对外不可用（磁盘满/目录只读正是侧车要覆盖的故障形态），
	// 计数恒 0 不代表无丢弃。
	WriterStatsUnavailable bool `json:"writer_stats_unavailable,omitempty"`
	// Skipped* 是摄取侧「畸形区跳过」累计（跳过=该段审计数据的事件永久
	// 丢弃）：与写侧计数同为一等健康信号——窗口内（15min）有跳过即降级，
	// 累计量供事件列表/总览/大屏三面披露与任务日志边沿留痕。
	SkippedBytes   uint64 `json:"skipped_bytes"`
	SkippedRegions uint64 `json:"skipped_regions"`
	LastSkipAt     string `json:"last_skip_at,omitempty"`
	// DataLoss 与 WriterDegraded 分离表达：degraded 只回答「当前窗口内是否
	// 仍在失败」（窗口滑出即恢复），data_loss 回答「本进程启动以来是否曾
	// 永久丢失事件」（写侧丢弃/写盘错误累计>0 或畸形区跳过>0）——丢失事实
	// 不随窗口滑出而消失，进程重启或测试重置才清零。前端据此区分
	// 「正在失败」与「曾丢失 N 条」两类文案。
	DataLoss bool `json:"data_loss"`
	// RotationDeferred 表示最近一轮审计日志轮转因「活文件尾部尚未摄取」顺延：
	// 归档已就位而活文件未截断，磁盘空间暂未回收。它不是采集失败——本轮
	// 采集与入库都成功、事件零丢失，故不计入 ConsecutiveFailures 也不降级
	// Healthy；三面据此把「容量延迟」与「采集异常」分开呈现。
	RotationDeferred       bool   `json:"rotation_deferred"`
	RotationLastDeferredAt string `json:"rotation_last_deferred_at,omitempty"`
	// Spool* 是 B 形态（IPC 主路径 + fallback spool）的待补采状态：
	// 写侧 IPC 失败时把事件落 spool，面板由采集任务补采入库。这些条目仍在
	// 磁盘上、可入库，属「待补采」而非永久丢失（不得据此置 DataLoss）；
	// 但目录不可读 / 已达上限（写侧很可能正在丢弃新事件）/ 补采连续失败
	// 达阈值时健康位降级——静默的积压会把「主路径坏了」伪装成一切正常。
	SpoolDir                 string `json:"spool_dir,omitempty"`
	SpoolFiles               int    `json:"spool_files"`
	SpoolPendingEntries      int64  `json:"spool_pending_entries"`
	SpoolPendingBytes        int64  `json:"spool_pending_bytes"`
	SpoolLimitEntries        int64  `json:"spool_limit_entries,omitempty"`
	SpoolLimitBytes          int64  `json:"spool_limit_bytes,omitempty"`
	SpoolSaturated           bool   `json:"spool_saturated,omitempty"`
	SpoolUnavailable         bool   `json:"spool_unavailable,omitempty"`
	SpoolConsecutiveFailures int    `json:"spool_consecutive_failures,omitempty"`
	SpoolLastError           string `json:"spool_last_error,omitempty"`
	SpoolLastErrorAt         string `json:"spool_last_error_at,omitempty"`
}

var securityEventsIngestionHealth struct {
	sync.Mutex
	status SecurityEventsIngestionStatus
}

func securityEventsRecordPollResult(err error) {
	if errors.Is(err, errSecurityEventsStalled) {
		// 残缺文档是正常等待写侧补全的瞬态，不进入失败状态。
		return
	}
	now := time.Now().UTC()
	securityEventsIngestionHealth.Lock()
	defer securityEventsIngestionHealth.Unlock()
	status := &securityEventsIngestionHealth.status
	status.Observed = true
	if errors.Is(err, errAuditRotationDeferred) {
		// 轮转顺延不是采集失败：本轮采集/入库已成功，只有「活文件截断」被推到
		// 下一轮（空间暂未回收）。计入连续失败会在持续写入期把三面健康位误报
		// 成采集异常，并让真实失败被容量噪音掩盖——按成功 tick 记账，另记延迟
		// 状态供三面显示「轮转延迟」。
		status.ConsecutiveFailures = 0
		status.Healthy = true
		status.LastSuccessAt = now.Format(time.RFC3339)
		status.LastError = ""
		status.LastErrorAt = ""
		status.RotationDeferred = true
		status.RotationLastDeferredAt = now.Format(time.RFC3339)
		return
	}
	if err == nil {
		status.ConsecutiveFailures = 0
		status.Healthy = true
		status.LastSuccessAt = now.Format(time.RFC3339)
		// 成功 tick 必须清空错误字段：保留旧 last_error/last_error_at 会让
		// healthy=true 的快照同时带「健康」与「报错」矛盾信息（三面同源消费）。
		status.LastError = ""
		status.LastErrorAt = ""
		// 本轮轮转已不再顺延（空间回收完成或无需轮转）：延迟标记随之复位。
		status.RotationDeferred = false
		return
	}
	status.ConsecutiveFailures++
	status.Healthy = status.ConsecutiveFailures < securityEventsIngestionFailureThreshold
	status.LastError = err.Error()
	status.LastErrorAt = now.Format(time.RFC3339)
}

// SecurityEventsIngestionHealthSnapshot 返回一致的健康快照（事件列表/安全
// 总览/威胁大屏三处 API 同源消费）：tick 记账结果叠加任务实态与审计写侧计数。
func SecurityEventsIngestionHealthSnapshot() SecurityEventsIngestionStatus {
	securityEventsIngestionHealth.Lock()
	status := securityEventsIngestionHealth.status
	securityEventsIngestionHealth.Unlock()
	return securityEventsOverlayIngestionHealth(status)
}

// securityEventsIngestionTaskID 是采集任务在 taskengine 的注册 ID（单一源：
// 任务注册与健康位判据共用）。
const securityEventsIngestionTaskID = "security-events-ingestion"

// securityEventsIngestionTaskHealthState 采集任务实态（健康位与自动封禁
// 喂入侧共享的唯一判据）：
//   - running：daemon Run 存活；
//   - restarting：调度仍开（LoopOn=true）但 Run 不在——异常退出后的有界退避
//     重拉窗口（1s/5s/30s 级）。自愈通道仍在，不得按「已停止」降级，否则每次
//     短暂重拉都会瞬时把三面健康位打成不健康并触发 autoban feed_degraded；
//   - stopped：调度关闭（用户停止）或异常自愈预算用尽（引擎同时置
//     RestartExhausted 与 LoopOn=false）；
//   - unknown：引擎未装配/任务未注册（测试/嵌入形态），不参与判定。
type securityEventsIngestionTaskHealthState struct {
	State            string
	Running          bool
	RestartExhausted bool
}

// securityEventsIngestionTaskState 返回采集任务实态。未装配引擎/未注册
// （测试/嵌入形态）返回 unknown——不参与健康位降级判定。
func securityEventsIngestionTaskState() securityEventsIngestionTaskHealthState {
	te := TaskEngine()
	if te == nil {
		return securityEventsIngestionTaskHealthState{State: "unknown"}
	}
	meta, ok := te.Lookup(securityEventsIngestionTaskID)
	if !ok {
		return securityEventsIngestionTaskHealthState{State: "unknown"}
	}
	state := securityEventsIngestionTaskHealthState{
		Running:          meta.Running,
		RestartExhausted: meta.RestartExhausted,
	}
	// LoopOn 优先：停止调度是权威事实——取消后 in-flight Run 尚在退出
	// （running 仍真实为 true）时也不得判 running，否则「用户刚停掉」的窗口
	// 内健康位仍显示采集正常。
	switch {
	case !meta.LoopOn:
		state.State = "stopped"
	case meta.Running:
		state.State = "running"
	default:
		state.State = "restarting"
	}
	return state
}

// 审计写侧失败可见性（插件 → 面板）契约：
//   - caddygeoip 的审计落盘管线把累计「队列满丢弃 / 写盘错误」计数（原子）由
//     drain goroutine 低频写入 <审计日志路径>.writer-stats.json（请求路径零参与）；
//   - 根服务摄取 tick 每次读取该侧车文件（跨 Go module，无法共享常量——两处
//     后缀/字段名必须同步），按增量累计成本进程启动以来的计数；
//   - 失败窗口（securityEventsWriterFailureWindow）内累计失败达阈值即降级采集
//     健康位（与任务停/连续失败同一位），并由 ingestion daemon 在状态变化时写
//     一条任务日志业务行（仅状态变化，低频）。
//   - written_at 判据边界（已裁定，勿按「停更」重报）：写侧只在计数变化时
//     重写侧车（无失败＝不写盘），故 written_at 陈旧是正常形态而非故障信号；
//     读侧只用它做代际判定（早于本进程启动的读数是上一代面板的累计值，
//     记为基线而非归零——插件计数只在插件进程重启时从 0 起），不得据其
//     年龄判「写侧停摆/侧车停更」——按年龄降级会在无失败期间长期误报。写侧
//     drain 真停摆没有独立存活信号可观测（要判必须先在生产侧落固定心跳）。
const (
	securityEventsAuditWriterStatsSuffix = ".writer-stats.json"
	// securityEventsAuditWriterStatsFailureSuffix 是插件侧车写盘失败标记后缀
	// （跨 module 协议第三段，与 caddygeoip 的 auditWriterStatsFailureSuffix
	// 同值）：计数侧车写不进去时标记文件在场——文件缺失不再等于「正常」。
	securityEventsAuditWriterStatsFailureSuffix = ".failed"
	securityEventsWriterFailureThreshold        = 3
	securityEventsWriterFailureWindow           = 15 * time.Minute
)

// securityEventsAuditWriterStatsPath 返回插件侧车计数文件路径（默认与审计日志
// 同目录）。auditLogPath 是包级变量，测试可注入临时路径。
func securityEventsAuditWriterStatsPath() string {
	return auditLogPath + securityEventsAuditWriterStatsSuffix
}

// securityEventsAuditWriterStatsFailurePath 返回插件侧车写盘失败标记路径。
func securityEventsAuditWriterStatsFailurePath() string {
	return securityEventsAuditWriterStatsPath() + securityEventsAuditWriterStatsFailureSuffix
}

// securityEventsWriterHealth 是侧车计数的进程内累计状态：baseline 是上一次
// 观测到的插件计数（插件重启计数回落时按新基线处理），totals 是本进程启动
// 以来实际观测到的失败量，window* 是「窗口内失败量」（阈值判据）。
// sidecar* 是侧车文件自身的可用性：读取/解析连续失败达阈值即「写侧计数
// 不可用」——磁盘满/目录只读正是侧车要覆盖的故障形态，双向失效不得静默。
// securityEventsProcessStart 是本进程（面板服务）启动时刻，用于判定侧车
// 计数的代际：计数文件跨容器重启存活，written_at 早于本时刻说明写它的是
// 上一代进程——那批累计读数**只记为基线**（baselineDropped/IO/Format），不
// 计入本代失败窗口；基线不得归零：插件计数器只在插件进程（Caddy）自身重启时
// 才从 0 起，面板单独重启时插件仍持旧累计值，归零会把历史失败全量算成本代
// 新增。插件真重启时计数回落，delta 的 `current<baseline` 分支再自动复位
// 基线。否则重启后首个 tick 会把历史失败当成本进程新失败（degraded 15 分钟
// + data_loss + 一条「审计日志写侧失败」任务日志的误报），且新进程无失败时
// 侧车永不重写，误报长期存在。var 供测试注入。
var securityEventsProcessStart = time.Now()

// securityEventsMessagesDropped 是写侧单行 messages 截断量的进程级累计：
// 仅在实际插入随事务提交成功后按行内 messages_dropped 递增；INSERT OR IGNORE
// 忽略的重放行、回滚与提交失败均不重复放大。被写侧省略的命中条目无法回填，
// 只能作为丢失事实披露（与写侧计数同为一等健康信号）。
var securityEventsMessagesDropped atomic.Uint64

// failureWindow 是窗口化失败计数器的单源实现：滑动窗口内累计失败数，达
// threshold 判降级；窗口滑过（首记或距窗口起点 ≥ window）即复位重累计。
// 累计总量（「曾丢失」）由宿主结构另行保存——窗口只回答「正在失败吗」。
// 此前写侧健康与畸形区跳过各持一份内联实现（start/counter 字段 + 三段式
// 复位/降级判定），窗长口径只能靠注释互指。zero value 不可用（window=0）：
// 宿主均经字面量注入 window/threshold。
type failureWindow struct {
	counter   uint64
	start     time.Time
	threshold uint64
	window    time.Duration
}

// record 累计 n 次失败；窗口过期时先复位再累计（n=0 语义：仅推进过期窗口
// 起点、清零计数，不引入失败）。
func (w *failureWindow) record(now time.Time, n uint64) {
	if w.start.IsZero() || now.Sub(w.start) >= w.window {
		w.start = now
		w.counter = 0
	}
	w.counter += n
}

// degraded 判定窗口内失败是否达阈值（窗口未滑过且计数达标）；零值窗口
// （从未记录）恒 false。
func (w *failureWindow) degraded(now time.Time) bool {
	return !w.start.IsZero() && now.Sub(w.start) < w.window && w.counter >= w.threshold
}

// clear 清空窗口（健康位整体重置用）。
func (w *failureWindow) clear() {
	w.counter = 0
	w.start = time.Time{}
}

type securityEventsWriterHealthState struct {
	mu              sync.Mutex
	baselineDropped uint64
	baselineIO      uint64
	baselineFormat  uint64
	droppedTotal    uint64
	ioTotal         uint64
	formatTotal     uint64
	// window 是失败窗口（阈值判据单源 failureWindow：窗长/阈值由字面量注入）。
	window        failureWindow
	lastFailureAt time.Time
	// sidecarReadFailures 连续读取/解析失败计数（文件缺失不计——插件未
	// 产生失败/未启动是正常形态）。
	sidecarReadFailures int
	// sidecarWriteFailureHits 连续观测到插件写盘失败标记的轮数：标记在场=
	// 插件写不进计数侧车（磁盘满/目录只读），此刻读到的是旧值、文件可能
	// 根本不存在（首写即失败）——计数不可信，按阈值置 unavailable。
	sidecarWriteFailureHits int
}

var securityEventsWriterHealth = securityEventsWriterHealthState{
	window: failureWindow{window: securityEventsWriterFailureWindow, threshold: securityEventsWriterFailureThreshold},
}

// securityEventsWriterStatsFailureMarker 读插件侧车写盘失败标记并解析出写入
// 时刻（标记正文形如「writer-stats sidecar write failed at <RFC3339>: <cause>」，
// 见 caddygeoip markWriterStatsFailure）。返回 ok=false 表示标记缺失或正文
// 不可解析——调用方按「在场但时刻未知」处理（保守计入失败）。
func securityEventsWriterStatsFailureMarker() (time.Time, bool) {
	data, err := os.ReadFile(securityEventsAuditWriterStatsFailurePath())
	if err != nil {
		return time.Time{}, false
	}
	const prefix = "writer-stats sidecar write failed at "
	body := strings.TrimSpace(string(data))
	if !strings.HasPrefix(body, prefix) {
		return time.Time{}, false
	}
	rest := body[len(prefix):]
	if idx := strings.Index(rest, ": "); idx >= 0 {
		rest = rest[:idx]
	}
	at, err := time.Parse(time.RFC3339, rest)
	if err != nil {
		return time.Time{}, false
	}
	return at, true
}

// securityEventsObserveWriterStatsFailureMarker 观测插件侧车写盘失败标记
// （跨 module 协议第三段，见 caddygeoip auditWriterStatsFailureSuffix）。
// 标记在场或不可 stat 即计一轮失败；缺失则复位连续计数。标记按代际判定：
// 写入时刻早于本进程启动说明它是上一代进程的故障（插件在创建管线时也会清除
// 残留标记，两道防线互为兜底），整份忽略——计数只在变化时写盘，本代无失败
// 时标记不会被成功路径删除，若不做代际判定会永久误报「写侧计数不可用」。
func securityEventsObserveWriterStatsFailureMarker(now time.Time) {
	_, err := os.Stat(securityEventsAuditWriterStatsFailurePath())
	securityEventsWriterHealth.mu.Lock()
	defer securityEventsWriterHealth.mu.Unlock()
	if err != nil && errors.Is(err, os.ErrNotExist) {
		securityEventsWriterHealth.sidecarWriteFailureHits = 0
		return
	}
	if err == nil {
		if at, ok := securityEventsWriterStatsFailureMarker(); ok {
			if at.Before(securityEventsProcessStart) {
				securityEventsWriterHealth.sidecarWriteFailureHits = 0
				return
			}
			// 失败时刻取标记内时间（写侧真实故障时刻），不再每 tick 刷新成
			// 「现在」——旧实现让 WriterLastFailureAt 永久指向当前时刻。
			securityEventsWriterHealth.sidecarWriteFailureHits++
			securityEventsWriterHealth.lastFailureAt = at
			return
		}
	}
	securityEventsWriterHealth.sidecarWriteFailureHits++
	securityEventsWriterHealth.lastFailureAt = now
}

// securityEventsObserveAuditWriterStats 读取插件侧车计数并累计增量。文件缺失
// （插件未产生失败/未启动）视为「本轮无信号」且复位连续失败计数；读取/解析
// 失败计入 sidecarReadFailures——侧车不可用时写侧丢弃/IO 计数恒 0，
// 必须由 writer_stats_unavailable 健康信号暴露而非保持假绿。
func securityEventsObserveAuditWriterStats() {
	securityEventsObserveWriterStatsFailureMarker(time.Now())
	data, err := os.ReadFile(securityEventsAuditWriterStatsPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			securityEventsWriterHealth.mu.Lock()
			securityEventsWriterHealth.sidecarReadFailures++
			securityEventsWriterHealth.mu.Unlock()
		} else {
			securityEventsWriterHealth.mu.Lock()
			securityEventsWriterHealth.sidecarReadFailures = 0
			securityEventsWriterHealth.mu.Unlock()
		}
		return
	}
	var payload struct {
		Dropped      uint64 `json:"dropped"`
		IOErrors     uint64 `json:"io_errors"`
		FormatErrors uint64 `json:"format_errors"`
		WrittenAt    string `json:"written_at"`
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		securityEventsWriterHealth.mu.Lock()
		securityEventsWriterHealth.sidecarReadFailures++
		securityEventsWriterHealth.mu.Unlock()
		return
	}
	// 代际判定：读取成功但书写时刻早于本进程启动 = 上一代进程（面板）的累计
	// 读数。**不得把基线归零**：插件计数器只有在**插件进程（Caddy）自身重启**
	// 时才是从 0 起的；面板进程单独重启（监督器只重启 app、Caddy 保持运行）时
	// 插件计数器保留旧累计值。归零后插件下一次任意写入（哪怕只新增 1 次失败）
	// 都会让 delta=累计值-0 把历史失败全量算进本代窗口 → 误报 degraded（15
	// 分钟）+ 永久 data_loss + 一条任务日志业务行，误导排障与升级验收。
	// 旧代读数作为基线：本代只累计其后的新增；插件进程真重启时计数归 0 会走
	// delta 的「current<baseline」分支自动复位基线。
	if written, perr := time.Parse(time.RFC3339, payload.WrittenAt); perr == nil {
		if written.Before(securityEventsProcessStart) {
			securityEventsWriterHealth.mu.Lock()
			securityEventsWriterHealth.baselineDropped = payload.Dropped
			securityEventsWriterHealth.baselineIO = payload.IOErrors
			securityEventsWriterHealth.baselineFormat = payload.FormatErrors
			securityEventsWriterHealth.sidecarReadFailures = 0
			securityEventsWriterHealth.mu.Unlock()
			return
		}
	}
	delta := func(current uint64, baseline *uint64) uint64 {
		if current < *baseline {
			*baseline = 0 // 插件进程重启：计数从 0 重新累计
		}
		diff := current - *baseline
		*baseline = current
		return diff
	}
	now := time.Now()
	securityEventsWriterHealth.mu.Lock()
	defer securityEventsWriterHealth.mu.Unlock()
	securityEventsWriterHealth.sidecarReadFailures = 0
	droppedDelta := delta(payload.Dropped, &securityEventsWriterHealth.baselineDropped)
	ioDelta := delta(payload.IOErrors, &securityEventsWriterHealth.baselineIO)
	formatDelta := delta(payload.FormatErrors, &securityEventsWriterHealth.baselineFormat)
	securityEventsWriterHealth.droppedTotal += droppedDelta
	securityEventsWriterHealth.ioTotal += ioDelta
	securityEventsWriterHealth.formatTotal += formatDelta
	// 格式化失败同样是「审计行没落盘」（写侧跳过该行），必须进同一失败窗口；
	// 累计量单独暴露，排障时据此区分磁盘故障（io_errors）与代码/契约故障
	// （format_errors）。
	newFailures := droppedDelta + ioDelta + formatDelta
	if newFailures == 0 {
		return
	}
	securityEventsWriterHealth.lastFailureAt = now
	securityEventsWriterHealth.window.record(now, newFailures)
}

// securityEventsSkipHealth 是畸形区跳过的进程内累计状态：跳过=该段审计数据
// 的事件被永久丢弃（崩溃残片/不可恢复畸形区），必须是与写侧计数同族的一等
// 健康信号——窗口内（securityEventsWriterFailureWindow，与写侧同口径）出现
// 跳过即降级健康位，累计量供三面披露；窗口滑过后健康位恢复但累计计数保留
// （「曾丢失」与「正在失败」分离表达）。
var securityEventsSkipHealth = securityEventsSkipHealthState{
	// 窗长与写侧同口径；threshold=1——窗口内出现跳过即降级（跳过=数据永久
	// 丢弃，没有「可容忍次数」）。
	window: failureWindow{window: securityEventsWriterFailureWindow, threshold: 1},
}

type securityEventsSkipHealthState struct {
	mu             sync.Mutex
	skippedBytes   uint64
	skippedRegions uint64
	// window 是跳过窗口（单源 failureWindow）；累计量（skipped*）单独表达
	// 「曾丢失」，窗口只表达「正在失败」。
	window     failureWindow
	lastSkipAt time.Time
}

// securityEventsRecordSkips 累计一次畸形区跳过（摄取 pass 内三处跳过分支的
// 唯一登记点，覆盖活文件停等跳过与归档补采的有界扫描/不可恢复尾部）。
func securityEventsRecordSkips(bytes int64, regions int) {
	if bytes <= 0 && regions <= 0 {
		return
	}
	now := time.Now()
	securityEventsSkipHealth.mu.Lock()
	defer securityEventsSkipHealth.mu.Unlock()
	if bytes > 0 {
		securityEventsSkipHealth.skippedBytes += uint64(bytes)
	}
	if regions > 0 {
		securityEventsSkipHealth.skippedRegions += uint64(regions)
	}
	securityEventsSkipHealth.lastSkipAt = now
	securityEventsSkipHealth.window.record(now, uint64(regions))
}

// securityEventsSkipHealthSnapshot 返回跳过累计与窗口内是否降级。
func securityEventsSkipHealthSnapshot() (skippedBytes, skippedRegions uint64, degraded bool, lastSkipAt time.Time) {
	securityEventsSkipHealth.mu.Lock()
	defer securityEventsSkipHealth.mu.Unlock()
	skippedBytes, skippedRegions = securityEventsSkipHealth.skippedBytes, securityEventsSkipHealth.skippedRegions
	lastSkipAt = securityEventsSkipHealth.lastSkipAt
	degraded = securityEventsSkipHealth.window.degraded(time.Now())
	return skippedBytes, skippedRegions, degraded, lastSkipAt
}

// securityEventsWriterHealthSnapshot 返回累计计数、窗口内是否降级，以及侧车
// 计数是否不可用（连续读取/解析失败达阈值——侧车双向失效时写侧计数恒 0，
// 不可用事实必须作为一等健康信号上抛）。
func securityEventsWriterHealthSnapshot() (dropped, ioErrors, formatErrors uint64, degraded, statsUnavailable bool, lastFailureAt time.Time) {
	securityEventsWriterHealth.mu.Lock()
	defer securityEventsWriterHealth.mu.Unlock()
	dropped, ioErrors = securityEventsWriterHealth.droppedTotal, securityEventsWriterHealth.ioTotal
	formatErrors = securityEventsWriterHealth.formatTotal
	lastFailureAt = securityEventsWriterHealth.lastFailureAt
	degraded = securityEventsWriterHealth.window.degraded(time.Now())
	statsUnavailable = securityEventsWriterHealth.sidecarReadFailures >= securityEventsWriterFailureThreshold ||
		securityEventsWriterHealth.sidecarWriteFailureHits >= securityEventsWriterFailureThreshold
	return dropped, ioErrors, formatErrors, degraded, statsUnavailable, lastFailureAt
}

// securityEventsOverlayIngestionHealth 把进程级信号叠加到 tick 记账结果上：
// ①任务已停（调度关闭/未运行）→ 未采集，非 healthy；②审计写侧窗口内失败
// 累计达阈值 → 落盘不可靠，非 healthy。两者都只置降级，不虚构成功。
func securityEventsOverlayIngestionHealth(status SecurityEventsIngestionStatus) SecurityEventsIngestionStatus {
	if task := securityEventsIngestionTaskState(); task.State != "unknown" {
		status.TaskState, status.TaskRunning = task.State, task.Running
		// 仅真实停止（调度关闭/自愈预算用尽）降级；退避重拉窗口
		// （restarting）自愈通道仍在，不能瞬时打成不健康。
		if task.State == "stopped" {
			status.Observed = true
			status.Healthy = false
		}
	} else {
		// 字段契约 running/restarting/stopped/unknown：引擎未装配/任务未注册
		// （测试/嵌入形态）必须显式落 unknown，空串会让按 unknown 分支消费的
		// 调用方失效。
		status.TaskState, status.TaskRunning = "unknown", false
	}
	dropped, ioErrors, formatErrors, degraded, statsUnavailable, lastFailureAt := securityEventsWriterHealthSnapshot()
	status.WriterDropped, status.WriterIOErrors, status.WriterFormatErrors = dropped, ioErrors, formatErrors
	status.MessagesDropped = securityEventsMessagesDropped.Load()
	status.WriterDegraded = degraded
	if !lastFailureAt.IsZero() {
		status.WriterLastFailureAt = lastFailureAt.UTC().Format(time.RFC3339)
	}
	if degraded {
		status.Observed = true
		status.Healthy = false
	}
	// 侧车不可用=写侧计数不可信：与窗口降级同一位置暴露（计数恒 0 的
	// 假绿比显式 unhealthy 更糟）。
	if statsUnavailable {
		status.WriterStatsUnavailable = true
		status.Observed = true
		status.Healthy = false
	}
	// 畸形区跳过叠加：窗口内有跳过（事件已永久丢弃）即降级——与写侧
	// 失败同一位；跳过那一轮 tick 本身成功返回 nil（记账会重置连续失败
	// 计数），不靠 tick 记账就无法暴露丢弃事实。
	skippedBytes, skippedRegions, skipDegraded, lastSkipAt := securityEventsSkipHealthSnapshot()
	status.SkippedBytes, status.SkippedRegions = skippedBytes, skippedRegions
	if !lastSkipAt.IsZero() {
		status.LastSkipAt = lastSkipAt.UTC().Format(time.RFC3339)
	}
	if skipDegraded {
		status.Observed = true
		status.Healthy = false
	}
	// 丢失事实与「当前是否仍在失败」分离：任一侧的累计丢失>0 即置位，
	// 窗口滑出 degraded 恢复后仍保持（见字段注释）。格式化失败=该审计行整行
	// 未落盘；命中明细截断=事件在库但部分规则命中永久缺失，两者同属丢失事实。
	status.DataLoss = dropped > 0 || ioErrors > 0 || formatErrors > 0 ||
		status.MessagesDropped > 0 || skippedRegions > 0
	// spool 待补采状态叠加（B 形态）：待补采不是丢失，但目录不可读/已满/
	// 补采连续失败必须降级——静默积压=主路径故障不可见。
	securityEventsOverlaySpoolHealth(&status)
	return status
}

// SecurityEventsSetIngestionHealthForTest 直设健康快照（handlers 契约测试用；
// 生产路径只经 securityEventsRecordPollResult 更新）。
func SecurityEventsSetIngestionHealthForTest(status SecurityEventsIngestionStatus) {
	securityEventsIngestionHealth.Lock()
	securityEventsIngestionHealth.status = status
	securityEventsIngestionHealth.Unlock()
	// 写侧计数累计状态同步复位：健康位是一个整体（tick 记账 + 任务实态 +
	// 写侧计数），测试重置健康位时必须一并清空，否则窗口内降级状态跨用例泄漏。
	securityEventsWriterHealth.mu.Lock()
	securityEventsWriterHealth.baselineDropped = 0
	securityEventsWriterHealth.baselineIO = 0
	securityEventsWriterHealth.baselineFormat = 0
	securityEventsWriterHealth.droppedTotal = 0
	securityEventsWriterHealth.ioTotal = 0
	securityEventsWriterHealth.formatTotal = 0
	securityEventsWriterHealth.window.clear()
	securityEventsWriterHealth.lastFailureAt = time.Time{}
	securityEventsWriterHealth.sidecarReadFailures = 0
	securityEventsWriterHealth.sidecarWriteFailureHits = 0
	securityEventsWriterHealth.mu.Unlock()
	// 跳过累计同属健康位整体，重置时一并清空（防跨用例泄漏）。
	// 消息截断计数同属健康位整体：它是独立原子计数，健康快照每次从它填
	// MessagesDropped 并据此推导 DataLoss，漏清会让后续用例继承上一用例的
	// data_loss=true（顺序依赖/随机红）。
	securityEventsMessagesDropped.Store(0)
	securityEventsSkipHealth.mu.Lock()
	securityEventsSkipHealth.skippedBytes = 0
	securityEventsSkipHealth.skippedRegions = 0
	securityEventsSkipHealth.window.clear()
	securityEventsSkipHealth.lastSkipAt = time.Time{}
	securityEventsSkipHealth.mu.Unlock()
}

// SecurityEventsPollOnce 单轮摄取（先采集后轮转——引擎 2s 节拍调用）。
// 返回本轮摄取条数与轮转错误（采集 tick 错误经限流 warn+健康快照记账，
// 不随返回值暴露）；任务日志只由 ingestion daemon 自己写，其他调用方不得越权。
// 无取消语义的调用方（手动兜底轮转）用本入口；daemon 走 securityEventsPollOnce
// 传入引擎 ctx，让停机时 pass 在批次边界收尾。
func SecurityEventsPollOnce() (int, error) {
	return securityEventsPollOnce(context.Background())
}

func securityEventsPollOnce(ctx context.Context) (int, error) {
	securityEventsPollState.Lock()
	defer securityEventsPollState.Unlock()
	// 审计写侧计数（插件侧车）每轮先观测：即使本轮无新事件，写侧失败也必须
	// 进入健康位（降级判定与事件吞吐无关）。
	securityEventsObserveAuditWriterStats()
	if !securityEventsPollState.inited {
		securityEventsPollState.tailer = securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
		if err := ensureAuditLogDir(); err != nil {
			Logf("warn", "security events ingestion: create audit log dir %s failed: %v", filepath.Dir(auditLogPath), err)
		}
		securityEventsPollState.inited = true
		Logf("info", "security events ingestion(engine) started: audit_log=%s", auditLogPath)
	}
	tickErr := securityEventsPollState.tailer.securityEventsTickContext(ctx)
	if tickErr != nil {
		securityEventsPollState.tailer.securityEventsRateLimitedWarn(tickErr)
	}
	ingested := securityEventsPollState.tailer.lastIngested
	securityEventsPollState.tailer.lastIngested = 0
	// 轮转/补采窗口入库的事件计入同一轮摄取数（此前只报 tailer 计数，
	// 补采事件永不进任务日志）；失败不阻塞返回（轮转自身已限流告警）。
	rotated, rotErr := rotateAuditLogIfNeeded(ctx)
	ingested += rotated
	// fallback spool 补采（B 形态主路径的兜底）：只有 DB commit 完成的 sealed
	// 文件才会被删除；失败按退避保留，待补采量由健康位/统计暴露。
	spoolIngested, spoolErr := drainSecurityEventsSpool(ctx)
	ingested += spoolIngested
	// 轮转失败与采集失败同口径进健康快照——一轮内
	// 两类失败只记一次（不双计）；停等（stalled）瞬态不遮蔽轮转失败。
	healthErr := tickErr
	if rotErr != nil && (healthErr == nil || errors.Is(healthErr, errSecurityEventsStalled)) {
		healthErr = rotErr
	}
	// spool 补采失败同属采集失败（待补采条目未入库）：同样单记一次。
	if spoolErr != nil && (healthErr == nil || errors.Is(healthErr, errSecurityEventsStalled)) {
		healthErr = spoolErr
	}
	securityEventsRecordPollResult(healthErr)
	return ingested, rotErr
}

// runIngestionLoop 常驻自管理摄取循环（v2.0 Daemon 标准）：2s 节拍尾读 +
// 轮转跟随，阻塞直到 ctx 取消。引擎 StartLoop 时启动一次（Run=本函数），
// StopLoop 时 ctx 取消返回。
func runIngestionLoop(ctx context.Context) error {
	//scope-exempt: daemon-run-body-loop —— §0.2 形态② daemon Run 体自管理阻塞循环（2s 尾读+轮转跟随，ctx 取消即退）
	ticker := time.NewTicker(securityEventsPollInterval)
	defer ticker.Stop()
	var lastRotateFailureSummaryAt time.Time
	lastWriterDegraded := false
	lastWriterStatsUnavailable := false
	// 命中明细截断的边沿留痕（5min 节流）：单条命中规则数过多时写侧只保留
	// 前若干条，缺失部分永不可回填，任务日志须可见。
	lastMessagesDropped := uint64(0)
	lastMessagesDroppedLogAt := time.Time{}
	// 畸形区跳过的边沿留痕基线（跳过=事件永久丢弃，必须进任务日志——
	// 仅 Logf 应用日志会让排障翻不到任务日志）。
	lastSkippedRegions := uint64(0)
	// 待补采（fallback spool）边沿基线：IPC 主路径正常时恒 0；有值=主路径
	// 曾失败、事件已落盘等补采（不是丢失，但必须可见）。
	lastSpoolPending := int64(0)
	lastSpoolSaturated := false
	lastSpoolUnavailable := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			ingested, rotErr := securityEventsPollOnce(ctx)
			if ingested > 0 {
				TaskLogf("security-events-ingestion", "ingest", "摄取 %d 条安全事件", ingested)
			}
			// 审计写侧失败状态变化才留痕（避免每 2s 重复写同一结论）：达阈值
			// 降级与恢复各一行，随任务日志导出排障上下文。
			status := SecurityEventsIngestionHealthSnapshot()
			if status.SkippedRegions > lastSkippedRegions {
				TaskLogfWarn("security-events-ingestion", "skip", "审计日志畸形区被跳过：累计 %d 段 / %d 字节，相关安全事件已永久丢失", status.SkippedRegions, status.SkippedBytes)
				lastSkippedRegions = status.SkippedRegions
			}
			if status.WriterDegraded != lastWriterDegraded {
				if status.WriterDegraded {
					TaskLogfWarn("security-events-ingestion", "audit-writer", "审计日志写侧失败：窗口内累计丢弃 %d 条、写盘错误 %d 次、格式化失败 %d 次（累计值），安全事件可能缺失", status.WriterDropped, status.WriterIOErrors, status.WriterFormatErrors)
				} else {
					TaskLogf("security-events-ingestion", "audit-writer", "审计日志写侧失败已回落至阈值以下（累计丢弃 %d 条、写盘错误 %d 次、格式化失败 %d 次）", status.WriterDropped, status.WriterIOErrors, status.WriterFormatErrors)
				}
				lastWriterDegraded = status.WriterDegraded
			}
			if status.MessagesDropped > lastMessagesDropped {
				if time.Since(lastMessagesDroppedLogAt) >= 5*time.Minute {
					TaskLogfWarn("security-events-ingestion", "audit-truncate", "审计行命中明细被写侧截断：累计 %d 条规则命中未入库（事件本身已入库），请检查单条请求命中的规则数与审计行体积", status.MessagesDropped)
					lastMessagesDroppedLogAt = time.Now()
				}
				lastMessagesDropped = status.MessagesDropped
			}
			// 侧车不可用边沿留痕（磁盘满/目录只读时写侧计数对外恒 0，
			// 假绿比显式不可用更糟）；恢复一行便于排障闭环。
			if status.WriterStatsUnavailable != lastWriterStatsUnavailable {
				if status.WriterStatsUnavailable {
					TaskLogfWarn("security-events-ingestion", "audit-writer", "审计写侧计数侧车连续读取失败：写侧丢弃/写盘错误计数不可用（显示 0 不代表无丢弃），请检查审计日志目录的磁盘空间与权限")
				} else {
					TaskLogf("security-events-ingestion", "audit-writer", "审计写侧计数侧车读取已恢复")
				}
				lastWriterStatsUnavailable = status.WriterStatsUnavailable
			}
			// 待补采状态边沿留痕（B 形态：IPC 主路径失败才产生 spool）：
			// 有积压=主路径故障，事件仍在磁盘可补采（不是丢失）；清空=已自愈。
			if status.SpoolPendingEntries != lastSpoolPending {
				if status.SpoolPendingEntries > 0 {
					msg := fmt.Sprintf("IPC 入库失败，%d 条安全事件待补采（%d 个文件 / %d 字节）：事件未丢失，采集任务每轮重试补采", status.SpoolPendingEntries, status.SpoolFiles, status.SpoolPendingBytes)
					if status.SpoolLastError != "" {
						msg += "；最近失败: " + status.SpoolLastError
					}
					TaskLogfWarn("security-events-ingestion", "spool", "%s", msg)
				} else {
					TaskLogf("security-events-ingestion", "spool", "待补采安全事件已全部入库（spool 已清空）")
				}
				lastSpoolPending = status.SpoolPendingEntries
			}
			if status.SpoolSaturated != lastSpoolSaturated {
				if status.SpoolSaturated {
					TaskLogfWarn("security-events-ingestion", "spool", "待补采 spool 已达上限（%d 条 / %d 字节）：写侧新事件可能被丢弃，请检查数据库可用性与磁盘空间", status.SpoolLimitEntries, status.SpoolLimitBytes)
				} else {
					TaskLogf("security-events-ingestion", "spool", "待补采 spool 已回落到上限以下")
				}
				lastSpoolSaturated = status.SpoolSaturated
			}
			if status.SpoolUnavailable != lastSpoolUnavailable {
				if status.SpoolUnavailable {
					TaskLogfWarn("security-events-ingestion", "spool", "待补采目录 %s 不可读：待补采计数不可用（显示 0 不代表无积压），请检查目录权限与磁盘", status.SpoolDir)
				} else {
					TaskLogf("security-events-ingestion", "spool", "待补采目录读取已恢复")
				}
				lastSpoolUnavailable = status.SpoolUnavailable
			}
			// 轮转写任务摘要——此前任务日志仅在
			// ingested>0 时留痕，轮转持续失败零可见性。2s 节拍下持续失败每
			// 分钟至多一行（与应用日志 60s 限流同窗口）。顺延（活文件尾部
			// 尚未摄取）是容量问题不是采集失败：文案必须与失败区分，否则
			// 排障会被引向「采集故障」。
			if rotErr != nil && time.Since(lastRotateFailureSummaryAt) >= time.Minute {
				if errors.Is(rotErr, errAuditRotationDeferred) {
					TaskLogf("security-events-ingestion", "rotate", "审计日志轮转延迟：活文件尚未截断（磁盘空间暂未回收，事件采集与入库不受影响）: %v", rotErr)
				} else {
					TaskLogfWarn("security-events-ingestion", "rotate", "审计日志轮转失败：%v", rotErr)
				}
				lastRotateFailureSummaryAt = time.Now()
			}
		}
	}
}

// —— 安全处理耗时（2026-09-27 分段计时；历史侧车退役）——
// 耗时不再经侧车文件跨进程传递：审计写插件
// （caddygeoip auditwriter.go）在 Caddy 进程内把 per-request 分段耗时注入
// 审计行顶层 lb_timing 字段（{"pre_us":N,"end_us":M}，缺席分段省略），摄取
// 管道解析审计行时直接取值——零文件、零截断协议、零 tick 级查表，补采路径
// 天然携带自身耗时。

// securityEventsStageDurationEmbedded 按规则归属与事件动作从审计行内嵌
// lb_timing 字段选分段耗时（µs）。分段二态契约（与写侧
// caddygeoip 分段选键/锚点交接配对）：
//
//	pre_us=预检决策耗时(放行=timing_pre 收点记;预检拦=blocked_counter 代记);
//	end_us=拦截事件 链首→中断全链(blocked_counter) / logged 事件 预检后→链末
//	       (timing_end 读重写后的分段锚点)=WAF 段值。
//
// 预检段规则: pre_us 优先;缺席回退 end_us(头对缺失/竞态降级形态)。
// WAF 段规则按事件动作二态: 拦截(interrupted)=end_us-pre_us 隔离 WAF 成本;
// logged=end_us 即段值直接取用(锚点交接后减法会混入跨锚点垃圾差值)。
// 负值视同缺席(防御畸形注入;写侧时序值恒非负);双段均为负差退化 end_us。
func securityEventsStageDurationEmbedded(pre, end *int64, ruleID string, interrupted bool) int64 {
	preV, preOK := timingUsOrNil(pre)
	endV, endOK := timingUsOrNil(end)
	if securityEventsIsPrecheckRule(ruleID) {
		if preOK {
			return preV
		}
		if endOK {
			return endV
		}
		return 0
	}
	if interrupted {
		if endOK && preOK && endV >= preV {
			return endV - preV
		}
		if endOK {
			return endV
		}
		return 0
	}
	if endOK {
		return endV
	}
	return 0
}

// timingUsOrNil 非负指针解引用（负值视同缺席）。
func timingUsOrNil(v *int64) (int64, bool) {
	if v == nil || *v < 0 {
		return 0, false
	}
	return *v, true
}

// securityEventsIsPrecheckRule 判定规则 ID 是否预检段——IP ACL(2/4/5/7)、
// 信任(3/12)、GeoIP(8)、威胁情报(14)与阶段 1 预检 8xxxxx 段（普通 GeoIP /
// 爬虫豁免 / 爬虫伪装三族）。与 stageCategorizeAttack 的预检分支同口径；
// 集合单一事实源=IsStage1PrecheckEventID（与 Stage1PrecheckIDSQLList 同源，
// 三集合对账由 security_stage1_segment_test.go 钉死）。
func securityEventsIsPrecheckRule(ruleID string) bool {
	n, err := strconv.Atoi(ruleID)
	if err != nil {
		return false
	}
	return IsStage1PrecheckEventID(n)
}

// securityEventsIsGeoIPScoringRule 普通 GeoIP 固定分谓词：
// id 8 或 8xxxxx 段中「能唯一解码且不属爬虫两族」的 id。p=0 边界值（810000/
// 850000）不属任何合法爬虫族，按普通 GeoIP 计——不得被当爬虫豁免得 0 分。
func securityEventsIsGeoIPScoringRule(ruleID string) bool {
	if ruleID == "8" {
		return true
	}
	n, err := strconv.Atoi(ruleID)
	if err != nil || n <= geoipPrecheckRuleBase || n >= geoipPrecheckRuleLimit {
		return false
	}
	family, _, _, ok := decodePrecheckRuleID(ruleID)
	return !ok || family != precheckRuleFamilyCrawlerExempt && family != precheckRuleFamilyCrawlerSpoof
}

// securityEventsIsCrawlerExemptRule 豁免放行规则 id（810000+policyID*16+引擎序号）。
// 与生成公式同源——decode + 编码回环校验，越界 id（如
// policyID≥2500 溢入伪装段的形态）不得误判为豁免。
func securityEventsIsCrawlerExemptRule(id string) bool {
	n, err := strconv.Atoi(id)
	if err != nil {
		return false
	}
	family, pid, idx, ok := decodePrecheckRuleID(id)
	if !ok || family != precheckRuleFamilyCrawlerExempt {
		return false
	}
	enc, eok := encodeCrawlerExemptRuleID(pid, idx)
	return eok && enc == n
}

// securityEventsIsCrawlerSpoofRule 爬虫伪装规则 id（850000+policyID）。
// 与生成公式同源（decode + 编码回环校验）。
func securityEventsIsCrawlerSpoofRule(id string) bool {
	n, err := strconv.Atoi(id)
	if err != nil {
		return false
	}
	family, pid, _, ok := decodePrecheckRuleID(id)
	if !ok || family != precheckRuleFamilyCrawlerSpoof {
		return false
	}
	enc, eok := encodeCrawlerSpoofRuleID(pid)
	return eok && enc == n
}

// —— 攻击口径（放行不计入攻击）——

// 安全事件 action 取值（写侧 securityEventsParseTransaction 单源）。
const (
	// SecurityEventActionBlocked 事件被拦截（coraza 事务 is_interrupted）。
	SecurityEventActionBlocked = "blocked"
	// SecurityEventActionLogged 事件仅记录（检测/信任/爬虫放行）。
	SecurityEventActionLogged = "logged"
)

// IsCrawlerExemptRuleID 报告 rule_triggered 是否为「已验证爬虫放行」规则 id
// （geoipCrawlerRuleBase+policyID*16+引擎序号，段内起始 id 之后）。
// 必须是 6 位纯数字形态：归因/评分走 Atoi 宽松形态，"+810016"/前导零/空白
// 会被当成同一 id，而放行口径是面向用户展示的统计维度，宽松形态一律不认。
// 段界判定复用 decode+encode 回环（单源），不在此复写段基址。
func IsCrawlerExemptRuleID(id string) bool {
	if len(id) != 6 {
		return false
	}
	for i := range len(id) {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		return false
	}
	if n < geoipCrawlerRuleBase+geoipCrawlerEngineSlots || n >= geoipCrawlerSpoofRuleBase {
		return false
	}
	return securityEventsIsCrawlerExemptRule(id)
}

// SecurityEventCountsAsAttack 攻击口径唯一判据：仅「已记录 + 爬虫放行族」
// 不计入攻击（放行不是攻击）；其余一律计入。
//
// 边界：归因取审计首条消息，多策略下「A 放行 + B 拦截」的事件仍可能被记在
// 放行规则名下——因此这里按 action 判定而非按规则族：action=blocked 的放行族
// 事件仍然计入，不隐藏真实拦截。
func SecurityEventCountsAsAttack(action, ruleTriggered string) bool {
	return !(action == SecurityEventActionLogged && IsCrawlerExemptRuleID(ruleTriggered))
}

// CrawlerExemptRuleIDSQLPredicate 返回「rule_triggered 属爬虫放行族」的 SQL
// 谓词（与 IsCrawlerExemptRuleID 同集合）：GLOB 六位数字同时约束长度与字符集，
// CAST 后落在 [段内起始, 伪装段起点)。
func CrawlerExemptRuleIDSQLPredicate(col string) string {
	return fmt.Sprintf(`(COALESCE(%s,'') GLOB '[0-9][0-9][0-9][0-9][0-9][0-9]' AND CAST(COALESCE(%s,'') AS INTEGER) BETWEEN %d AND %d)`,
		col, col, geoipCrawlerRuleBase+geoipCrawlerEngineSlots, geoipCrawlerSpoofRuleBase-1)
}

// AttackEventSQLPredicate 返回「该行计入攻击」的 SQL 谓词（与
// SecurityEventCountsAsAttack 同集合）：非「logged 且爬虫放行族」。
func AttackEventSQLPredicate(ruleCol, actionCol string) string {
	return fmt.Sprintf(`NOT (COALESCE(%s,'') = '%s' AND %s)`, actionCol, SecurityEventActionLogged, CrawlerExemptRuleIDSQLPredicate(ruleCol))
}
