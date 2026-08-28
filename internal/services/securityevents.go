package services

// allow: SIZE_OK — single cohesive WAF audit-log ingestion module; the
// deliverable is mandated as this one file and splitting is not authorized.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

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
	ClientIP      string
	Method        string
	URI           string
	EventType     string
	RuleTriggered string
	RuleMsg       string
	Action        string
	AnomalyScore  int
}

// securityEventsAuditTransaction mirrors the Coraza JSON audit envelope:
// messages is a TOP-LEVEL sibling of transaction, not nested inside it.
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
		} `json:"request"`
		IsInterrupted bool `json:"is_interrupted"`
	} `json:"transaction"`
	Messages []struct {
		Message string `json:"message"`
		Data    struct {
			ID    json.Number `json:"id"`
			Score json.Number `json:"score"`
		} `json:"data"`
	} `json:"messages"`
}

// errSecurityEventsEmptyID 标记无 transaction_id 的事务：去重唯一索引是部分索引
// （WHERE transaction_id != ”），空 id 没有幂等键，重试路径（tick 失败重放、
// 轮转补采与 tick 重叠）会重复插入，因此视为解析失败跳过。
var errSecurityEventsEmptyID = errors.New("transaction has no id")

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
	for _, msg := range doc.Messages {
		if score, err := msg.Data.Score.Float64(); err == nil {
			rec.AnomalyScore += int(score)
		}
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
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,''), COALESCE(name,'') FROM lb_rules WHERE protocol='http' AND COALESCE(domain,'') != ''`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var caddyID, domain, name string
		if err := rows.Scan(&caddyID, &domain, &name); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan rule: %w", err)
		}
		canonical, err := db.CanonicalDomains(domain)
		if err != nil {
			continue // a domain that cannot be canonicalized can never match
		}
		for _, host := range strings.Split(canonical, ",") {
			rules[host] = securityEventsRuleRef{caddyID: caddyID, name: name}
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

	// 策略的 custom_rules / crs_rule_groups / ip_blacklist / ip_acl_* 用于
	// 「rule_triggered 属于哪个策略」判定；仅加载启用策略（disabled 策略不应再
	// 接收事件归因）。
	policyByID := make(map[int]*models.SecurityPolicy)
	polRows, err := db.DB.Query(`SELECT id, COALESCE(name,''), COALESCE(custom_rules,'[]'), COALESCE(crs_rule_groups,'[]'), COALESCE(ip_blacklist,'[]'), COALESCE(ip_acl_enabled,0), COALESCE(ip_acl_mode,''), COALESCE(ip_acl_list,'[]') FROM security_policies WHERE enabled=1`)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("security events: load policies: %w", err)
	}
	defer polRows.Close()
	for polRows.Next() {
		p := &models.SecurityPolicy{}
		var customJSON, crsJSON, blacklistJSON string
		if err := polRows.Scan(&p.ID, &p.Name, &customJSON, &crsJSON, &blacklistJSON, &p.IPACLEnabled, &p.IPACLMode, &p.IPACLList); err != nil {
			return nil, nil, nil, fmt.Errorf("security events: scan policy: %w", err)
		}
		p.CustomRules = json.RawMessage(customJSON)
		p.CRSRuleGroups = json.RawMessage(crsJSON)
		p.IPBlacklist = json.RawMessage(blacklistJSON)
		policyByID[p.ID] = p
	}
	if err := polRows.Err(); err != nil {
		return nil, nil, nil, fmt.Errorf("security events: iterate policies: %w", err)
	}
	return rules, bindings, policyByID, nil
}

// securityEventsPolicyContainsRule reports whether the given rule id belongs to
// the policy's active rule set. 自定义规则（10000+，且 <900000）：查 custom_rules
// JSON（兼容 ID 数组与内嵌对象数组两种形状）。注意 ID 空间：custom_rules JSON
// 存的是 security_custom_rules 的 DB 主键 id，而 audit 的 rule_triggered 是
// emit id（DB id + 10000，见 emitCustomRules），因此归属判定在 emit 空间比较
// （DB id + 10000 == n）。CRS 规则（9xxxxx）：crs_rule_groups 条目为两位数字
// 代码（如 "42" 对应 942xxx，与 BuildCorazaDirectives 的 `REQUEST-9<code>-*.conf`
// Include 同款口径）；空数组按发射端语义视为「包含全部 REQUEST-*」，即所有 CRS
// 规则均属于该策略。IP ACL 拒绝带（A3 I-6）：id 4 = 遗留 ip_blacklist 拒绝，
// BuildCorazaDirectives 仅对黑名单非空的策略发射；id 2 = IP ACL 黑名单模式
// 拒绝，仅对 ip_acl_enabled + mode='deny' + 名单非空的策略发射——归属口径与
// 发射条件一一对应（名单解析失败/为空均视为不拥有，与发射端 json.Unmarshal
// 失败得到空切片同义）。
func securityEventsPolicyContainsRule(policy *models.SecurityPolicy, ruleTriggered string) bool {
	if policy == nil || ruleTriggered == "" {
		return false
	}
	n, err := strconv.Atoi(ruleTriggered)
	if err != nil {
		return false
	}
	switch {
	case n == 4:
		var blacklist []string
		if err := json.Unmarshal(policy.IPBlacklist, &blacklist); err != nil {
			return false
		}
		return len(blacklist) > 0
	case n == 2:
		if !policy.IPACLEnabled || policy.IPACLMode != "deny" {
			return false
		}
		var aclList []string
		if err := json.Unmarshal([]byte(policy.IPACLList), &aclList); err != nil {
			return false
		}
		return len(aclList) > 0
	case n >= 10000 && n < 900000:
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
	case n >= 900000 && n <= 999999:
		var groups []string
		if err := json.Unmarshal(policy.CRSRuleGroups, &groups); err != nil {
			return false
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
	}
	return false
}

// securityEventsAttributePolicy v2.2.0 多策略事件归因：rule_triggered → 查该规则
// ID 属于哪个策略（custom_rules / CRS 组 / IP ACL 拒绝带匹配），重叠时取绑定顺序
// 第一条（policy_id ASC 的第一个）。策略均未显式包含时回退到绑定顺序中第一个
// ENABLED 策略（policyByID 仅含启用策略：禁用/悬空的首绑定被跳过，事件仍归到该
// lb_rule 的可用主策略）。无任何启用绑定策略、或 lb_rule 完全未绑定（无
// security_policy_bindings 行）返回零值 (0, "")。ACL 拒绝带（id 4/2）无属主时
// 同样走该回退而非归零：事件既已被摄取，必是某绑定策略在发射时的配置发出了它
// （当前配置可能已变更），归到首启用绑定是最接近发射现实的归属。
func securityEventsAttributePolicy(ruleCaddyID, ruleTriggered string, policyByID map[int]*models.SecurityPolicy, bindings map[string][]int) (int, string) {
	policyIDs := bindings[ruleCaddyID]
	if len(policyIDs) == 0 {
		return 0, ""
	}
	for _, pid := range policyIDs {
		p := policyByID[pid]
		if p == nil {
			continue
		}
		if securityEventsPolicyContainsRule(p, ruleTriggered) {
			return pid, p.Name
		}
	}
	for _, pid := range policyIDs {
		if p := policyByID[pid]; p != nil {
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

// securityEventsFindNextDocument scans forward from `from` for the next `{`
// at column 0, which in the pretty-printed multi-line format marks the start
// of the next top-level transaction. found=false when none exists yet.
func securityEventsFindNextDocument(f *os.File, from int64) (int64, bool, error) {
	const scanLimit = securityEventsScanWindowLimit
	buf := make([]byte, scanLimit)
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
	// archivePass 标记归档补采（.1 补采 / pending 重试）：归档大小有界且不再增长，
	// 遇到 ≥4MB 畸形区时改为有界 scan-to-EOF 恢复，而不是 F1 报错（见
	// securityEventsProcessPass）。
	archivePass bool
	// failOffset 是本 pass 中 F1 停摆（畸形区）的偏移，仅 F1 错误路径设置；
	// -1 表示本次 tick 未触发 F1。
	failOffset int64
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
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return offset, fmt.Errorf("security events: seek audit log: %w", err)
	}
	committedOffset := offset
	tx, err := db.MetricsDB.Begin()
	if err != nil {
		return offset, fmt.Errorf("security events: begin insert transaction: %w", err)
	}
	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO security_events
		(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
			rule := securityEventsMapHost(rec.Host, rules)
			policyID, policyName := securityEventsAttributePolicy(rule.caddyID, rec.RuleTriggered, policyByID, bindings)
			if _, ierr := stmt.Exec(rec.EventTime, rule.caddyID, policyID, rec.ClientIP, rec.Method, rec.URI,
				rec.EventType, rec.RuleTriggered, rec.RuleMsg, rec.Action, rec.AnomalyScore,
				rule.name, policyName, rec.TransactionID); ierr != nil {
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
					(event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, anomaly_score, rule_name, policy_name, transaction_id)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
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
func StartSecurityEventsIngestion(ctx context.Context) {
	tailer := securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
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
