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
)

// Security event ingestion: tails the Coraza WAF audit log (consecutive
// pretty-printed JSON transactions) and inserts parsed rows into the
// security_events table. All identifiers carry the securityEvents prefix to
// avoid package-level symbol clashes inside services.

var (
	securityEventsAuditLogPath = "/app/waf/audit/audit.log"
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

// securityEventsPolicyRef is a bound security_policies identity resolved for
// one event: the policy id plus its name snapshotted at ingest time.
type securityEventsPolicyRef struct {
	id   int
	name string
}

// securityEventsLoadMappings batch-loads host→rule and rule→policy indexes
// once per ingest tick so the tailer never queries per row. Both indexes carry
// the display names so each inserted event snapshots them. Domain
// canonicalization matches handlers' normalizedRuleDomains (db.CanonicalDomains).
func securityEventsLoadMappings() (map[string]securityEventsRuleRef, map[string]securityEventsPolicyRef, error) {
	if db.DB == nil {
		return nil, nil, errors.New("security events: database not initialized")
	}
	rules := make(map[string]securityEventsRuleRef)
	rows, err := db.DB.Query(`SELECT caddy_id, COALESCE(domain,''), COALESCE(name,'') FROM lb_rules WHERE protocol='http' AND COALESCE(domain,'') != ''`)
	if err != nil {
		return nil, nil, fmt.Errorf("security events: load rules: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var caddyID, domain, name string
		if err := rows.Scan(&caddyID, &domain, &name); err != nil {
			return nil, nil, fmt.Errorf("security events: scan rule: %w", err)
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
		return nil, nil, fmt.Errorf("security events: iterate rules: %w", err)
	}

	bindings := make(map[string]securityEventsPolicyRef)
	bindRows, err := db.DB.Query(`SELECT b.rule_caddy_id, b.policy_id, COALESCE(p.name,'')
		FROM security_policy_bindings b LEFT JOIN security_policies p ON p.id = b.policy_id ORDER BY b.policy_id DESC`)
	if err != nil {
		return nil, nil, fmt.Errorf("security events: load policy bindings: %w", err)
	}
	defer bindRows.Close()
	for bindRows.Next() {
		var caddyID, policyName string
		var policyID int
		if err := bindRows.Scan(&caddyID, &policyID, &policyName); err != nil {
			return nil, nil, fmt.Errorf("security events: scan binding: %w", err)
		}
		if _, exists := bindings[caddyID]; !exists {
			bindings[caddyID] = securityEventsPolicyRef{id: policyID, name: policyName} // first binding wins, mirroring QueryRow lookups
		}
	}
	if err := bindRows.Err(); err != nil {
		return nil, nil, fmt.Errorf("security events: iterate bindings: %w", err)
	}
	return rules, bindings, nil
}

// securityEventsMapHost resolves a request host to its rule and bound policy;
// zero-value refs when nothing matches.
func securityEventsMapHost(host string, rules map[string]securityEventsRuleRef, bindings map[string]securityEventsPolicyRef) (securityEventsRuleRef, securityEventsPolicyRef) {
	canonical, err := db.CanonicalDomains(host)
	if err != nil {
		return securityEventsRuleRef{}, securityEventsPolicyRef{} // IPs and invalid domains never match a domain rule
	}
	for _, candidate := range strings.Split(canonical, ",") {
		if rule, ok := rules[candidate]; ok {
			return rule, bindings[rule.caddyID]
		}
	}
	return securityEventsRuleRef{}, securityEventsPolicyRef{}
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

// securityEventsFindNextDocument scans forward from `from` for the next `{`
// at column 0, which in the pretty-printed multi-line format marks the start
// of the next top-level transaction. found=false when none exists yet.
func securityEventsFindNextDocument(f *os.File, from int64) (int64, bool, error) {
	const scanLimit = 4 << 20
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

// securityEventsTailer streams new audit transactions from the log file,
// persisting its byte offset between passes so restarts resume in place.
type securityEventsTailer struct {
	logPath    string
	offsetPath string
	lastInfo   os.FileInfo
}

func securityEventsNewTailer(logPath, offsetPath string) *securityEventsTailer {
	return &securityEventsTailer{logPath: logPath, offsetPath: offsetPath}
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
	rules, bindings, err := securityEventsLoadMappings()
	if err != nil {
		return err
	}
	f, err := os.Open(t.logPath)
	if err != nil {
		return fmt.Errorf("security events: open audit log: %w", err)
	}
	defer f.Close()
	newOffset, passErr := t.securityEventsProcessPass(f, offset, rules, bindings)
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
func (t *securityEventsTailer) securityEventsProcessPass(f *os.File, offset int64, rules map[string]securityEventsRuleRef, bindings map[string]securityEventsPolicyRef) (int64, error) {
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
			Logf("error", "security events ingestion: skipping malformed transaction id=%s: %v", securityEventsTransactionID(raw), perr)
		} else {
			rule, policy := securityEventsMapHost(rec.Host, rules, bindings)
			if _, ierr := stmt.Exec(rec.EventTime, rule.caddyID, policy.id, rec.ClientIP, rec.Method, rec.URI,
				rec.EventType, rec.RuleTriggered, rec.RuleMsg, rec.Action, rec.AnomalyScore,
				rule.name, policy.name, rec.TransactionID); ierr != nil {
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
	f, err := os.Open(archive)
	if err != nil {
		return fmt.Errorf("security events: open rotated archive: %w", err)
	}
	defer f.Close()
	rules, bindings, err := securityEventsLoadMappings()
	if err != nil {
		return err
	}
	t := securityEventsNewTailer(auditLogPath, securityEventsOffsetPath)
	_, passErr := t.securityEventsProcessPass(f, persistedOffset, rules, bindings)
	return passErr
}

// StartSecurityEventsIngestion tails the Coraza WAF audit log and ingests new
// transactions into security_events until ctx is cancelled. Blocking; call
// from a goroutine.
func StartSecurityEventsIngestion(ctx context.Context) {
	tailer := securityEventsNewTailer(securityEventsAuditLogPath, securityEventsOffsetPath)
	Logf("info", "security events ingestion started: audit_log=%s offset_file=%s", securityEventsAuditLogPath, securityEventsOffsetPath)
	ticker := time.NewTicker(securityEventsPollInterval)
	defer ticker.Stop()
	for {
		// 先采集后轮转：copytruncate 前把未摄取内容全部吃进，杜绝轮转窗口丢事件。
		if err := tailer.securityEventsTick(); err != nil {
			Logf("warn", "security events ingestion: tick failed: %v", err)
		}
		rotateAuditLogIfNeeded()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
