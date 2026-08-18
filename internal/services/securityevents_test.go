package services

// allow: SIZE_OK — fixtures (verbatim Coraza audit transactions) plus one test
// per required acceptance case; the deliverable is mandated as this one file.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

// Real Coraza audit transaction (pretty-printed JSON, multi-line).
const securityEventsFixtureBlocked = `{
  "transaction": {
    "timestamp": "2026/08/11 19:16:57",
    "unix_timestamp": 1786447017841320426,
    "id": "tx-blocked-1",
    "client_ip": "::1",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": "/admin/login?x=1", "headers": { "host": ["go029.com"] } },
    "response": { "status": 403 },
    "producer": { "rulesets": ["OWASP_CRS/4.28.0"] },
    "highest_severity": "CRITICAL",
    "is_interrupted": true
  },
  "messages": [
    { "message": "SQL Injection Attack Detected via libinjection", "data": { "id": 942100, "score": 5 } }
  ]
}`

const securityEventsFixtureBlockedMulti = `{
  "transaction": {
    "timestamp": "2026/08/11 19:16:57",
    "unix_timestamp": 1786447017841320,
    "id": "tx-blocked-2",
    "client_ip": "203.0.113.50",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": "/search", "headers": { "host": ["go029.com"] } },
    "is_interrupted": true
  },
  "messages": [
    { "message": "First message", "data": { "id": 942100, "score": 5 } },
    { "message": "Second message", "data": { "id": 942110, "score": 3 } }
  ]
}`

const securityEventsFixtureClean = `{
  "transaction": {
    "timestamp": "2026/08/11 19:16:58",
    "unix_timestamp": 1786447018,
    "id": "tx-clean-1",
    "client_ip": "203.0.113.9",
    "server_id": "",
    "request": { "method": "POST", "uri": "/upload", "headers": { "host": ["Example.COM:8443"] } },
    "response": { "status": 200 },
    "is_interrupted": false
  },
  "messages": []
}`

const securityEventsFixtureUnknownHost = `{
  "transaction": {
    "timestamp": "2026/08/11 19:16:59",
    "unix_timestamp": 1786447019000000000,
    "id": "tx-unknown-1",
    "client_ip": "198.51.100.7",
    "server_id": "unknown.example.com",
    "request": { "method": "GET", "uri": "/BlockedPath", "headers": { "host": ["unknown.example.com"] } },
    "is_interrupted": true
  },
  "messages": [
    { "message": "Blocked attack", "data": { "id": 949110, "score": 5 } }
  ]
}`

func TestSecurityEventsParseTransaction_BlockedMapsAllFields(t *testing.T) {
	// Given: a blocked Coraza transaction with a single rule message
	// When: parsing the raw transaction JSON
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsFixtureBlocked))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Then: every security_events column source is mapped
	if rec.EventTime != "2026-08-11 11:16:57" {
		t.Errorf("EventTime=%q, want UTC of unix_timestamp nanoseconds", rec.EventTime)
	}
	if rec.Action != "blocked" {
		t.Errorf("Action=%q, want blocked (is_interrupted)", rec.Action)
	}
	if rec.EventType != "waf" {
		t.Errorf("EventType=%q, want waf", rec.EventType)
	}
	if rec.RuleTriggered != "942100" {
		t.Errorf("RuleTriggered=%q, want 942100", rec.RuleTriggered)
	}
	if rec.RuleMsg != "SQL Injection Attack Detected via libinjection" {
		t.Errorf("RuleMsg=%q", rec.RuleMsg)
	}
	if rec.AnomalyScore != 5 {
		t.Errorf("AnomalyScore=%d, want 5", rec.AnomalyScore)
	}
	if rec.ClientIP != "::1" || rec.Method != "GET" || rec.URI != "/admin/login?x=1" {
		t.Errorf("request fields=%s %s %s", rec.ClientIP, rec.Method, rec.URI)
	}
	if rec.Host != "go029.com" {
		t.Errorf("Host=%q, want server_id", rec.Host)
	}
	if rec.TransactionID != "tx-blocked-1" {
		t.Errorf("TransactionID=%q", rec.TransactionID)
	}
}

func TestSecurityEventsParseTransaction_SumsAnomalyScoresAcrossMessages(t *testing.T) {
	// Given: a blocked transaction with two rule messages (microsecond timestamp)
	// When: parsing
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsFixtureBlockedMulti))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Then: scores sum while rule fields come from the first message
	if rec.AnomalyScore != 8 {
		t.Errorf("AnomalyScore=%d, want 8 (5+3)", rec.AnomalyScore)
	}
	if rec.RuleTriggered != "942100" || rec.RuleMsg != "First message" {
		t.Errorf("rule fields=%q/%q, want first message", rec.RuleTriggered, rec.RuleMsg)
	}
	if rec.EventTime != "2026-08-11 11:16:57" {
		t.Errorf("EventTime=%q, want UTC of unix_timestamp microseconds", rec.EventTime)
	}
}

func TestSecurityEventsParseTransaction_CleanPassThroughLogsWithoutRuleFields(t *testing.T) {
	// Given: a non-interrupted transaction with no messages and only a host header
	// When: parsing
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsFixtureClean))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Then: action is logged and rule fields stay empty
	if rec.Action != "logged" {
		t.Errorf("Action=%q, want logged", rec.Action)
	}
	if rec.RuleTriggered != "" || rec.RuleMsg != "" || rec.AnomalyScore != 0 {
		t.Errorf("rule fields=%q/%q/%d, want empty/0", rec.RuleTriggered, rec.RuleMsg, rec.AnomalyScore)
	}
	if rec.Host != "Example.COM" {
		t.Errorf("Host=%q, want host header with port stripped", rec.Host)
	}
	if rec.EventTime != "2026-08-11 11:16:58" {
		t.Errorf("EventTime=%q, want UTC of unix_timestamp seconds", rec.EventTime)
	}
}

func TestSecurityEventsMapHost_MatchesCanonicalAndReportsUnknown(t *testing.T) {
	// Given: a seeded rule for go029.com bound to policy 7
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name) VALUES (7,'policy-seven')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	rules, bindings, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	// When/Then: canonical comparison is case-insensitive and carries the resolved names
	rule, policy := securityEventsMapHost("GO029.COM", rules, bindings)
	if rule.caddyID != "lb_rule1" || policy.id != 7 {
		t.Errorf("mapHost(GO029.COM)=(%q,%d), want (lb_rule1,7)", rule.caddyID, policy.id)
	}
	if rule.name != "test rule" || policy.name != "policy-seven" {
		t.Errorf("mapHost(GO029.COM) names=(%q,%q), want (test rule,policy-seven)", rule.name, policy.name)
	}
	// When/Then: unknown hosts map to zero-value refs
	if rule, policy := securityEventsMapHost("unknown.example.com", rules, bindings); rule.caddyID != "" || policy.id != 0 {
		t.Errorf("mapHost(unknown)=(%q,%d), want (\"\",0)", rule.caddyID, policy.id)
	}
	// When/Then: bare IPs never match a domain rule
	if rule, _ := securityEventsMapHost("203.0.113.9", rules, bindings); rule.caddyID != "" {
		t.Errorf("mapHost(ip)=%q, want empty", rule.caddyID)
	}
}

func TestSecurityEventsMigration_NameColumnsExistWithDefaults(t *testing.T) {
	// Given: a freshly initialized database (createTables + runMigrations)
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	// When: inspecting the security_events snapshot columns
	rows, err := db.MetricsDB.Query(`SELECT name, "notnull", dflt_value FROM pragma_table_info('security_events') WHERE name IN ('rule_name','policy_name')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type colInfo struct {
		notnull int
		dflt    sql.NullString
	}
	got := map[string]colInfo{}
	for rows.Next() {
		var name string
		var info colInfo
		if err := rows.Scan(&name, &info.notnull, &info.dflt); err != nil {
			t.Fatal(err)
		}
		got[name] = info
	}
	// Then: both exist, NOT NULL, defaulting to ''
	for _, col := range []string{"rule_name", "policy_name"} {
		info, ok := got[col]
		if !ok {
			t.Errorf("security_events.%s missing after migrations", col)
			continue
		}
		if !info.dflt.Valid || info.dflt.String != "''" {
			t.Errorf("security_events.%s dflt=%+v, want DEFAULT ''", col, info.dflt)
		}
	}
	// And: a legacy INSERT that omits the snapshot columns stores ''
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
		VALUES ('2026-08-12 10:00:00', 'lb_legacy', 1, '192.0.2.9', 'GET', '/a', 'waf', '942100', 'SQL Injection', 'blocked')`); err != nil {
		t.Fatalf("legacy insert: %v", err)
	}
	var ruleName, policyName string
	if err := db.MetricsDB.QueryRow(`SELECT rule_name, policy_name FROM security_events`).Scan(&ruleName, &policyName); err != nil {
		t.Fatal(err)
	}
	if ruleName != "" || policyName != "" {
		t.Errorf("legacy row snapshots=(%q,%q), want both empty", ruleName, policyName)
	}
}

func TestSecurityEventsTickStoresResolvedNames(t *testing.T) {
	// Given: rule go029.com -> lb_named1 (命名规则) bound to policy 命名策略
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_named1','命名规则','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('命名策略')`)
	if err != nil {
		t.Fatal(err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_named1',?)`, policyID); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// When: running one ingest tick
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then: the stored event snapshots the names resolved at ingest time
	var ruleName, policyName string
	if err := db.MetricsDB.QueryRow(`SELECT rule_name, policy_name FROM security_events`).Scan(&ruleName, &policyName); err != nil {
		t.Fatal(err)
	}
	if ruleName != "命名规则" || policyName != "命名策略" {
		t.Errorf("stored names=(%q,%q), want (命名规则,命名策略)", ruleName, policyName)
	}
}

func TestSecurityEventsOffsetRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "security_events.offset")
	// Given: no offset file yet -> starts at 0 without error
	if got, err := securityEventsReadOffset(path); err != nil || got != 0 {
		t.Fatalf("missing file: offset=%d err=%v, want 0,nil", got, err)
	}
	// When: writing then reading back
	if err := securityEventsWriteOffset(path, 4096); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Then: the plain integer round-trips
	if got, err := securityEventsReadOffset(path); err != nil || got != 4096 {
		t.Fatalf("round-trip: offset=%d err=%v, want 4096,nil", got, err)
	}
	// And: corrupt content falls back to 0
	if err := os.WriteFile(path, []byte("not-a-number"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := securityEventsReadOffset(path); err != nil || got != 0 {
		t.Fatalf("corrupt: offset=%d err=%v, want 0,nil", got, err)
	}
}

func TestSecurityEventsShouldReset_ShrinkAndInodeChange(t *testing.T) {
	dir := t.TempDir()
	pathA := filepath.Join(dir, "a.log")
	pathB := filepath.Join(dir, "b.log")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("12345"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	infoA, err := os.Stat(pathA)
	if err != nil {
		t.Fatal(err)
	}
	infoAAgain, err := os.Stat(pathA)
	if err != nil {
		t.Fatal(err)
	}
	infoB, err := os.Stat(pathB)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name         string
		offset, size int64
		prev, curr   os.FileInfo
		wantReset    bool
	}{
		{name: "file shrank below offset", offset: 100, size: 50, prev: infoA, curr: infoAAgain, wantReset: true},
		{name: "same inode, healthy size", offset: 5, size: 10, prev: infoA, curr: infoAAgain, wantReset: false},
		{name: "inode changed (rotation)", offset: 5, size: 10, prev: infoA, curr: infoB, wantReset: true},
		{name: "first pass has no previous inode", offset: 5, size: 10, prev: nil, curr: infoA, wantReset: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := securityEventsShouldReset(tt.offset, tt.size, tt.prev, tt.curr); got != tt.wantReset {
				t.Errorf("securityEventsShouldReset=%v, want %v", got, tt.wantReset)
			}
		})
	}
}

func TestSecurityEventsTickIngestsFixtureLog(t *testing.T) {
	// Given: a DB with rule go029.com -> lb_rule1 -> policy 7 and an audit log with 2 transactions
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	content := strings.Join([]string{securityEventsFixtureBlocked, securityEventsFixtureUnknownHost}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When: running one ingest tick
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then: both transactions are inserted with rule/policy mapping applied
	type row struct {
		ruleID, action, triggered, msg, ip, method, uri, eventTime string
		policyID, score                                            int
	}
	rows, err := db.MetricsDB.Query(`SELECT rule_caddy_id, policy_id, action, anomaly_score, rule_triggered, rule_msg, client_ip, method, uri, CAST(event_time AS TEXT) FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.ruleID, &r.policyID, &r.action, &r.score, &r.triggered, &r.msg, &r.ip, &r.method, &r.uri, &r.eventTime); err != nil {
			t.Fatal(err)
		}
		got = append(got, r)
	}
	if len(got) != 2 {
		t.Fatalf("rows=%d, want 2: %+v", len(got), got)
	}
	want0 := row{ruleID: "lb_rule1", policyID: 7, action: "blocked", score: 5, triggered: "942100", msg: "SQL Injection Attack Detected via libinjection", ip: "::1", method: "GET", uri: "/admin/login?x=1", eventTime: "2026-08-11 11:16:57"}
	if got[0] != want0 {
		t.Errorf("row0=%+v\nwant %+v", got[0], want0)
	}
	want1 := row{ruleID: "", policyID: 0, action: "blocked", score: 5, triggered: "949110", msg: "Blocked attack", ip: "198.51.100.7", method: "GET", uri: "/BlockedPath", eventTime: "2026-08-11 11:16:59"}
	if got[1] != want1 {
		t.Errorf("row1=%+v\nwant %+v", got[1], want1)
	}

	// And: the offset is persisted at the end of the last document
	// (the decoder stops after the closing brace; the trailing newline
	// is consumed on the next pass)
	offset, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(len(content) - 1); offset != want {
		t.Errorf("offset=%d, want %d (file size minus trailing newline)", offset, want)
	}

	// When: ticking again with no new data
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("second tick: %v", err)
	}
	// Then: nothing is duplicated
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Errorf("count after idle tick=%d, want 2", count)
	}

	// When: a new transaction is appended and another tick runs
	appended := strings.Replace(securityEventsFixtureClean, "/upload", "/again", 1)
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(appended + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("third tick: %v", err)
	}
	// Then: only the new row is added, resuming from the persisted offset
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("count after append=%d, want 3", count)
	}
	var uri, action string
	if err := db.MetricsDB.QueryRow(`SELECT uri, action FROM security_events ORDER BY id DESC LIMIT 1`).Scan(&uri, &action); err != nil {
		t.Fatal(err)
	}
	if uri != "/again" || action != "logged" {
		t.Errorf("appended row uri=%q action=%q, want /again logged", uri, action)
	}
}

func TestSecurityEventsIngestRotatedDelta_recoversRotationWindowEvents(t *testing.T) {
	// Given: DB with rule go029.com -> lb_rule1, an audit log with transaction A,
	// and a tick that ingests A and persists its offset
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	// 轮转函数与补采函数读包级路径/阈值，测试注入临时路径与极小阈值
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	fixtureA := securityEventsFixtureBlocked + "\n"
	if err := os.WriteFile(logPath, []byte(fixtureA), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after first tick=%d, want 1", count)
	}

	// When: transaction B is appended (the tick never saw it) and rotation runs
	// — copytruncate moves [A+B] into audit.log.1 and truncates the live file,
	// leaving B only in the archive
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(securityEventsFixtureUnknownHost + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	rotateAuditLogIfNeeded()

	// Then: the rotated-delta ingest recovered B from the archive window
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after rotation=%d, want 2 (A + rotation-window B)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-unknown-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/BlockedPath" {
		t.Fatalf("recovered window event uri=%q, want /BlockedPath", uri)
	}

	// And: the tailer still resumes on the truncated live file — a new append C
	// is ingested by the next tick without duplicating A/B
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureClean+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("post-rotation tick: %v", err)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("rows after post-rotation tick=%d, want 3 (A + B + C)", count)
	}
}

func TestSecurityEventsTickDedupesDuplicateTransactionID(t *testing.T) {
	// Given：审计日志中同一事务出现两次（模拟轮转/重放导致的重复读取）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','test rule','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	content := strings.Join([]string{securityEventsFixtureBlocked, securityEventsFixtureBlocked}, "\n") + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When：运行一次摄取
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then：transaction_id 唯一索引去重，同一事务只落一行
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("duplicate transaction id must dedupe to 1 row, got %d", count)
	}
	var txID string
	if err := db.MetricsDB.QueryRow(`SELECT transaction_id FROM security_events`).Scan(&txID); err != nil {
		t.Fatal(err)
	}
	if txID != "tx-blocked-1" {
		t.Fatalf("stored transaction_id=%q, want tx-blocked-1", txID)
	}
}

func TestSecurityEventsTickSkipsMalformedAndContinues(t *testing.T) {
	// Given: an audit log with garbage bytes and a non-transaction JSON between valid docs
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	content := securityEventsFixtureBlocked + "\nGARBAGE BYTES\n" + `{"unexpected": true}` + "\n" + securityEventsFixtureClean + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When: running one ingest tick
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then: both valid transactions are ingested and the malformed entries were skipped
	rows, err := db.MetricsDB.Query(`SELECT uri FROM security_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var uris []string
	for rows.Next() {
		var uri string
		if err := rows.Scan(&uri); err != nil {
			t.Fatal(err)
		}
		uris = append(uris, uri)
	}
	if len(uris) != 2 || uris[0] != "/admin/login?x=1" || uris[1] != "/upload" {
		t.Errorf("uris=%v, want [/admin/login?x=1 /upload]", uris)
	}
}

func TestSecurityEventsParseTransaction_rejectsEmptyID(t *testing.T) {
	// Given：同一事务但 transaction_id 为空（去重唯一索引 WHERE transaction_id!=''
	// 覆盖不到，重试路径会重复插入）
	noID := strings.Replace(securityEventsFixtureBlocked, `"id": "tx-blocked-1",`, `"id": "",`, 1)
	// When：解析
	_, err := securityEventsParseTransaction(json.RawMessage(noID))
	// Then：视为解析失败拒绝
	if err == nil {
		t.Fatalf("empty transaction_id must be rejected as parse failure")
	}
	if !errors.Is(err, errSecurityEventsEmptyID) {
		t.Fatalf("err=%v, want errSecurityEventsEmptyID", err)
	}
}

func TestSecurityEventsTickSkipsTransactionWithoutIDAndContinues(t *testing.T) {
	// Given：日志含一个空 transaction_id 的事务 + 一个正常事务
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	noID := strings.Replace(securityEventsFixtureBlocked, `"id": "tx-blocked-1",`, `"id": "",`, 1)
	content := noID + "\n" + securityEventsFixtureClean + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When：运行一次摄取
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then：空 id 事务不产生事件记录，后续正常事务仍被摄取
	rows, err := db.MetricsDB.Query(`SELECT transaction_id, uri FROM security_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []struct{ tx, uri string }
	for rows.Next() {
		var tx, uri string
		if err := rows.Scan(&tx, &uri); err != nil {
			t.Fatal(err)
		}
		got = append(got, struct{ tx, uri string }{tx, uri})
	}
	if len(got) != 1 || got[0].tx != "tx-clean-1" || got[0].uri != "/upload" {
		t.Fatalf("rows=%+v, want single tx-clean-1 /upload（空 id 事务必须跳过）", got)
	}
}

func TestRotateAuditLog_ingestsLiveTailWrittenBetweenCopyAndTruncate(t *testing.T) {
	// Given：日志含事务 A（tick 已摄取并持久化偏移）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile
	})
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after tick=%d, want 1", count)
	}

	// When：copy 完成后、truncate 前 Coraza 把事务 C 写入活文件（残余窗口事件，
	// 只在活文件、不在 .1）
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(securityEventsFixtureClean + "\n")
		return err
	}
	rotateAuditLogIfNeeded()

	// Then：活文件尾部事件在 truncate 前被补采入库
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after rotation=%d, want 2 (A + live-tail C)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-clean-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/upload" {
		t.Fatalf("live-tail event uri=%q, want /upload", uri)
	}
}

func TestRotateAuditLog_retriesPendingDeltaBeforeShifting(t *testing.T) {
	// Given：日志含 A（tick 已摄取）+ B（tick 后追加，只存在于归档窗口）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(securityEventsFixtureUnknownHost + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	// When：指标库故障导致轮转后补采失败 → pending 标记落盘
	_ = db.MetricsDB.Close()
	rotateAuditLogIfNeeded()
	marker := securityEventsPendingDeltaPath()
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("pending marker must exist after failed delta ingest: %v", err)
	}
	// Then：F5 崩溃窗口（truncate 已执行、补采未完成）——活文件已清空但标记
	// 因先于 truncate 落盘而幸存，.1 仍保存 B，下次轮转可恢复
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() != 0 {
		t.Fatalf("live log size=%d after failed ingest, want 0 (truncated)", liveInfo.Size())
	}

	// When：指标库恢复后再次轮转 → shift 前先重试补采成功、标记清除、B 入库
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	rotateAuditLogIfNeeded()
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("pending marker must be removed after successful retry, stat err=%v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after retry=%d, want 2 (A + recovered B)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-unknown-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/BlockedPath" {
		t.Fatalf("recovered event uri=%q, want /BlockedPath", uri)
	}
}

func TestSecurityEventsTick_reportsErrorBeyondScanWindow(t *testing.T) {
	// Given：日志含正常事务 + ≥4MB 无文档头畸形区（崩溃残片）+ 后续正常事务，
	// 且指标库就绪
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	content := securityEventsFixtureBlocked + "\n" + strings.Repeat("x", securityEventsScanWindowLimit+4096) + "\n" + securityEventsFixtureClean + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When：运行一次摄取
	err := tailer.securityEventsTick()

	// Then：畸形区判定为无法自愈，返回错误暴露停摆（而非原地成功打转）
	if err == nil || !strings.Contains(err.Error(), "scan window") {
		t.Fatalf("tick err=%v, want beyond-scan-window error", err)
	}
	// And：畸形区之前的事务仍入库且偏移推进（已提交部分不丢）
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows=%d, want 1 (document before garbage region)", count)
	}
	offset, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if offset == 0 {
		t.Fatalf("offset=%d, want advanced past the first document", offset)
	}

	// When：启动与生产一致的摄取循环（tick 失败走 warn 路径）
	oldAuditLog, oldAuditOffset := auditLogPath, securityEventsOffsetPath
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	t.Cleanup(func() { auditLogPath, securityEventsOffsetPath = oldAuditLog, oldAuditOffset })
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartSecurityEventsIngestion(ctx)
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(buf.String(), "tick failed") {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	// Then：停摆以 warn 暴露（日志含 "tick failed"），而非静默打转
	if !strings.Contains(buf.String(), "tick failed") {
		t.Fatalf("ingestion loop must log warn for stalled tick, captured: %s", buf.String())
	}
}

func TestRotateAuditLog_recoversCrossBoundaryTransaction(t *testing.T) {
	// Given：日志含 A（tick 已摄取）+ 事务 T 的前半（copy 末次读截断在 T 中部，
	// 前缀将只存在于 .1、后缀只追加到活文件——跨界事务两路补采各自不完整）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile
	})
	fixtureT := securityEventsFixtureUnknownHost
	split := strings.Index(fixtureT, `"uri":`)
	if split <= 0 {
		t.Fatalf("fixture split point not found")
	}
	prefix, suffix := fixtureT[:split], fixtureT[split:]
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"+prefix), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after tick=%d, want 1 (incomplete prefix not ingested)", count)
	}

	// When：copy 完成后 Coraza 补写完 T 的后半（后缀只在活文件，.1 中 T 仍不完整）
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(suffix)
		return err
	}
	rotateAuditLogIfNeeded()

	// Then：跨界事务 T 完整入库（活文件补采从 T 文档头后向回扫重新解码）
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after rotation=%d, want 2 (A + cross-boundary T)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-unknown-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/BlockedPath" {
		t.Fatalf("cross-boundary event uri=%q, want /BlockedPath", uri)
	}
}

func TestSecurityEventsPendingDeltaMarker_atomicWriteAndRead(t *testing.T) {
	// Given：临时日志路径下的 pending 标记位置
	dir := t.TempDir()
	oldLogPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit.log")
	t.Cleanup(func() { auditLogPath = oldLogPath })
	p := securityEventsPendingDelta{Path: filepath.Join(dir, "audit.log.1"), Offset: 1234, Size: 5678}

	// When：写入标记
	if err := securityEventsWritePendingDelta(p); err != nil {
		t.Fatal(err)
	}

	// Then：原子落盘完成（无 .tmp 残留），内容完整可读回
	if _, err := os.Stat(securityEventsPendingDeltaPath() + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("tmp file must be cleaned up after atomic rename, stat err=%v", err)
	}
	got := securityEventsReadPendingDelta()
	if got == nil || got.Path != p.Path || got.Offset != p.Offset || got.Size != p.Size {
		t.Fatalf("read back=%+v, want %+v", got, p)
	}
	// And：损坏（半写）内容被读取端容错视为无标记
	if err := os.WriteFile(securityEventsPendingDeltaPath(), []byte(`{"path": "broken`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := securityEventsReadPendingDelta(); got != nil {
		t.Fatalf("corrupt marker must read as nil, got %+v", got)
	}
}

func TestSecurityEventsTick_warnRateLimitedPerOffset(t *testing.T) {
	// Given：日志含正常事务 + ≥4MB 无文档头畸形区 + 后续事务（F1 停摆场景，
	// 偏移永久卡在畸形区前）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	content := securityEventsFixtureBlocked + "\n" + strings.Repeat("x", securityEventsScanWindowLimit+4096) + "\n" + securityEventsFixtureClean + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	oldAuditLog, oldAuditLogPath, oldOffsetPath, oldInterval := auditLogPath, securityEventsAuditLogPath, securityEventsOffsetPath, securityEventsPollInterval
	auditLogPath, securityEventsAuditLogPath, securityEventsOffsetPath = logPath, logPath, offsetPath
	securityEventsPollInterval = 100 * time.Millisecond
	t.Cleanup(func() {
		auditLogPath, securityEventsAuditLogPath, securityEventsOffsetPath, securityEventsPollInterval = oldAuditLog, oldAuditLogPath, oldOffsetPath, oldInterval
	})
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	// When：摄取循环运行多个 tick（同一偏移反复 F1，旧行为每 tick 一条 warn）
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		StartSecurityEventsIngestion(ctx)
		close(done)
	}()
	time.Sleep(1200 * time.Millisecond) // ≥ 10 个 tick
	cancel()
	<-done

	// Then：同一偏移的停摆告警只出现一条（按偏移限流），而非每 tick 刷屏
	warns := strings.Count(buf.String(), "tick failed")
	if warns != 1 {
		t.Fatalf("warn count=%d, want 1 (rate-limited per offset), captured: %s", warns, buf.String())
	}
}

func TestRotateAuditLog_skipsMalformedRegionInArchive(t *testing.T) {
	// Given：日志含 A（tick 已摄取）+ ≥4MB 畸形区 + B（tick 被畸形区卡住停采）——
	// 轮转归档后补采必须跳过畸形区恢复摄取 B，否则 pending 标记永留、轮转死锁
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	content := securityEventsFixtureBlocked + "\n" + strings.Repeat("x", securityEventsScanWindowLimit+4096) + "\n" + securityEventsFixtureUnknownHost + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err == nil || !strings.Contains(err.Error(), "scan window") {
		t.Fatalf("tick err=%v, want beyond-scan-window error (precondition)", err)
	}

	// When：轮转——归档含畸形区 + B，补采走归档 scan-to-EOF 恢复
	rotateAuditLogIfNeeded()

	// Then：畸形区之后的 B 入库、轮转正常推进（标记清除、活文件已截断）
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows=%d, want 2 (A + B after garbage)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-unknown-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/BlockedPath" {
		t.Fatalf("recovered event uri=%q, want /BlockedPath", uri)
	}
	if _, err := os.Stat(securityEventsPendingDeltaPath()); !os.IsNotExist(err) {
		t.Fatalf("pending marker must be cleared after successful archive ingest, stat err=%v", err)
	}
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() != 0 {
		t.Fatalf("live log size=%d, want 0 (rotation truncated)", liveInfo.Size())
	}
	if !strings.Contains(buf.String(), "skipping unreadable audit data") {
		t.Fatalf("expected one skip error log, captured: %s", buf.String())
	}
}

func TestRotateAuditLog_endsPassWhenArchiveGarbageUnrecoverable(t *testing.T) {
	// Given：日志含 A + ≥4MB 畸形区在尾部（无后续事件，scan-to-EOF 找不到文档头）
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	content := securityEventsFixtureBlocked + "\n" + strings.Repeat("x", securityEventsScanWindowLimit+4096)
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	oldWriter := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(oldWriter) })

	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err == nil || !strings.Contains(err.Error(), "scan window") {
		t.Fatalf("tick err=%v, want beyond-scan-window error (precondition)", err)
	}

	// When：轮转——归档补采 scan-to-EOF 找不到下一个文档头
	rotateAuditLogIfNeeded()

	// Then：记一条 error 日志并结束该 pass（区域不可恢复），轮转照常推进：
	// 标记清除、活文件已截断、已摄取事件保留
	if !strings.Contains(buf.String(), "unrecoverable unreadable audit data") {
		t.Fatalf("expected unrecoverable-region error log, captured: %s", buf.String())
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows=%d, want 1 (A only)", count)
	}
	if _, err := os.Stat(securityEventsPendingDeltaPath()); !os.IsNotExist(err) {
		t.Fatalf("pending marker must be cleared, stat err=%v", err)
	}
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() != 0 {
		t.Fatalf("live log size=%d, want 0 (rotation truncated)", liveInfo.Size())
	}
}

func TestRotateAuditLog_backscanFindsStraddleDocStartBeyond8MB(t *testing.T) {
	// Given：日志含 A + 事务 T 的前缀，T 文档头在归档起点 8MB 之前（旧固定 8MB
	// 窗口回扫会漏掉文档头，跨界事务 T 两半皆失）；copy 完成后补写 T 的后缀
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes, auditLogCopyFile = oldLogPath, oldOffsetPath, oldSizeBytes, oldCopyFile
	})
	// 单个事务超过 8MB（巨型 uri 字符串），前缀 9MB > 8MB 固定窗口
	fixtureT := `{
  "transaction": {
    "timestamp": "2026/08/11 19:16:57",
    "unix_timestamp": 1786447017841320426,
    "id": "tx-huge-straddle",
    "client_ip": "198.51.100.8",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": "/huge/` + strings.Repeat("a", 9<<20) + `", "headers": { "host": ["go029.com"] } },
    "is_interrupted": true
  },
  "messages": []
}`
	split := 9 << 20 // 截断点深入 uri 字符串内部
	prefix, suffix := fixtureT[:split], fixtureT[split:]
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"+prefix), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err == nil || !strings.Contains(err.Error(), "scan window") {
		t.Fatalf("tick err=%v, want beyond-scan-window error (incomplete straddle prefix)", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after tick=%d, want 1 (A only)", count)
	}

	// When：copy 完成后 Coraza 补写完 T 的后缀（后缀只在活文件，.1 中 T 仍不完整）
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(suffix)
		return err
	}
	rotateAuditLogIfNeeded()

	// Then：全量回扫找到 8MB 之前的文档头 → 跨界事务 T 完整入库、轮转正常推进
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after rotation=%d, want 2 (A + straddled T)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-huge-straddle'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "/huge/") || len(uri) != len("/huge/")+9<<20 {
		t.Fatalf("straddled event uri length=%d, want full 9MB uri", len(uri))
	}
	if _, err := os.Stat(securityEventsPendingDeltaPath()); !os.IsNotExist(err) {
		t.Fatalf("pending marker must be cleared, stat err=%v", err)
	}
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() != 0 {
		t.Fatalf("live log size=%d, want 0 (rotation truncated)", liveInfo.Size())
	}
}

func TestRotateAuditLog_abortsRotationWhenMarkerWriteFails(t *testing.T) {
	// Given：日志含 A（tick 已摄取）、超过轮转阈值
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	oldLogPath, oldOffsetPath, oldSizeBytes := auditLogPath, securityEventsOffsetPath, auditLogSizeBytes
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	auditLogSizeBytes = func() int64 { return 1 }
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, auditLogSizeBytes = oldLogPath, oldOffsetPath, oldSizeBytes
	})
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after tick=%d, want 1", count)
	}

	// When：pending 标记路径被目录占据导致原子 rename 失败（模拟标记写失败）
	if err := os.MkdirAll(securityEventsPendingDeltaPath(), 0o755); err != nil {
		t.Fatal(err)
	}
	liveSize := func() int64 {
		info, err := os.Stat(logPath)
		if err != nil {
			t.Fatal(err)
		}
		return info.Size()
	}
	before := liveSize()
	rotateAuditLogIfNeeded()

	// Then：轮转在 truncate 前中止——活文件内容完整（绝不无标记截断），
	// 已摄取事件保留，下周期重试
	if after := liveSize(); after != before {
		t.Fatalf("live log size=%d, want %d (must not truncate without marker)", after, before)
	}
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows=%d, want 1 (no data loss)", count)
	}
}
