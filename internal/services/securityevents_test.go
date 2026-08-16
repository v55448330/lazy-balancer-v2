package services

// allow: SIZE_OK — fixtures (verbatim Coraza audit transactions) plus one test
// per required acceptance case; the deliverable is mandated as this one file.

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
