package services

// allow: SIZE_OK — fixtures (verbatim Coraza audit transactions) plus one test
// per required acceptance case; the deliverable is mandated as this one file.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
)

// syncBuffer is a bytes.Buffer guarded by a mutex for concurrent write/poll.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// Real Coraza audit transaction (pretty-printed JSON, multi-line). Message
// shape mirrors coraza v3's JSON formatter: data.id 是规则 ID，data.raw 是规则
// 原文，msg 携带宏展开后的文本；阻断评估规则（949110）的 msg 报告累计总分。
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
    { "message": "SQL Injection Attack Detected via libinjection", "data": { "id": 942100, "raw": "SecRule ARGS \"@detectSQLi\" \"id:942100,phase:2,block,log,msg:'SQL Injection Attack Detected via libinjection'\"" } },
    { "message": "Inbound Anomaly Score Exceeded (Total Score: 5)", "data": { "id": 949110, "raw": "SecRule TX:ANOMALY_SCORE \"@ge %{TX.INBOUND_ANOMALY_SCORE_THRESHOLD}\" \"id:949110,phase:2,deny,log,msg:'Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})'\"" } }
  ]
}`

// 自定义规则拦截事务：phase 1 deny 直接中断，949 评估不会执行——评分信号只剩
// raw 动作串里的 setvar:+N 字面量（两条命中规则 +5/+3 求和）。
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
    { "message": "First message", "data": { "id": 10001, "raw": "SecRule REQUEST_URI \"@contains /search\" \"id:10001,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'First message'\"" } },
    { "message": "Second message", "data": { "id": 10002, "raw": "SecRule ARGS \"@rx bad\" \"id:10002,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+3,msg:'Second message'\"" } }
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
    { "message": "Inbound Anomaly Score Exceeded (Total Score: 5)", "data": { "id": 949110, "raw": "id:949110,phase:2,deny,log" } }
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

func TestSecurityEventsParseTransaction_SumsSetvarScoresAcrossMessages(t *testing.T) {
	// Given: a phase-1 custom-rule interruption with two matched rules (+5/+3 setvar)
	// When: parsing
	rec, err := securityEventsParseTransaction(json.RawMessage(securityEventsFixtureBlockedMulti))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// Then: setvar contributions sum while rule fields come from the first message
	if rec.AnomalyScore != 8 {
		t.Errorf("AnomalyScore=%d, want 8 (5+3)", rec.AnomalyScore)
	}
	if rec.RuleTriggered != "10001" || rec.RuleMsg != "First message" {
		t.Errorf("rule fields=%q/%q, want first message", rec.RuleTriggered, rec.RuleMsg)
	}
	if rec.EventTime != "2026-08-11 11:16:57" {
		t.Errorf("EventTime=%q, want UTC of unix_timestamp microseconds", rec.EventTime)
	}
}

func TestSecurityEventsParseTransaction_TotalScoreBeatsSetvarSum(t *testing.T) {
	// Given: a blocked CRS transaction whose 949110 message reports the running
	// total (7) alongside a custom rule setvar (+5) — the evaluated total is
	// authoritative because it already includes every contribution
	raw := `{
  "transaction": { "unix_timestamp": 1786447017, "id": "tx-max-1", "client_ip": "203.0.113.60",
    "server_id": "go029.com", "request": { "method": "GET", "uri": "/x", "headers": {} },
    "is_interrupted": true },
  "messages": [
    { "message": "Custom hit", "data": { "id": 10001, "raw": "id:10001,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'Custom hit'" } },
    { "message": "Inbound Anomaly Score Exceeded in phase 1 (Total Score: 7)", "data": { "id": 949111, "raw": "" } },
    { "message": "Outbound Anomaly Score Exceeded (Total Score: 3)", "data": { "id": 959100, "raw": "" } }
  ]
}`
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.AnomalyScore != 7 {
		t.Errorf("AnomalyScore=%d, want 7 (max of inbound/outbound totals, not 5 setvar / 3 outbound)", rec.AnomalyScore)
	}
}

func TestSecurityEventsParseTransaction_RealCustomRuleAuditShape(t *testing.T) {
	// Given: a transaction captured verbatim from the live audit log (custom rule
	// deny in phase 1) — no score field exists anywhere in the real format
	raw := `{
  "transaction": {
    "unix_timestamp": 1759277134212248000, "id": "negHfpusbqgfuHpT", "client_ip": "::1",
    "server_id": "localhost", "request": { "method": "GET", "uri": "/", "headers": { "host": ["localhost"] } },
    "is_interrupted": true },
  "messages": [
    { "message": "自定义规则 测试 UA 拦截 命中", "data": { "file": "_inline_", "line": 8, "id": 10006, "rev": "",
      "msg": "自定义规则 测试 UA 拦截 命中", "data": "", "severity": -1, "ver": "", "maturity": 0, "accuracy": 0, "tags": [],
      "raw": "SecRule REQUEST_HEADERS:User-Agent \"@contains curl/\" \"id:10006,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'自定义规则 测试 UA 拦截 命中'\"" } }
  ]
}`
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.RuleTriggered != "10006" || rec.RuleMsg != "自定义规则 测试 UA 拦截 命中" {
		t.Errorf("rule fields=%q/%q, want 10006 and the custom-rule message", rec.RuleTriggered, rec.RuleMsg)
	}
	if rec.AnomalyScore != 5 {
		t.Errorf("AnomalyScore=%d, want 5 from the setvar literal (was always 0 before the fix)", rec.AnomalyScore)
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
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,mode) VALUES (7,'policy-seven','blocking')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',7)`); err != nil {
		t.Fatal(err)
	}
	rules, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	// When/Then: canonical comparison is case-insensitive and carries the resolved names
	rule := securityEventsMapHost("GO029.COM", rules)
	if rule.caddyID != "lb_rule1" || rule.name != "test rule" {
		t.Errorf("mapHost(GO029.COM)=(%q,%q), want (lb_rule1,test rule)", rule.caddyID, rule.name)
	}
	// And: attribution resolves policy 7 (crs_rule_groups 空数组 = 包含全部 CRS 规则)
	pid, pname := securityEventsAttributePolicy(rule.caddyID, "942100", "blocked", "", policyByID, bindings)
	if pid != 7 || pname != "policy-seven" {
		t.Errorf("attributePolicy=(%d,%q), want (7,policy-seven)", pid, pname)
	}
	// When/Then: unknown hosts map to zero-value rule, attribution returns zero
	if rule := securityEventsMapHost("unknown.example.com", rules); rule.caddyID != "" {
		t.Errorf("mapHost(unknown)=%q, want \"\"", rule.caddyID)
	}
	if pid, pname := securityEventsAttributePolicy("", "942100", "blocked", "", policyByID, bindings); pid != 0 || pname != "" {
		t.Errorf("attributePolicy(empty)=(%d,%q), want (0,\"\")", pid, pname)
	}
	// When/Then: bare IPs never match a domain rule
	if rule := securityEventsMapHost("203.0.113.9", rules); rule.caddyID != "" {
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
	res, err := db.DB.Exec(`INSERT INTO security_policies (name,mode) VALUES ('命名策略','blocking')`)
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

func TestSecurityEventsFindNextDocument_boundedBufferOnSmallTail(t *testing.T) {
	// N+11 D3-F2：扫描缓冲按 min(4MB, size-from) 定界（f.Stat）——硬杀残片
	// 留下 <4KB 小文件时，每次 2s tick 的解码失败不再分配整块 4MB 窗口。
	// 定位行为保持不变；from 到/超 EOF 时零读取直接未找到。
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	full := `{"transaction":{"id":"tx-a","unix_timestamp":1,"request":{"method":"GET","uri":"/"}}}`
	tail := `{"transaction":{"id":"tx-b","unix_timestamp":2,` // 截断残尾，内部无文档头
	content := full + "\n" + tail
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	// When/Then：从 0 起找到第二文档头（第一文档尾换行后的 `{`）
	pos, found, err := securityEventsFindNextDocument(f, 0)
	if err != nil {
		t.Fatalf("find: %v", err)
	}
	if !found {
		t.Fatal("second document head must be found in a small tail")
	}
	if want := int64(len(full) + 1); pos != want {
		t.Fatalf("pos=%d, want %d (byte after the first document's newline)", pos, want)
	}
	// When/Then：截断残尾内部起点——无文档头，未找到且无错误
	if _, found, err := securityEventsFindNextDocument(f, pos+1); err != nil || found {
		t.Fatalf("find in tail: found=%v err=%v, want (false,nil)", found, err)
	}
	// When/Then：from 在/超 EOF——定界为零字节，未找到且无错误
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for _, from := range []int64{info.Size(), info.Size() + 1} {
		if _, found, err := securityEventsFindNextDocument(f, from); err != nil || found {
			t.Fatalf("from=%d: found=%v err=%v, want (false,nil)", from, found, err)
		}
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
	// 启用策略 7（crs_rule_groups 空数组 = 包含全部 CRS 规则）：绑定必须指向
	// 真实存在的启用策略，归因才会在 contains 路径命中而非悬空回退零值。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES (7,'policy-seven',1,'blocking','[]','[]')`); err != nil {
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
	want1 := row{ruleID: "", policyID: 0, action: "blocked", score: 5, triggered: "949110", msg: "Inbound Anomaly Score Exceeded (Total Score: 5)", ip: "198.51.100.7", method: "GET", uri: "/BlockedPath", eventTime: "2026-08-11 11:16:59"}
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

func TestSecurityEventsTick_idleTickSkipsMappingLoad(t *testing.T) {
	// N+11 D3-F5a：空闲 tick（上次干净 pass 后无新增字节）不得重载映射
	// （3 条主库查询 + 逐行 IDNA）。seam：首次干净 tick 后把主库置 nil——
	// 若空闲 tick 仍调 loadMappings 会返回 "database not initialized"；
	// 追加新事务后应照常恢复摄取。
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	oldDB := db.DB
	t.Cleanup(func() { db.DB = oldDB })
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureBlocked+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When：首个 tick 正常摄取
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("first tick: %v", err)
	}
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("rows after first tick=%d, want 1", count)
	}

	// When：主库失效（nil）且文件不变时连续两个空闲 tick
	db.DB = nil
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("idle tick with nil main DB: %v, want nil (mapping load must be skipped)", err)
	}
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("second idle tick: %v, want nil", err)
	}
	db.DB = oldDB

	// When：追加新事务后 tick
	f, err := os.OpenFile(logPath, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(securityEventsFixtureClean + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick after append: %v", err)
	}
	// Then：新事务入库、无重复（空闲跳过不得卡死恢复）
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows after append=%d, want 2 (skip must not stall resumption)", count)
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
	// When: running ingest ticks until the stall limit trips the skip path
	//（SECLB35-1：残缺数据先原地等待重试，连续 securityEventsDecodeStallLimit
	// 个 tick 仍失败才跳过——旧的「单 tick 立即跳过」正是并发窗口丢事件的根因）
	for i := 0; i < securityEventsDecodeStallLimit; i++ {
		if err := tailer.securityEventsTick(); err == nil {
			t.Fatalf("tick %d within stall limit: expected stall wait, got nil", i+1)
		}
	}
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick after stall limit: %v", err)
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
	var buf syncBuffer
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
	// R65 B-S4：审计日志路径收敛为单一 auditLogPath（原 securityEventsAuditLogPath 双 var 已删）。
	oldAuditLog, oldOffsetPath, oldInterval := auditLogPath, securityEventsOffsetPath, securityEventsPollInterval
	auditLogPath, securityEventsOffsetPath = logPath, offsetPath
	securityEventsPollInterval = 100 * time.Millisecond
	t.Cleanup(func() {
		auditLogPath, securityEventsOffsetPath, securityEventsPollInterval = oldAuditLog, oldOffsetPath, oldInterval
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

func TestRotateAuditLog_liveTailGarbageDoesNotBlockRotation(t *testing.T) {
	// Given：日志含 A（tick 已摄取）+ ≥4MB 畸形区 + B（tick 被畸形区卡住停采）；
	// copy 完成后 Coraza 再写入 ≥4MB 畸形区 C——活文件补采区间 [archSize, EOF)
	// 整体为畸形区，旧行为（archive=false）F1 报错中止轮转：每 2s 周期反复复制
	// 更大文件、永不截断（R33 F1 死锁）
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
	garbage := strings.Repeat("x", securityEventsScanWindowLimit+4096)
	content := securityEventsFixtureBlocked + "\n" + garbage + "\n" + securityEventsFixtureUnknownHost + "\n"
	if err := os.WriteFile(logPath, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)
	if err := tailer.securityEventsTick(); err == nil || !strings.Contains(err.Error(), "scan window") {
		t.Fatalf("tick err=%v, want beyond-scan-window error (precondition)", err)
	}
	// When：copy 完成后活文件尾部追加 ≥4MB 畸形区（补采区间全部不可解码）
	auditLogCopyFile = func(src, dst string) error {
		if err := copyAuditLogTo(src, dst); err != nil {
			return err
		}
		f, err := os.OpenFile(src, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.WriteString(strings.Repeat("z", securityEventsScanWindowLimit+4096) + "\n")
		return err
	}
	rotateAuditLogIfNeeded()
	// Then：轮转正常推进——活文件已截断、标记清除、B 入库（A + B 两行）
	var count int
	if err := db.MetricsDB.QueryRow(`SELECT COUNT(*) FROM security_events`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("rows=%d, want 2 (A + B after garbage tail)", count)
	}
	var uri string
	if err := db.MetricsDB.QueryRow(`SELECT uri FROM security_events WHERE transaction_id='tx-unknown-1'`).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != "/BlockedPath" {
		t.Fatalf("event uri=%q, want /BlockedPath", uri)
	}
	if _, err := os.Stat(securityEventsPendingDeltaPath()); !os.IsNotExist(err) {
		t.Fatalf("pending marker must be cleared after rotation, stat err=%v", err)
	}
	liveInfo, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if liveInfo.Size() != 0 {
		t.Fatalf("live log size=%d, want 0 (rotation must truncate despite garbage tail)", liveInfo.Size())
	}
}

func TestSecurityEventsBackscanDocumentStart_crossChunkBoundary(t *testing.T) {
	// Given：唯一 "\n{" 跨 1MB 分块边界——'\n' 恰为 [0, 1MB) 块末字节、
	// '{' 恰为 [1MB, ...) 块首字节（分块回扫必须识别跨块文档头，R33 F3）
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	content := strings.Repeat("a", 1<<20-1) + "\n{" + strings.Repeat("b", 1<<20-2)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	// When：回扫 [0, len) 找最近文档头
	got, err := securityEventsBackscanDocumentStart(path, int64(len(content)))
	// Then：返回跨块 '\n{' 的 '{' 位置（1MB），而非回退 from
	if err != nil {
		t.Fatal(err)
	}
	if want := int64(1 << 20); got != want {
		t.Fatalf("backscan=%d, want %d (cross-chunk doc start)", got, want)
	}
	// And：文件超过 from 时结果与整块语义一致（截断点之前无文档头则回退 from）
	if got, err := securityEventsBackscanDocumentStart(path, 100); err != nil || got != 100 {
		t.Fatalf("backscan(100)=(%d,%v), want (100,nil)", got, err)
	}
	// And：from=0 直接返回 0（空读安全路径）
	if got, err := securityEventsBackscanDocumentStart(path, 0); err != nil || got != 0 {
		t.Fatalf("backscan(0)=(%d,%v), want (0,nil)", got, err)
	}
}

// SC-EVT-01 fixture：可变规则 ID 的 Coraza 事务模板。
func securityEventsFixtureForRule(ruleID string) string {
	return `{
  "transaction": {
    "timestamp": "2026/08/12 10:00:00",
    "unix_timestamp": 1786447017841320426,
    "id": "tx-attr-` + ruleID + `",
    "client_ip": "198.51.100.9",
    "server_id": "go029.com",
    "request": { "method": "GET", "uri": "/attr", "headers": { "host": ["go029.com"] } },
    "is_interrupted": true
  },
  "messages": [
    { "message": "hit ` + ruleID + `", "data": { "id": ` + ruleID + `, "raw": "id:` + ruleID + `,phase:1,deny,log,setvar:tx.inbound_anomaly_score_pl1=+5,msg:'hit ` + ruleID + `'" } }
  ]
}`
}

// securityEventsSeedAttrPolicy 种子数据 + 一次摄取，返回落库 (policy_id, policy_name)。
// customJSON/crsJSON 存储口径与生产一致：custom_rules JSON 持有 security_custom_rules
// 的 DB 主键 id（emit id = DB id + 10000，见 emitCustomRules）。enabled=0 可模拟
// 禁用策略（归因只加载启用策略）。
func securityEventsSeedAttrPolicy(t *testing.T, ruleTriggered string, policies []struct {
	id         int
	name       string
	enabled    int
	mode       string
	customJSON string
	crsJSON    string
}) (int, string) {
	t.Helper()
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','r','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	// 自定义规则 DB id 3（生产口径：coraza emit id = DB id + 10000）。
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id,name,conditions,action,score,enabled) VALUES (3,'cr','[]','block',5,1) ON CONFLICT DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	for _, p := range policies {
		if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES (?,?,?,?,?,?)`,
			p.id, p.name, p.enabled, p.mode, p.customJSON, p.crsJSON); err != nil {
			t.Fatal(err)
		}
		if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',?)`, p.id); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureForRule(ruleTriggered)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var pid int
	var pname string
	if err := db.MetricsDB.QueryRow(`SELECT policy_id, policy_name FROM security_events`).Scan(&pid, &pname); err != nil {
		t.Fatal(err)
	}
	return pid, pname
}

// SC-EVT-01 重叠自定义规则 → 归因到最低 policy_id。
// Given：自定义规则 DB id 3（coraza emit id = DB id + 10000 = 10003，见
// emitCustomRules），两个启用策略的 custom_rules JSON 均含 DB id 3。
// When：摄取 audit rule_triggered="10003"（emit 空间）。
// Then：重叠 → 归因到最低 policy_id。
func TestSecurityEventsAttribution_OverlappingCustomRulePicksLowestPolicyID(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "10003", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 1, name: "policy-A", enabled: 1, mode: "", customJSON: `[3]`, crsJSON: `[]`},
		{id: 3, name: "policy-B", enabled: 1, mode: "", customJSON: `[3]`, crsJSON: `[]`},
	})
	if pid != 1 || pname != "policy-A" {
		t.Fatalf("attribution=(%d,%q), want (1,policy-A) — 重叠自定义规则必须归因到最低 policy_id", pid, pname)
	}
}

// SC-EVT-01 单属自定义规则 → 归因到拥有该规则的策略（而非首绑定回退值）。
// Given：自定义规则 DB id 3 仅被 policy-B（customJSON [3]，emit id 10003）包含；
// policy-A 是绑定顺序第一条但不含该规则。
// When：摄取 audit rule_triggered="10003"。
// Then：归因到 policy-B —— 若 contains 判定用 DB id 与 emit id 直接比较（ID 空间
// 错位），contains 对两个策略均失败，会错误回退到首绑定 policy-A。
func TestSecurityEventsAttribution_SingleOwnerCustomRulePicksOwnerPolicy(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "10003", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 1, name: "policy-A", enabled: 1, mode: "", customJSON: `[]`, crsJSON: `[]`},
		{id: 3, name: "policy-B", enabled: 1, mode: "", customJSON: `[3]`, crsJSON: `[]`},
	})
	if pid != 3 || pname != "policy-B" {
		t.Fatalf("attribution=(%d,%q), want (3,policy-B) — 单属自定义规则必须归因到拥有该规则的策略（DB id 3 emit 10003）", pid, pname)
	}
}

// SC-EVT-01 归因回退：首绑定为禁用策略 → 跳过到第一个启用绑定。
// Given：policy-off（id 1）禁用且绑定顺序第一，policy-B（id 3）启用；
// rule_triggered="2"（IP ACL 拒绝 id，不属于自定义/CRS 任一 ID 带）不被任何策略
// 显式包含 → 触发回退路径。
// When：摄取 audit rule_triggered="2"。
// Then：回退到第一个 ENABLED 绑定 policy-B；禁止返回 (1,"")（禁用首绑定 + 空名）。
func TestSecurityEventsAttribution_FallbackSkipsDisabledFirstBinding(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "2", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 1, name: "policy-off", enabled: 0, mode: "", customJSON: `[]`, crsJSON: `[]`},
		{id: 3, name: "policy-B", enabled: 1, mode: "", customJSON: `[]`, crsJSON: `[]`},
	})
	if pid != 3 || pname != "policy-B" {
		t.Fatalf("attribution=(%d,%q), want (3,policy-B) — 回退必须跳过禁用首绑定，取第一个启用绑定", pid, pname)
	}
}

// SC-EVT-01 重叠 CRS 组 → 归因到最低 policy_id。
func TestSecurityEventsAttribution_OverlappingCRSGroupPicksLowestPolicyID(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "942001", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 2, name: "policy-A", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `["42"]`},
		{id: 5, name: "policy-B", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `["42"]`},
	})
	if pid != 2 || pname != "policy-A" {
		t.Fatalf("attribution=(%d,%q), want (2,policy-A) — 重叠 CRS 组必须归因到最低 policy_id", pid, pname)
	}
}

// W-I1 回归：属主非首绑定 + 组号——六位分支未命中后必须回落组号归因，
// 而非回退首启用策略（第五轮 V1-S1 遮蔽组号分支的回归面）。
func TestSecurityEventsAttribution_GroupOwnerNotFirstBound(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "942001", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 2, name: "policy-xss", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `["41"]`},
		{id: 5, name: "policy-sqli", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `["42"]`},
	})
	if pid != 5 || pname != "policy-sqli" {
		t.Fatalf("attribution=(%d,%q), want (5,policy-sqli) — 942001 属组 42，必须归因到组号 42 的策略而非首绑定的 41 策略", pid, pname)
	}
}

// SC-1（2026-09-05 安全核心域审计裁定修复）：mode=off 策略不得认领 CRS 事件。
// Given：lb_rule1 绑定两条启用策略——低 id 策略 mode='off'（crs_rule_groups 空
// =发射端「包含全部 CRS」语义），高 id 策略 mode='blocking'（空组合同样全量）。
// When：摄取 audit rule_triggered="942100"（CRS 事件，只能由 blocking 策略发出）。
// Then：归因到 blocking 策略——A1-S6 off 门（securityEventsPolicyContainsRule
// 的 policy.Mode == "off"）必须真正生效；归因落到 off 策略（含经回退路径）即失败。
func TestSecurityEventsAttribution_ModeOffPolicyDoesNotClaimCRSEvents(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "942100", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 2, name: "policy-off", enabled: 1, mode: "off", customJSON: `[]`, crsJSON: `[]`},
		{id: 5, name: "policy-blocking", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `[]`},
	})
	if pid != 5 || pname != "policy-blocking" {
		t.Fatalf("attribution=(%d,%q), want (5,policy-blocking) — mode=off 策略不得认领 CRS 事件（A1-S6 off 门）", pid, pname)
	}
}

// 2026-09-09 四态化:custom_only 策略零 CRS Include,不得认领 CRS 事件
// （归因门收紧为 CRS 生效模式——与 A1-S6 off 门同口径的延伸）。
func TestSecurityEventsAttribution_CustomOnlyPolicyDoesNotClaimCRSEvents(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "942100", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 2, name: "policy-custom-only", enabled: 1, mode: "custom_only", customJSON: `[]`, crsJSON: `[]`},
		{id: 5, name: "policy-blocking", enabled: 1, mode: "blocking", customJSON: `[]`, crsJSON: `[]`},
	})
	if pid != 5 || pname != "policy-blocking" {
		t.Fatalf("attribution=(%d,%q), want (5,policy-blocking) — custom_only 策略不得认领 CRS 事件", pid, pname)
	}
}

// SC-EVT-01 未绑定（无 security_policy_bindings 行）→ 归因零值。
func TestSecurityEventsAttribution_UnboundReturnsZeroValue(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','r','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	// 故意不插入 security_policy_bindings / security_policies —— 完全未绑定场景。
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureForRule("999999")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var pid int
	var pname string
	if err := db.MetricsDB.QueryRow(`SELECT policy_id, policy_name FROM security_events`).Scan(&pid, &pname); err != nil {
		t.Fatal(err)
	}
	if pid != 0 || pname != "" {
		t.Fatalf("attribution=(%d,%q), want (0,\"\") — 未绑定策略的规则必须归因零值", pid, pname)
	}
}

// A3 I-6 遗留 ip_blacklist 拒绝（rule_triggered="4"）必须归因到拥有黑名单的策略。
// Given：lb_rule1 绑定 [policy-A(id1, 无任何 IP 控制), policy-B(id3, ip_blacklist
// '["10.0.0.1"]')]，绑定顺序 policy_id ASC。
// When：归因 audit rule_triggered="4"（BuildCorazaDirectives 对非空 ip_blacklist
// 发射 id:4 的遗留黑名单拒绝）。
// Then：归因到 policy-B(id3) —— 而非首绑定回退值 policy-A。
func TestSecurityEventsAttribution_LegacyBlacklistDenyPicksOwnerPolicy(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups) VALUES (1,'policy-A',1,'[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups,ip_blacklist) VALUES (3,'policy-B',1,'[]','[]','["10.0.0.1"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',1),('lb_rule1',3)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_rule1", "4", "blocked", "", policyByID, bindings)
	if pid != 3 || pname != "policy-B" {
		t.Fatalf("attribution=(%d,%q), want (3,policy-B) — 遗留黑名单拒绝必须归因到拥有 ip_blacklist 的策略", pid, pname)
	}
}

// A3 I-6 IP ACL 黑名单模式拒绝（rule_triggered="2"）必须归因到拥有该 ACL 的策略。
// Given：lb_rule1 绑定 [policy-A(id1, 无任何 IP 控制), policy-C(id4,
// ip_acl_enabled=1, ip_acl_mode='deny', ip_acl_list '["1.2.3.4"]')]。
// When：归因 audit rule_triggered="2"（enabled+deny+名单非空时发射 id:2）。
// Then：归因到 policy-C(id4) —— 而非首绑定回退值 policy-A。
func TestSecurityEventsAttribution_IPACLDenyPicksOwnerPolicy(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups) VALUES (1,'policy-A',1,'[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups,ip_acl_enabled,ip_acl_mode,ip_acl_list) VALUES (4,'policy-C',1,'[]','[]',1,'deny','["1.2.3.4"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',1),('lb_rule1',4)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_rule1", "2", "blocked", "", policyByID, bindings)
	if pid != 4 || pname != "policy-C" {
		t.Fatalf("attribution=(%d,%q), want (4,policy-C) — IP ACL 黑名单模式拒绝必须归因到拥有该 ACL 的策略", pid, pname)
	}
}

// A3 I-6 回退守恒：rule_triggered="4" 但没有任何绑定策略配置黑名单时，
// 仍回退到第一个 ENABLED 绑定策略（发射现实：必有策略发出了该 id，只是当前
// 配置已变更），禁止回归为零值或报错。
func TestSecurityEventsAttribution_BlacklistDenyFallsBackToFirstEnabledWhenNoOwner(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups) VALUES (1,'policy-A',1,'[]','[]'),(3,'policy-B',1,'[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',1),('lb_rule1',3)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_rule1", "4", "blocked", "", policyByID, bindings)
	if pid != 1 || pname != "policy-A" {
		t.Fatalf("attribution=(%d,%q), want (1,policy-A) — 无属主时必须回退到第一个启用绑定策略", pid, pname)
	}
}

// A3 I-6 边界：allow（白名单）模式的 IP ACL 不拥有 rule_triggered="2" 的归属
// （归属口径仅认 deny 黑名单模式，与审计规格一致）；事件回退到第一个启用绑定。
func TestSecurityEventsAttribution_IPACLAllowModeDoesNotOwnDenyEvent(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups) VALUES (1,'policy-A',1,'[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,custom_rules,crs_rule_groups,ip_acl_enabled,ip_acl_mode,ip_acl_list) VALUES (4,'policy-C',1,'[]','[]',1,'allow','["1.2.3.4"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',1),('lb_rule1',4)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_rule1", "2", "blocked", "", policyByID, bindings)
	if pid != 1 || pname != "policy-A" {
		t.Fatalf("attribution=(%d,%q), want (1,policy-A) — allow 模式 ACL 不拥有 id:2 归属，必须回退首绑定", pid, pname)
	}
}

// S-2：启动时审计目录缺失必须创建（此前只靠 tick 反复报错刷屏、从不建目录）。
func TestEnsureAuditLogDir_createsMissingDirectory(t *testing.T) {
	// Given：auditLogPath 指向尚不存在的子目录
	dir := t.TempDir()
	oldLogPath := auditLogPath
	auditLogPath = filepath.Join(dir, "audit", "audit.log")
	t.Cleanup(func() { auditLogPath = oldLogPath })

	// When
	if err := ensureAuditLogDir(); err != nil {
		t.Fatalf("ensure audit dir: %v", err)
	}

	// Then：目录已创建；重复调用幂等
	if info, err := os.Stat(filepath.Join(dir, "audit")); err != nil || !info.IsDir() {
		t.Fatalf("audit dir must exist after ensure, stat err=%v", err)
	}
	if err := ensureAuditLogDir(); err != nil {
		t.Fatalf("ensure on existing dir must be a no-op success: %v", err)
	}
}

// S-1：轮转/摄取的重复同类失败日志必须限流（2s tick 下同一失败每 tick 刷屏）。
// 直测限流判定（时钟可注入）：同消息 60s 内仅首条放行，异消息不受影响，
// 60s 后同消息恢复放行。
func TestAuditFailureShouldLog_throttlesIdenticalMessages(t *testing.T) {
	// Given：重置限流状态并注入固定时钟
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	now := time.Now()
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return now }
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})

	// When：同消息连续判定，随后异消息，再 61s 后同消息
	if !auditFailureShouldLog("copy to .1 failed") {
		t.Fatal("first emission of a message must be allowed")
	}
	if auditFailureShouldLog("copy to .1 failed") {
		t.Fatal("identical message within 60s must be suppressed")
	}
	if !auditFailureShouldLog("truncate failed") {
		t.Fatal("a different message must not be suppressed by another message's window")
	}
	now = now.Add(61 * time.Second)
	if !auditFailureShouldLog("copy to .1 failed") {
		t.Fatal("identical message after 60s must be emitted again")
	}
}

// N-1：限流 map 不得随变体消息无界增长——放行路径清扫已过期（≥60s）条目。
func TestAuditFailureShouldLog_evictsStaleEntriesOnAllowedLog(t *testing.T) {
	// Given：重置限流状态并注入固定时钟
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	now := time.Now()
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return now }
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})

	// When：T0 放行消息 A；T0+61s 放行消息 B
	if !auditFailureShouldLog("rotation copy failed") {
		t.Fatal("first emission must be allowed")
	}
	now = now.Add(61 * time.Second)
	if !auditFailureShouldLog("rotation truncate failed") {
		t.Fatal("a different message after the window must be allowed")
	}

	// Then：消息 A 的条目已过期被清扫，map 仅剩 B
	auditFailureLogMu.Lock()
	size := len(auditFailureLogTimes)
	_, hasA := auditFailureLogTimes["rotation copy failed"]
	auditFailureLogMu.Unlock()
	if size != 1 {
		t.Fatalf("map size after sweep = %d, want 1 (stale entry evicted)", size)
	}
	if hasA {
		t.Fatal("stale entry (age ≥60s) must be evicted on an allowed log")
	}
}

// N-1：键数超上限时整体重置——map 回到仅含当前条目，限流语义不中断。
func TestAuditFailureShouldLog_resetsWhenOverCap(t *testing.T) {
	// Given：重置限流状态并注入固定时钟
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	now := time.Now()
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return now }
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})

	// When：同一时刻放行 66 条互异消息（用字母区分——数字区分会被 N-2 归一
	// 化折叠为同键，无法构造多键）
	for i := 0; i < auditFailureLogEvictCap+2; i++ {
		if !auditFailureShouldLog(fmt.Sprintf("rotation case %c failed", 'a'+i)) {
			t.Fatalf("new message %d must be allowed", i)
		}
	}
	last := fmt.Sprintf("rotation case %c failed", 'a'+auditFailureLogEvictCap+1)

	// Then：超限已整体重置，map 仅剩最后一条且其限流窗口仍生效
	auditFailureLogMu.Lock()
	size := len(auditFailureLogTimes)
	_, hasLast := auditFailureLogTimes[auditFailureThrottleKey(last)]
	auditFailureLogMu.Unlock()
	if size != 1 {
		t.Fatalf("map size after cap reset = %d, want 1", size)
	}
	if !hasLast {
		t.Fatal("cap reset must retain the current entry")
	}
	if auditFailureShouldLog(last) {
		t.Fatal("last message must remain throttled after reset")
	}
}

// N-2：内嵌数字的变体消息共享限流键——同故障不同偏移 60s 内仅首条放行，
// 窗口后恢复；非数字差异的消息不受影响。
func TestAuditFailureShouldLog_normalizesNumericVariants(t *testing.T) {
	// Given：重置限流状态并注入固定时钟
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	now := time.Now()
	oldClock := auditFailureLogClock
	auditFailureLogClock = func() time.Time { return now }
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})

	// When：窗口内两条仅偏移不同的同类失败
	m1 := "audit log rotation: ingest live tail [100, 200) failed (not truncating): boom"
	m2 := "audit log rotation: ingest live tail [300, 400) failed (not truncating): boom"
	if !auditFailureShouldLog(m1) {
		t.Fatal("first variant must be allowed")
	}
	if auditFailureShouldLog(m2) {
		t.Fatal("same failure with different offsets within 60s must be suppressed")
	}
	if !auditFailureShouldLog("audit log rotation: shift audit.log.a to audit.log.b failed: boom") {
		t.Fatal("a genuinely different message must not be suppressed")
	}

	// When/Then：61s 后同类失败（又一新偏移）恢复放行
	now = now.Add(61 * time.Second)
	m3 := "audit log rotation: ingest live tail [500, 600) failed (not truncating): boom"
	if !auditFailureShouldLog(m3) {
		t.Fatal("variant after 60s must be allowed again")
	}
}

// N-2：限流键归一化——数字串统一替换为 #。
func TestAuditFailureThrottleKey_replacesDigitRuns(t *testing.T) {
	got := auditFailureThrottleKey("ingest live tail [12345, 67890) failed: read timeout 5s")
	want := "ingest live tail [#, #) failed: read timeout #s"
	if got != want {
		t.Fatalf("throttle key = %q, want %q", got, want)
	}
}

// N+9 C3-S3：pending 归档缺失分支的 warn 必须走 60s 限流——标记删除失败
// （只读目录等）时标记留在盘上，2s tick 反复进入该分支，裸 warn 每 tick
// 一条（~43k 行/天）。只读目录模拟在 root 下退化为「删除成功」，但断言的
// 窗口内至多一条上限两种情况都成立。
func TestRotateAuditLogIfNeeded_pendingArchiveMissing_unremovableMarkerWarnsAtMostOncePerWindow(t *testing.T) {
	// Given：重置限流状态；临时目录活文件 + 指向缺失归档的 pending 标记
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	oldClock := auditFailureLogClock
	auditFailureLogClock = time.Now
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write live audit log: %v", err)
	}
	oldAuditLogPath := auditLogPath
	auditLogPath = logPath
	t.Cleanup(func() { auditLogPath = oldAuditLogPath })
	oldSizeFn := auditLogSizeBytes
	auditLogSizeBytes = func() int64 { return 1 << 40 }
	t.Cleanup(func() { auditLogSizeBytes = oldSizeFn })
	markerPath := securityEventsPendingDeltaPath()
	marker := fmt.Sprintf(`{"path":%q,"offset":0,"size":1}`, filepath.Join(dir, "audit.log.1"))
	if err := os.WriteFile(markerPath, []byte(marker), 0o644); err != nil {
		t.Fatalf("write pending marker: %v", err)
	}

	// 只读目录：os.Remove(标记) 失败 → 标记留存、分支每 tick 重入
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("chmod dir read-only: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	// When：连续 3 个 tick
	rotateAuditLogIfNeeded()
	rotateAuditLogIfNeeded()
	rotateAuditLogIfNeeded()

	// Then：warn 仅放行首条（60s 窗口）
	if count := strings.Count(logs.String(), "pending delta archive"); count != 1 {
		t.Fatalf("pending-missing warn count=%d, want 1 (60s throttle window): %s", count, logs.String())
	}
}

// N+9 C3-S3（正向）：标记可删除时 warn 仍保持一次性——删除成功后标记消失，
// 后续 tick 不再进入该分支。
func TestRotateAuditLogIfNeeded_pendingArchiveMissing_removableMarkerWarnsOnceAndDrops(t *testing.T) {
	// Given：重置限流状态；可写目录 + 指向缺失归档的 pending 标记
	auditFailureLogMu.Lock()
	auditFailureLogTimes = map[string]time.Time{}
	auditFailureLogMu.Unlock()
	oldClock := auditFailureLogClock
	auditFailureLogClock = time.Now
	t.Cleanup(func() {
		auditFailureLogClock = oldClock
		auditFailureLogMu.Lock()
		auditFailureLogTimes = map[string]time.Time{}
		auditFailureLogMu.Unlock()
	})
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(logPath, []byte("x"), 0o644); err != nil {
		t.Fatalf("write live audit log: %v", err)
	}
	oldAuditLogPath := auditLogPath
	auditLogPath = logPath
	t.Cleanup(func() { auditLogPath = oldAuditLogPath })
	oldSizeFn := auditLogSizeBytes
	auditLogSizeBytes = func() int64 { return 1 << 40 }
	t.Cleanup(func() { auditLogSizeBytes = oldSizeFn })
	markerPath := securityEventsPendingDeltaPath()
	marker := fmt.Sprintf(`{"path":%q,"offset":0,"size":1}`, filepath.Join(dir, "audit.log.1"))
	if err := os.WriteFile(markerPath, []byte(marker), 0o644); err != nil {
		t.Fatalf("write pending marker: %v", err)
	}

	var logs bytes.Buffer
	originalWriter := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(originalWriter) })

	// When：首个 tick（归档缺失、标记删除成功）
	rotateAuditLogIfNeeded()

	// Then：warn 恰一条且标记已删除
	if count := strings.Count(logs.String(), "pending delta archive"); count != 1 {
		t.Fatalf("pending-missing warn count=%d, want 1: %s", count, logs.String())
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("marker should be removed after successful drop: %v", err)
	}

	// When：第二个 tick（无标记，分支不重入）
	rotateAuditLogIfNeeded()

	// Then：仍仅一条 warn
	if count := strings.Count(logs.String(), "pending delta archive"); count != 1 {
		t.Fatalf("pending-missing warn count after 2nd tick=%d, want 1 (no marker, branch not re-entered): %s", count, logs.String())
	}
}

// 审计 I-3：GeoIP（id:8）归因走真实 loader 路径——securityEventsLoadMappings
// 此前不加载 geoip_countries，case 8 所有权判定对空 GeoIPCountries 必败，
// 多策略绑定时错归首启用策略（单测曾用合成 map 绕过 loader 掩盖该缺陷）。
// Given：policy-A（id 1，无 geoip）绑定顺序第一，policy-B（id 3，geoip ["CN"]）。
// When：摄取 audit rule_triggered="8"（GeoIP 区域拦截）。
// Then：归因到 policy-B（携带 geoip 条目者），而非首绑定 policy-A。
func TestSecurityEventsAttribution_GeoIPOwnerPicksGeoIPCarryingPolicy(t *testing.T) {
	t.Helper()
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,protocol,domain,listen_port,enabled) VALUES ('lb_rule1','r','http','go029.com',443,1)`); err != nil {
		t.Fatal(err)
	}
	// 审计 B1-IA：A 为 off+保留名单（不发射 id:8）且绑定序第一——若归因门控
	// 不判 mode，A 会抢走 B（真实发射者）的 id:8 事件归因。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,geoip_countries,geoip_mode) VALUES (1,'policy-A',1,'["CN"]','off')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,geoip_countries,geoip_mode) VALUES (3,'policy-B',1,'["CN"]','deny')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_rule1',1),('lb_rule1',3)`); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := os.WriteFile(logPath, []byte(securityEventsFixtureForRule("8")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := securityEventsNewTailer(logPath, offsetPath).securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}
	var pid int
	var pname string
	if err := db.MetricsDB.QueryRow(`SELECT policy_id, policy_name FROM security_events`).Scan(&pid, &pname); err != nil {
		t.Fatal(err)
	}
	if pid != 3 || pname != "policy-B" {
		t.Fatalf("attribution=(%d,%q), want (3,policy-B) — GeoIP 事件必须归因到携带 geoip 条目的策略", pid, pname)
	}
}

func TestSecurityEventsSerializeHeaders_underCapKeepsExactJSON(t *testing.T) {
	headers := map[string][]string{
		"Host":       {"quanyi-order.go029.com"},
		"User-Agent": {"curl/8.0"},
	}
	got := securityEventsSerializeHeaders(headers)
	var roundTrip map[string][]string
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("serialized headers must stay valid JSON: %v", err)
	}
	if len(roundTrip) != 2 || roundTrip["Host"][0] != "quanyi-order.go029.com" {
		t.Errorf("roundTrip=%v, want exact headers preserved", roundTrip)
	}
	if securityEventsSerializeHeaders(nil) != "" {
		t.Error("nil headers must serialize to empty string")
	}
}

func TestSecurityEventsSerializeHeaders_dropsLargestUntilFits(t *testing.T) {
	headers := map[string][]string{
		"Host":       {"a.example.com"},
		"User-Agent": {"probe"},
		"X-Big":      {strings.Repeat("B", securityEventsHeadersCap)},
	}
	got := securityEventsSerializeHeaders(headers)
	if len(got) > securityEventsHeadersCap {
		t.Fatalf("len=%d exceeds cap %d", len(got), securityEventsHeadersCap)
	}
	var roundTrip map[string][]string
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("truncated headers must stay valid JSON: %v", err)
	}
	if _, ok := roundTrip["X-Big"]; ok {
		t.Error("largest header must be dropped first")
	}
	if roundTrip["Host"][0] != "a.example.com" || roundTrip["User-Agent"][0] != "probe" {
		t.Errorf("small headers must be kept: %v", roundTrip)
	}
	if len(roundTrip["_dropped"]) != 1 || roundTrip["_dropped"][0] != "1" {
		t.Errorf("_dropped marker=%v, want [\"1\"]", roundTrip["_dropped"])
	}
}

func TestSecurityEventsEncodeBody_plainText(t *testing.T) {
	if got := securityEventsEncodeBody("user=admin&pass=123"); got != "user=admin&pass=123" {
		t.Errorf("plain body changed: %q", got)
	}
	if got := securityEventsEncodeBody(""); got != "" {
		t.Errorf("empty body must stay empty, got %q", got)
	}
}

func TestSecurityEventsEncodeBody_truncatesAtRuneBoundary(t *testing.T) {
	// 65535 个 ASCII + 一个双字节字符 'é'（0xC3 0xA9，落在 65535-65536）+ 尾部：
	// 朴素字节截断会把 'é' 劈成半个符文，必须回退到符文边界 65535。
	body := strings.Repeat("a", 65535) + "é" + strings.Repeat("b", 100)
	got := securityEventsEncodeBody(body)
	if !strings.HasSuffix(got, "\n...[TRUNCATED]") {
		t.Fatal("truncated body must carry the marker suffix")
	}
	content := strings.TrimSuffix(got, "\n...[TRUNCATED]")
	if !utf8.ValidString(content) {
		t.Error("truncated content must remain valid UTF-8 (no split rune)")
	}
	if len(content) != 65535 {
		t.Errorf("content len=%d, want 65535 (rune boundary before the straddling é)", len(content))
	}
}

func TestSecurityEventsEncodeBody_binary(t *testing.T) {
	binary := string([]byte{0xff, 0xfe, 0x00, 0x01, 0x02})
	got := securityEventsEncodeBody(binary)
	if !strings.HasPrefix(got, "base64:") {
		t.Fatalf("binary body must carry base64: prefix, got %q", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "base64:"))
	if err != nil || string(decoded) != binary {
		t.Errorf("base64 round trip failed: decoded=%q err=%v", decoded, err)
	}
}

func TestSecurityEventsEncodeBody_binaryTruncated(t *testing.T) {
	binary := string(bytes.Repeat([]byte{0xff}, securityEventsBodyCap+100))
	got := securityEventsEncodeBody(binary)
	if !strings.HasPrefix(got, "base64-truncated:") {
		t.Fatalf("oversized binary must carry base64-truncated: prefix, got prefix of %q", got[:30])
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "base64-truncated:"))
	if err != nil {
		t.Fatalf("truncated payload must stay decodable: %v", err)
	}
	if len(decoded) != securityEventsBodyCap {
		t.Errorf("decoded len=%d, want exactly the 64KB raw cap", len(decoded))
	}
}

func TestSecurityEventsParseTransaction_requestContext(t *testing.T) {
	raw := `{"transaction":{"unix_timestamp":1754910200000000000,"id":"tx-ctx-1","client_ip":"1.2.3.4","server_id":"go029.com","request":{"method":"POST","uri":"/login","headers":{"Host":["go029.com"],"X-LB-Rule-ID":["lb_abc123"],"Cookie":["session=secret"]},"body":"user=admin&pass=123"},"is_interrupted":true},"messages":[]}`
	rec, err := securityEventsParseTransaction(json.RawMessage(raw))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if rec.AttributionRuleID != "lb_abc123" {
		t.Errorf("AttributionRuleID=%q, want lb_abc123 from X-LB-Rule-ID header", rec.AttributionRuleID)
	}
	if rec.RequestBody != "user=admin&pass=123" {
		t.Errorf("RequestBody=%q, want verbatim plain body", rec.RequestBody)
	}
	var headers map[string][]string
	if err := json.Unmarshal([]byte(rec.RequestHeaders), &headers); err != nil {
		t.Fatalf("RequestHeaders must be valid JSON: %v", err)
	}
	if headers["Cookie"][0] != "session=secret" {
		t.Errorf("RequestHeaders lost Cookie: %v", headers)
	}

	rawNoCtx := `{"transaction":{"unix_timestamp":1754910200000000000,"id":"tx-ctx-2","client_ip":"1.2.3.4","server_id":"go029.com","request":{"method":"GET","uri":"/","headers":{"Host":["go029.com"]}},"is_interrupted":false},"messages":[]}`
	rec2, err := securityEventsParseTransaction(json.RawMessage(rawNoCtx))
	if err != nil {
		t.Fatalf("parse no-ctx: %v", err)
	}
	if rec2.AttributionRuleID != "" || rec2.RequestBody != "" {
		t.Errorf("missing context must stay empty: attribution=%q body=%q", rec2.AttributionRuleID, rec2.RequestBody)
	}
}

// S2(2026-09-10 审计):自定义规则事件归因分支缺模式门——off=全关(四态化)后
// 零发射,不得认领自定义规则事件(与 CRS 分支 blocking/detection 门同口径)。
func TestSecurityEventsAttribution_ModeOffPolicyDoesNotClaimCustomRuleEvents(t *testing.T) {
	pid, pname := securityEventsSeedAttrPolicy(t, "10001", []struct {
		id         int
		name       string
		enabled    int
		mode       string
		customJSON string
		crsJSON    string
	}{
		{id: 2, name: "policy-off", enabled: 1, mode: "off", customJSON: `[{"id":1,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`, crsJSON: `[]`},
		{id: 5, name: "policy-blocking", enabled: 1, mode: "blocking", customJSON: `[{"id":1,"name":"r","enabled":true,"action":"block","score":5,"conditions":[{"target":"uri","operator":"contains","pattern":"/x"}]}]`, crsJSON: `[]`},
	})
	if pid != 5 || pname != "policy-blocking" {
		t.Fatalf("attribution=(%d,%q), want (5,policy-blocking) — mode=off 策略不得认领自定义规则事件", pid, pname)
	}
}

// SYSRENDER24-1(第 24 轮审计):迁移/首启动形态——文件缺失分支创建空文件时
// 残留 offset>0 必须归零。否则新文件快速增长超过旧 offset 后,前缀事件被
// 永久跳过(inode 分支 lastInfo=nil 首启动永不生效)。
func TestSecurityEventsTick_missingFileResetsStaleOffset(t *testing.T) {
	// Given: 无 audit 文件 + 残留 offset(升级前旧路径的尾部位置)
	_, _ = newClusterTestService(t)
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.log")
	offsetPath := filepath.Join(dir, "security_events.offset")
	if err := securityEventsWriteOffset(offsetPath, 52428800); err != nil { // 50MB
		t.Fatal(err)
	}
	tailer := securityEventsNewTailer(logPath, offsetPath)

	// When: 首个 tick(文件缺失→创建空文件)
	if err := tailer.securityEventsTick(); err != nil {
		t.Fatalf("tick: %v", err)
	}

	// Then: offset 已归零
	offset, err := securityEventsReadOffset(offsetPath)
	if err != nil {
		t.Fatal(err)
	}
	if offset != 0 {
		t.Fatalf("offset=%d after missing-file creation, want 0 (stale offset must reset)", offset)
	}
}

// 同域名双规则归因(2026-09-15 用户实证):rules[host] 覆盖致 https 规则 ref
// 蒸发,rulesByID 缺 https id → header=https-id 回退 MapHost 命中 http 规则。
// host:port 双写后两 ref 共存,归因精确。
func TestSecurityEventsAttribution_sameDomainTwoRules(t *testing.T) {
	_, database := newClusterTestService(t)
	// https 规则先创建(443),http 规则后创建(80)——用户生产形态
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES
		('lb_https','https-rule','example.com','http',443,1),
		('lb_http','http-rule','example.com','http',80,1)`); err != nil {
		t.Fatal(err)
	}
	rules, _, _, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatal(err)
	}
	// rulesByID 必须同时含两个 id(https ref 未被蒸发)
	rulesByID := make(map[string]securityEventsRuleRef, len(rules))
	for _, ref := range rules {
		rulesByID[ref.caddyID] = ref
	}
	if rulesByID["lb_https"].caddyID == "" {
		t.Fatal("https rule ref evicted from rulesByID (root cause of misattribution)")
	}
	if rulesByID["lb_http"].caddyID == "" {
		t.Fatal("http rule ref missing from rulesByID")
	}
	// header=https-id 归因命中 https 规则
	if got := rulesByID["lb_https"]; got.name != "https-rule" {
		t.Fatalf("attribution for https-id=%q, want https-rule", got.name)
	}
	// header=http-id 归因命中 http 规则
	if got := rulesByID["lb_http"]; got.name != "http-rule" {
		t.Fatalf("attribution for http-id=%q, want http-rule", got.name)
	}
	// 兜底:example.com:443 → https;example.com:80 → http
	if got := securityEventsMapHost("example.com:443", rules); got.caddyID != "lb_https" {
		t.Fatalf("MapHost(:443)=%q, want lb_https", got.caddyID)
	}
	if got := securityEventsMapHost("example.com:80", rules); got.caddyID != "lb_http" {
		t.Fatalf("MapHost(:80)=%q, want lb_http", got.caddyID)
	}
}

// 单规则形态(2026-09-15 用户问):仅一条规则时,双写键+端口优先无回归。
func TestSecurityEventsAttribution_singleRuleForms(t *testing.T) {
	_, database := newClusterTestService(t)
	if _, err := database.Exec(`INSERT INTO lb_rules (caddy_id,name,domain,protocol,listen_port,enabled) VALUES ('lb_single','single','single.example.com','http',443,1)`); err != nil {
		t.Fatal(err)
	}
	rules, _, _, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatal(err)
	}
	// host 带端口:精确键命中
	if got := securityEventsMapHost("single.example.com:443", rules); got.caddyID != "lb_single" {
		t.Fatalf("MapHost(:443)=%q, want lb_single", got.caddyID)
	}
	// host 不带端口(HTTP/2 常见):纯域名键命中(双写兼容)
	if got := securityEventsMapHost("single.example.com", rules); got.caddyID != "lb_single" {
		t.Fatalf("MapHost(no port)=%q, want lb_single", got.caddyID)
	}
}

// A34-CORE-F1/F2(第 34 轮审计,P2)+ A35-SECLB-1/2/3(第 35 轮审计,P2 误拒修正):
// fallback 归因模式/动作可行性门。门禁语义按「模式 × 动作 × 规则 id 族」交叉积,
// 逐格对照发射侧(security.go:179-184 IP 控制/GeoIP 与模式无关独立发射、
// :220-222 off 引擎 On、:347→:351 自定义先于 id:6 DetectionOnly 切换、:668
// phase:1 拦截保障明文、:459/:495 contains 模式门):
//
//	off:         仅 {2,4,7,8} 可产(IP 控制/GeoIP 独立发射)
//	detection:   logged 全可产;blocked 仅 {2,4,7,8}+自定义(phase:1 先于 id:6)
//	custom_only: CRS(9xxxxx)全拒(零 Include);blocked 另拒 id:11(无 949 评分链)
//	blocking:    全域
//
// 误拒三族(A35):off+{2,4} blocked / detection+{2,4} blocked / custom_only+7 blocked。
// 全用例排空 contains() 命中(组号错配/空名单),确保走的是 fallback 门。
func TestSecurityEventsAttribution_FallbackModeFeasibilityGate(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	// Given:四模式策略——custom_only/blocking(组 94 排空 contains)/detection(组 94)/off
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES
		(1,'p-customonly',1,'custom_only','[]','[]'),
		(2,'p-blocking',1,'blocking','[]','["94"]'),
		(3,'p-detection',1,'detection','[]','["94"]'),
		(4,'p-off',1,'off','[]','[]')`); err != nil {
		t.Fatal(err)
	}
	// 绑定加载按 policy_id ASC(securityEventsLoadMappings ORDER BY)——
	// 「首候选」= 最小 id;off 策略要作首候选须单独成绑。
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_r1',1),('lb_r1',2),
		('lb_r2',1),
		('lb_r3',3),
		('lb_r4',4)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	cases := []struct {
		name      string
		rule      string
		triggered string
		action    string
		wantPID   int
	}{
		// ── F1/F2 原始标靶(正确拒绝,保持) ──
		// F1:custom_only 首绑不得认领 blocked id:11(无 949 评分链,id:11 恒 pass)
		{"F1 custom_only id:11 blocked rejected", "lb_r1", "11", "blocked", 2},
		// F2:custom_only 不得认领 CRS(零 Include)
		{"F2 custom_only CRS blocked rejected", "lb_r2", "913100", "blocked", 0},
		// detection 不得认领 CRS blocked(id:6 切换先于 CRS 评估,DetectionOnly 零中断)
		{"detection CRS blocked rejected", "lb_r3", "913100", "blocked", 0},
		// ── A35 误拒三族(修正目标,当前被门错误拒绝) ──
		// off+IP 控制 blocked 可产(IP 控制与模式无关独立发射,security.go:179-181)
		{"off id:2 blocked allowed", "lb_r4", "2", "blocked", 4},
		{"off id:4 blocked allowed", "lb_r4", "4", "blocked", 4},
		// detection+IP 控制 blocked 可产(phase:1 先于 id:6 切换,:668 明文保障)
		{"detection id:2 blocked allowed", "lb_r3", "2", "blocked", 3},
		// custom_only+预检 id:7 blocked 可产(allow 交集与模式无关,:927-935)
		{"custom_only id:7 blocked allowed", "lb_r2", "7", "blocked", 1},
		// ── 回归形状 ──
		// custom_only 自定义 block 规则可产(排空 contains 走 fallback)
		{"custom_only custom blocked ok", "lb_r2", "10005", "blocked", 1},
		// blocking fallback 全域(组 94 排空 contains)
		{"blocking blocked fallback ok", "lb_r1", "913100", "blocked", 2},
		// off 不得认领 CRS logged(off 零 CRS 发射)
		{"off CRS logged rejected", "lb_r4", "913100", "logged", 0},
		// detection logged 全域
		{"detection logged ok", "lb_r3", "913100", "logged", 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, _ := securityEventsAttributePolicy(tc.rule, tc.triggered, tc.action, "", policyByID, bindings)
			if pid != tc.wantPID {
				t.Fatalf("attributePolicy(%s,%s,%s)=(%d), want %d", tc.rule, tc.triggered, tc.action, pid, tc.wantPID)
			}
		})
	}
}

// 阶段化模型归因精确化：GeoIP 事件 id 从共享 id:8（归「首个 geoip 启用策略」，
// 非精确）改为预检精确段 800000+policyID——securityEventsPolicyContainsRule
// 直接解码 id 命中属主策略；属主不在绑定集（配置已在发射后变更）时经
// fallback 可行性门归属（off 模式 GeoIP blocked 可产：ipControl 类含 800xxx 段，
// 否则 off 模式 GeoIP 事件被误拒为 (0,"")）。
func TestSecurityEventsAttribution_geoipPrecheckExactSegment(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	// Given：p1/p2 各带 geoip（deny 模式），p3 blocking 无 geoip，p5 off 无 geoip
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups,geoip_countries,geoip_mode) VALUES
		(1,'p-geo-overseas',1,'off','[]','[]','["海外"]','deny'),
		(2,'p-geo-jiangsu',1,'off','[]','[]','["江苏"]','deny'),
		(3,'p-blocking',1,'blocking','[]','[]','[]','off'),
		(5,'p-off-plain',1,'off','[]','[]','[]','off')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_rg',1),('lb_rg',2),('lb_rg',3),
		('lb_r5',5)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	cases := []struct {
		name      string
		rule      string
		triggered string
		action    string
		wantPID   int
	}{
		// 精确段：800000+policyID 直接命中属主（不再「首个 geoip 策略」通吃）
		{"800001 → p1 exact", "lb_rg", "800001", "blocked", 1},
		{"800002 → p2 exact (not first geoip policy)", "lb_rg", "800002", "blocked", 2},
		// 属主不在绑定集：off 模式 GeoIP blocked 经 fallback 可归属（ipControl 含 800xxx）
		{"off-mode 800xxx blocked fallback allowed", "lb_r5", "800099", "blocked", 5},
		// 回归：旧共享 id:8 仍归「首个 geoip 启用策略」（历史事件可继续解释）
		{"legacy id:8 → first geoip policy", "lb_rg", "8", "blocked", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, _ := securityEventsAttributePolicy(tc.rule, tc.triggered, tc.action, "", policyByID, bindings)
			if pid != tc.wantPID {
				t.Fatalf("attributePolicy(%s,%s,%s)=(%d), want %d", tc.rule, tc.triggered, tc.action, pid, tc.wantPID)
			}
		})
	}
}

// 2026-09-21 05:29 生产事故(lb_dq2351774e)复现:摄入时刻绑定快照 [42 观察模式
// detection 无 ACL, 49 ooo off+信任名单含事件源 IP] 中不存在 deny 属主,contains
// 全部落空走 fallback——旧门只核 mode/动作,无任何 IP 发射面的 42 作为首候选
// 直接胜出,id:2 事件错挂「观察模式」。能力首选层修后期望:logged(检测)语义下
// 信任名单策略(真实 IP 控制发射面,SecurityPolicyHasIPControl 同源字段)优先于
// 无能力策略。RED:当前代码返回首候选 42。
func TestSecurityEventsAttribution_IPFamilyFallbackPrefersIPCapablePolicy(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups,ip_whitelist_enabled,ip_whitelist) VALUES
		(1,'p-detection-noacl',1,'detection','[]','[]',0,'[]'),
		(2,'p-off-trust',1,'off','[]','[]',1,'["::1"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_incident',1),('lb_incident',2)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_incident", "2", "logged", "", policyByID, bindings)
	if pid != 2 || pname != "p-off-trust" {
		t.Fatalf("attribution=(%d,%q), want (2,p-off-trust) — IP 族 fallback 首选层必须优先具备 IP 控制发射面的策略(信任名单 logged 语义),而非无能力首候选", pid, pname)
	}
}

// A-3 ①「名单命中者优先」：多 deny 策略绑定下，contains 追加事件源 IP 成员判定
// ——名单未命中本 IP 的首绑 deny 策略不再凭「名单非空」误夺真属主（id 2/4 同
// 口径；条目支持精确与 CIDR）。IPv6 形状即生产事件源（::1）。
func TestSecurityEventsAttribution_IPACLMemberOwnerWinsOverNonMemberDeny(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups,ip_acl_enabled,ip_acl_mode,ip_acl_list,ip_blacklist) VALUES
		(1,'p-deny-other',1,'blocking','[]','[]',1,'deny','["203.0.113.5"]','[]'),
		(2,'p-deny-owner',1,'blocking','[]','[]',1,'deny','["2001:db8::/32"]','["10.0.0.0/8"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_member',1),('lb_member',2),
		('lb_member4',1),('lb_member4',2)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	cases := []struct {
		name     string
		rule     string
		clientIP string
		wantPID  int
	}{
		{"member owner wins (CIDR hit)", "lb_member", "2001:db8::5", 2},
		{"id:4 blacklist member wins", "lb_member", "10.0.0.7", 2},
		{"ip in no list (drift) -> first capable deny, never zero", "lb_member", "198.51.100.7", 1},
		{"empty clientIP keeps legacy non-empty-owner semantics", "lb_member", "", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name+" "+tc.clientIP, func(t *testing.T) {
			triggered := "2"
			if tc.clientIP == "10.0.0.7" {
				triggered = "4"
			}
			pid, _ := securityEventsAttributePolicy(tc.rule, triggered, "blocked", tc.clientIP, policyByID, bindings)
			if pid != tc.wantPID {
				t.Fatalf("attributePolicy(%s,%s,%s)=(%d), want %d", tc.rule, triggered, tc.clientIP, pid, tc.wantPID)
			}
		})
	}
}

// 任务书复现形状（生产合同钉）：[41 形 custom_only 无ACL, 42 形 detection 无ACL,
// 48 形 stage1 deny 含 ::1] + id:2 blocked（事件源 ::1）→ 归因 deny 属主 48 形。
// 2026-09-21 05:29 生产事故中该归属被「摄入快照绑定集不含属主 + fallback 无能力
// 首候选」双重击穿；本钉锁住「属主在绑定集内必胜出」的合同。
func TestSecurityEventsAttribution_Stage1DenyOwnerBeatsIncapablePolicies(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,policy_type,custom_rules,crs_rule_groups,ip_acl_enabled,ip_acl_mode,ip_acl_list) VALUES
		(1,'p-custom-only',1,'custom_only','stage3','[]','[]',0,'','[]'),
		(2,'p-detection',1,'detection','stage3','[]','[]',0,'','[]'),
		(3,'p-stage1-deny',1,'off','stage1','[]','[]',1,'deny','["::1"]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_dq2351774e',1),('lb_dq2351774e',2),('lb_dq2351774e',3)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	pid, pname := securityEventsAttributePolicy("lb_dq2351774e", "2", "blocked", "::1", policyByID, bindings)
	if pid != 3 || pname != "p-stage1-deny" {
		t.Fatalf("attribution=(%d,%q), want (3,p-stage1-deny) — deny 属主在绑定集内必须经 contains 成员命中胜出", pid, pname)
	}
}

// 畸形兜底（摄取必有归属）：绑定集内不存在任何有 IP 发射面的策略（含已知事件
// 源 IP 不在任何名单的漂移形状）时，能力首选层落空，仍按「模式/动作门」归属
// 首个可行绑定——禁止归零，禁止报错。
func TestSecurityEventsAttribution_IncapableOnlyStillAttributed(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES
		(1,'p-detection-noacl',1,'detection','[]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES ('lb_orphan',1)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	for _, clientIP := range []string{"", "::1", "198.51.100.7"} {
		pid, pname := securityEventsAttributePolicy("lb_orphan", "2", "blocked", clientIP, policyByID, bindings)
		if pid != 1 || pname != "p-detection-noacl" {
			t.Fatalf("attributePolicy(clientIP=%q)=(%d,%q), want (1,p-detection-noacl) — 无能力策略唯一存在必须回退首绑定,禁止归零", clientIP, pid, pname)
		}
	}
}

// R-6 真值表扩格（mode × IP 能力 × 动作）：能力首选层不得误拒既有合法形状——
// off+deny-ACL blocked 照旧首选（A35-SECLB-1 形状且真有能力）；refs-only deny
// 计能力（与发射端 refs 合并口径同源）；信任名单仅 logged 语义计能力，blocked
// 下不得抢过门禁可行但无能力的 detection 绑定；allow 模式不认领 id:2（A3 I-6
// 钉住的既有口径在能力层保持）；黑名单属主走 contains 不受影响。
func TestSecurityEventsAttribution_IPFamilyCapabilityTruthTable(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups,ip_acl_enabled,ip_acl_mode,ip_acl_list,ip_acl_list_refs,ip_whitelist_enabled,ip_whitelist) VALUES
		(1,'p-detection-noacl',1,'detection','[]','[]',0,'','[]','[]',0,'[]'),
		(2,'p-off-deny',1,'off','[]','[]',1,'deny','["::1"]','[]',0,'[]'),
		(3,'p-deny-refs-only',1,'blocking','[]','[]',1,'deny','[]','[9]',0,'[]'),
		(4,'p-off-trust',1,'off','[]','[]',0,'','[]','[]',1,'["::1"]'),
		(5,'p-allow',1,'blocking','[]','[]',1,'allow','["::1"]','[]',0,'[]'),
		(6,'p-geo-deny',1,'off','[]','[]',0,'','[]','[]',0,'[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE security_policies SET geoip_mode='deny', geoip_countries='["海外"]' WHERE id=6`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_off',1),('lb_off',2),
		('lb_refs',1),('lb_refs',3),
		('lb_trust',1),('lb_trust',4),
		('lb_allow',1),('lb_allow',5),
		('lb_geo',1),('lb_geo',6)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	cases := []struct {
		name     string
		rule     string
		id       string
		action   string
		clientIP string
		wantPID  int
	}{
		// off+deny-ACL blocked：clientIP 不在名单（漂移形状）排空 contains 后，
		// 能力首选层照旧首选（A35-SECLB-1 不得回归误拒、不归零）
		{"off deny-ACL blocked tier1", "lb_off", "2", "blocked", "198.51.100.7", 2},
		// off+deny-ACL blocked + 事件源在名单：contains 成员命中直达属主（合同形状）
		{"off deny-ACL member contains hit", "lb_off", "2", "blocked", "::1", 2},
		// refs-only deny（inline 空仅引用）计能力：logged 语义下优先于无能力 detection
		{"refs-only deny logged tier1", "lb_refs", "2", "logged", "198.51.100.7", 3},
		// 信任名单仅 logged 计能力：logged 下信任策略优先于无能力 detection
		{"trust wl logged tier1", "lb_trust", "2", "logged", "", 4},
		// blocked 下信任名单不计能力：无能力 detection 依模式门归属（不归零）
		{"trust wl blocked not capable", "lb_trust", "2", "blocked", "", 1},
		// allow 模式不认领 id:2（含成员命中形状）：blocked 下无能力 detection 归属
		{"allow mode never owns deny event", "lb_allow", "2", "blocked", "", 1},
		{"allow mode member ip still not owner", "lb_allow", "2", "blocked", "::1", 1},
		// 800xxx 属主漂移（属主 99 不在绑定集）：geoip 能力策略经能力首选层胜出
		{"800xxx drift geoip-capable tier1", "lb_geo", "800099", "blocked", "", 6},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, _ := securityEventsAttributePolicy(tc.rule, tc.id, tc.action, tc.clientIP, policyByID, bindings)
			if pid != tc.wantPID {
				t.Fatalf("attributePolicy(%s,%s,%s,ip=%s)=(%d), want %d", tc.rule, tc.id, tc.action, tc.clientIP, pid, tc.wantPID)
			}
		})
	}
}

// 2026-09-21 自定义族能力首选层（IP 族 securityEventsIPFamilyEventSurface 同模式
// 扩展）：emitCustomRules 对 Disabled 规则整条跳过（security.go「if !cr.Enabled
// { continue }」），无启用自定义规则的策略物理上不产任何自定义族事件——fallback
// 可行性门原本对该族在 custom_only/detection/blocking 下恒放行，无能力首绑凭
// 候选顺序抢先认领。合成 id（1000000+）在 contains 无分支、恒走 fallback，能力
// 首选层对该段是唯一精确化手段。全部用例排空 contains（事件 id 10005/1000001
// 不在任何策略引用集内），确保走的是 fallback 合成路径。
func TestSecurityEventsAttribution_CustomFamilyCapabilityPreference(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, description, conditions, action, score, enabled) VALUES
		(20,'启用规则A','', '[]','block',5,1),
		(21,'启用规则B','', '[]','block',5,1),
		(22,'启用规则C','', '[]','pass',5,1),
		(30,'停用规则','', '[]','block',5,0)`); err != nil {
		t.Fatal(err)
	}
	// 每对绑定中无能力策略 id 更小（policy_id ASC = 候选顺序在前），能力首选层
	// 胜出才可观测。p16（solo 无规则）/p17（引用停用规则）作必归属锚。
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups) VALUES
		(10,'p-blk-norules',1,'blocking','[]','[]'),
		(11,'p-blk-hasrules',1,'blocking','[20]','[]'),
		(12,'p-co-norules',1,'custom_only','[]','[]'),
		(13,'p-co-hasrules',1,'custom_only','[21]','[]'),
		(14,'p-det-norules',1,'detection','[]','["94"]'),
		(15,'p-det-hasrules',1,'detection','[22]','["94"]'),
		(16,'p-blk-solo-norules',1,'blocking','[]','[]'),
		(17,'p-blk-disabledref',1,'blocking','[30]','[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_blk',10),('lb_blk',11),
		('lb_co',12),('lb_co',13),
		('lb_det',14),('lb_det',15),
		('lb_solo',16),
		('lb_dis',10),('lb_dis',17)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	cases := []struct {
		name      string
		rule      string
		triggered string
		action    string
		wantPID   int
	}{
		// ── 能力首选层（RED 目标：无启用规则的策略不得抢先认领） ──
		{"blocking capable wins blocked", "lb_blk", "10005", "blocked", 11},
		{"blocking capable wins logged", "lb_blk", "10005", "logged", 11},
		{"blocking capable wins synthetic blocked", "lb_blk", "1000001", "blocked", 11},
		{"custom_only capable wins blocked", "lb_co", "10005", "blocked", 13},
		{"custom_only capable wins logged", "lb_co", "10005", "logged", 13},
		{"detection capable wins blocked", "lb_det", "10005", "blocked", 15},
		{"detection capable wins logged", "lb_det", "10005", "logged", 15},
		// detection 对 CRS blocked 恒拒（门既有口径）：能力维度不得放宽
		{"detection pair CRS blocked still rejected", "lb_det", "942100", "blocked", 0},
		// ── 必归属锚（摄取必有归属层，能力维度豁免；改动前后均须绿） ──
		// solo 无启用规则：能力首选层落空后仍归首绑（禁归零）
		{"solo no-rules still attributed", "lb_solo", "10005", "blocked", 16},
		// 引用停用规则不计能力：与无能力 p10 平局，归候选顺序第一（若 p17 被误判
		// 有能力，会经能力首选层抢在 p10 之前，本用例即失败）
		{"disabled ref counts as incapable", "lb_dis", "10005", "blocked", 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pid, _ := securityEventsAttributePolicy(tc.rule, tc.triggered, tc.action, "", policyByID, bindings)
			if pid != tc.wantPID {
				t.Fatalf("attributePolicy(%s,%s,%s)=(%d), want %d", tc.rule, tc.triggered, tc.action, pid, tc.wantPID)
			}
		})
	}
}

// R-6 真值表（mode × 自定义规则能力 × 动作 × 规则族）：可归因 = 模式/动作门
// （securityEventsFallbackCanProduce）∧（自定义族 → 存在启用自定义规则）。
// 门格逐格对照发射侧单一事实：
//   - off：CRS/自定义/body 守卫全关（仅 IP 族独立发射，非本表维度）；
//   - custom_only：CRS 全拒（零 Include）；id:11 blocked 拒（pass 动作恒不中断，
//     无 949 评分链）；logged 可产——emitBodyProcessorRules 在 custom_only 恒发射；
//   - detection：blocked 拒 CRS（id:6 切换先于 CRS）；自定义/含 id:11 logged 可产；
//   - blocking：门全域；id:11 blocked 保持可行格（发射面恒在；物理上 pass 恒不
//     中断、该形状事件不存在，恒真格无害）。
//     能力维度仅作用于自定义族（CRS 组选择不构成能力差异、id:11 与自定义规则
//     无关——均维持无能力维度）。
func TestSecurityEventsFallbackGate_CustomFamilyTruthTable(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, description, conditions, action, score, enabled) VALUES
		(20,'启用规则','', '[]','block',5,1),
		(30,'停用规则','', '[]','block',5,0)`); err != nil {
		t.Fatal(err)
	}
	newPolicy := func(mode, ref string) *models.SecurityPolicy {
		return &models.SecurityPolicy{Mode: mode, CustomRules: json.RawMessage(ref)}
	}
	// 能力面直接真值：引用形状 → 是否存在启用规则
	surfaceCases := []struct {
		name string
		ref  string
		want bool
	}{
		{"no refs incapable", `[]`, false},
		{"enabled ref capable", `[20]`, true},
		{"disabled ref incapable", `[30]`, false},
		{"dangling ref incapable", `[99]`, false},
		{"enabled plus disabled capable", `[20,30]`, true},
		{"disabled only incapable", `[30,31]`, false},
	}
	for _, tc := range surfaceCases {
		t.Run("surface/"+tc.name, func(t *testing.T) {
			if got := securityEventsCustomRulesEventSurface(newPolicy("blocking", tc.ref)); got != tc.want {
				t.Fatalf("customRulesEventSurface(ref=%s)=%v, want %v", tc.ref, got, tc.want)
			}
		})
	}
	// 合成真值表：want = 门 ∧（自定义族 → 能力面）。字面期望逐格写死。
	refs := map[string]string{"none": `[]`, "enabled": `[20]`, "disabled": `[30]`, "dangling": `[99]`}
	cells := []struct {
		name   string
		mode   string
		ref    string
		action string
		id     string
		want   bool
	}{
		// ── 自定义族 10005：off 恒不可产（门拒，能力无关） ──
		{"off none blocked", "off", "none", "blocked", "10005", false},
		{"off enabled blocked", "off", "enabled", "blocked", "10005", false},
		{"off enabled logged", "off", "enabled", "logged", "10005", false},
		// ── custom_only：门放行 logged/blocked，能力维度定真假（RED 格） ──
		{"custom_only none blocked", "custom_only", "none", "blocked", "10005", false},
		{"custom_only enabled blocked", "custom_only", "enabled", "blocked", "10005", true},
		{"custom_only none logged", "custom_only", "none", "logged", "10005", false},
		{"custom_only enabled logged", "custom_only", "enabled", "logged", "10005", true},
		// ── detection：同上（blocked 可产：自定义先于 id:6 切换） ──
		{"detection none blocked", "detection", "none", "blocked", "10005", false},
		{"detection enabled blocked", "detection", "enabled", "blocked", "10005", true},
		{"detection none logged", "detection", "none", "logged", "10005", false},
		{"detection enabled logged", "detection", "enabled", "logged", "10005", true},
		// ── blocking：门全域，能力维度定真假 ──
		{"blocking none blocked", "blocking", "none", "blocked", "10005", false},
		{"blocking enabled blocked", "blocking", "enabled", "blocked", "10005", true},
		{"blocking none logged", "blocking", "none", "logged", "10005", false},
		{"blocking enabled logged", "blocking", "enabled", "logged", "10005", true},
		// 停用/悬空引用均不计能力（enabled 过滤非空）
		{"blocking disabled blocked", "blocking", "disabled", "blocked", "10005", false},
		{"blocking dangling logged", "blocking", "dangling", "logged", "10005", false},
		// ── 合成 id 1000001 与 10005 同族同格（物理同形） ──
		{"custom_only enabled synthetic", "custom_only", "enabled", "blocked", "1000001", true},
		{"custom_only none synthetic", "custom_only", "none", "blocked", "1000001", false},
		{"blocking enabled synthetic logged", "blocking", "enabled", "logged", "1000001", true},
		// ── CRS 族：无能力维度（组选择不构成差异，维持）；门格锁定 ──
		{"off CRS blocked", "off", "enabled", "blocked", "942100", false},
		{"off CRS logged", "off", "enabled", "logged", "942100", false},
		{"custom_only CRS blocked", "custom_only", "enabled", "blocked", "942100", false},
		{"custom_only CRS logged", "custom_only", "enabled", "logged", "942100", false},
		{"detection CRS blocked", "detection", "enabled", "blocked", "942100", false},
		{"detection CRS logged", "detection", "enabled", "logged", "942100", true},
		{"blocking CRS none-ref blocked", "blocking", "none", "blocked", "942100", true},
		// ── id:11：无能力维度（与自定义规则无关）；门格锁定 ──
		{"off id11 blocked", "off", "enabled", "blocked", "11", false},
		{"off id11 logged", "off", "enabled", "logged", "11", false},
		{"custom_only id11 blocked", "custom_only", "enabled", "blocked", "11", false},
		{"custom_only id11 logged", "custom_only", "none", "logged", "11", true},
		{"detection id11 blocked", "detection", "enabled", "blocked", "11", false},
		{"detection id11 logged", "detection", "none", "logged", "11", true},
		{"blocking id11 blocked", "blocking", "none", "blocked", "11", true},
		{"blocking id11 logged", "blocking", "enabled", "logged", "11", true},
	}
	for _, tc := range cells {
		t.Run(tc.id+"/"+tc.name, func(t *testing.T) {
			p := newPolicy(tc.mode, refs[tc.ref])
			got := securityEventsFallbackCanProduce(p, tc.action, tc.id)
			if got && securityEventsRuleIsCustomFamily(tc.id) {
				got = securityEventsCustomRulesEventSurface(p)
			}
			if got != tc.want {
				t.Fatalf("attributable(mode=%s,ref=%s,%s,%s)=%v, want %v", tc.mode, tc.ref, tc.action, tc.id, got, tc.want)
			}
		})
	}
}

// 阶段 0 信任策略（stage0/直通）引擎零发射面（2026-09-20 裁定：直通=路由层
// subroute 短路零 coraza 事务；保留检测=id:12 DetectionOnly 全评估不拦，且
// BuildCorazaDirectives 对 stage0 产空串不出自有 handler）——对非 IP 族的任何
// 动作事件均不可产（mode=off 门恒拒，含信任 wl：wl 在能力面也仅 logged 语义）。
// 真值表锁格 + 与有能力兄弟绑定的合成形状；IP 族 blocked 的无属主漂移形状按
// S3 既有语义走必归属层归首绑（禁归零），一并锚定。
func TestSecurityEventsAttribution_Stage0ZeroEmissionSurfaceLock(t *testing.T) {
	dataDir := t.TempDir()
	if err := db.Initialize(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := db.InitializeMetricsDB(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_custom_rules (id, name, description, conditions, action, score, enabled) VALUES
		(20,'启用规则','', '[]','block',5,1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policies (id,name,enabled,mode,custom_rules,crs_rule_groups,ip_whitelist,ip_whitelist_enabled,policy_type,trust_detection) VALUES
		(9,'p-stage0-passthrough',1,'off','[]','[]','["::1"]',1,'stage0',0),
		(19,'p-stage0-detection',1,'off','[]','[]','["::1"]',1,'stage0',1),
		(11,'p-blk-hasrules',1,'blocking','[20]','[]','[]',0,'stage3',0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES
		('lb_s0p',9),('lb_s0d',19),
		('lb_mix',9),('lb_mix',11)`); err != nil {
		t.Fatal(err)
	}
	_, bindings, policyByID, err := securityEventsLoadMappings()
	if err != nil {
		t.Fatalf("load mappings: %v", err)
	}
	// 两个 stage0 形态 solo 绑定：非 IP 族（自定义/CRS/id:11）× 双动作全部归零
	for _, rule := range []string{"lb_s0p", "lb_s0d"} {
		for _, tc := range []struct {
			id, action string
		}{
			{"10005", "blocked"}, {"10005", "logged"},
			{"942100", "blocked"}, {"942100", "logged"},
			{"11", "blocked"}, {"11", "logged"},
		} {
			if pid, _ := securityEventsAttributePolicy(rule, tc.id, tc.action, "", policyByID, bindings); pid != 0 {
				t.Fatalf("stage0 %s (%s,%s)=(%d), want 0 — stage0 引擎零发射面,非 IP 族事件不可产", rule, tc.id, tc.action, pid)
			}
		}
	}
	// 合成形状：stage0（候选序第一）+ 有启用规则 blocking——自定义事件归后者
	if pid, _ := securityEventsAttributePolicy("lb_mix", "10005", "blocked", "", policyByID, bindings); pid != 11 {
		t.Fatalf("lb_mix (10005,blocked)=(%d), want 11 — stage0 不得凭候选顺序认领自定义事件", pid)
	}
	// IP 族 blocked 无属主（两个绑定均无 ACL 发射面）：按 S3 既有必归属语义归
	// 首绑 stage0，禁归零（能力首选层已拒绝两者,漂移形状归首启用绑定）
	if pid, _ := securityEventsAttributePolicy("lb_mix", "2", "blocked", "", policyByID, bindings); pid != 9 {
		t.Fatalf("lb_mix (2,blocked)=(%d), want 9 — 必归属层锚（S3 既有语义,禁归零）", pid)
	}
}
