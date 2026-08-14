package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
	"lazy-balancer-v2/internal/models"
	"lazy-balancer-v2/internal/services"
)

func newSecurityEventsRouter(t *testing.T) *gin.Engine {
	t.Helper()
	fakeCaddy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(fakeCaddy.Close)
	gin.SetMode(gin.TestMode)
	h := &Handlers{caddyService: services.NewCaddyService(fakeCaddy.URL)}
	router := gin.New()
	router.GET("/security/events", h.ListSecurityEvents)
	router.GET("/security/overview", h.GetSecurityOverview)
	return router
}

func seedSecurityEvent(t *testing.T, eventTime, ruleCaddyID string, policyID any, ruleTriggered, ruleMsg string) {
	t.Helper()
	var ruleName, policyName string
	db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&ruleName)
	db.DB.QueryRow("SELECT name FROM security_policies WHERE id=?", policyID).Scan(&policyName)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, policy_name)
		VALUES (?, ?, ?, '192.0.2.9', 'GET', '/a', 'crs', ?, ?, 'blocked', ?, ?)`,
		eventTime, ruleCaddyID, policyID, ruleTriggered, ruleMsg, ruleName, policyName); err != nil {
	}
}

func TestListSecurityEvents_returnsRuleAndPolicyNames(t *testing.T) {
	// Given a rule, a policy, and two events - one bound to both, one referencing neither
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_evtest1', '事件规则A', 'http', 8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('事件策略A')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	seedSecurityEvent(t, "2026-08-12 10:00:02", "lb_evtest1", policyID, "942100", "SQL Injection")
	seedSecurityEvent(t, "2026-08-12 10:00:01", "lb_ghost", 99999, "942100", "SQL Injection")

	// When the events list is requested
	recorder := getRequest(t, router, "/security/events")

	// Then each event carries the joined rule/policy name, falling back to empty when unbound
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []struct {
				RuleCaddyID string `json:"rule_caddy_id"`
				RuleName    string `json:"rule_name"`
				PolicyName  string `json:"policy_name"`
			} `json:"events"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if resp.Data.Total != 2 || len(resp.Data.Events) != 2 {
		t.Fatalf("events = %s", recorder.Body.String())
	}
	bound := resp.Data.Events[0] // newest first
	if bound.RuleCaddyID != "lb_evtest1" || bound.RuleName != "事件规则A" || bound.PolicyName != "事件策略A" {
		t.Fatalf("bound event = %+v, want joined rule/policy names", bound)
	}
	unbound := resp.Data.Events[1]
	if unbound.RuleCaddyID != "lb_ghost" || unbound.RuleName != "" || unbound.PolicyName != "" {
		t.Fatalf("unbound event = %+v, want empty names", unbound)
	}
}

func TestListSecurityEvents_legacyRowsFallBackToJoinedNames(t *testing.T) {
	// Given a rule and policy, plus a pre-migration event with empty snapshot columns
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_legacy1', '遗留规则', 'http', 8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES ('遗留策略')`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	seedSecurityEvent(t, "2026-08-12 10:00:01", "lb_legacy1", policyID, "942100", "SQL Injection")

	// When the events list is requested
	recorder := getRequest(t, router, "/security/events")

	// Then the empty snapshots fall back to the joined rule/policy names
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []struct {
				RuleName   string `json:"rule_name"`
				PolicyName string `json:"policy_name"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data.Events) != 1 {
		t.Fatalf("events = %s", recorder.Body.String())
	}
	if got := resp.Data.Events[0]; got.RuleName != "遗留规则" || got.PolicyName != "遗留策略" {
		t.Fatalf("legacy event = %+v, want joined names 遗留规则/遗留策略", got)
	}
}

func TestListSecurityEvents_returnsSnapshotNamesAfterRuleAndPolicyChanged(t *testing.T) {
	// Given two events whose names were snapshotted at ingest time; afterwards
	// the first rule/policy is renamed and the second rule/policy is deleted
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	seedRule := func(caddyID, name string) {
		t.Helper()
		if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES (?, ?, 'http', 8080)`, caddyID, name); err != nil {
			t.Fatalf("seed rule %s: %v", caddyID, err)
		}
	}
	seedPolicy := func(name string) int64 {
		t.Helper()
		res, err := db.DB.Exec(`INSERT INTO security_policies (name) VALUES (?)`, name)
		if err != nil {
			t.Fatalf("seed policy %s: %v", name, err)
		}
		id, err := res.LastInsertId()
		if err != nil {
			t.Fatalf("policy id: %v", err)
		}
		return id
	}
	seedSnapshotEvent := func(eventTime, ruleCaddyID string, policyID int64, ruleName, policyName string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, policy_name)
			VALUES (?, ?, ?, '192.0.2.9', 'GET', '/a', 'waf', '942100', 'SQL Injection', 'blocked', ?, ?)`,
			eventTime, ruleCaddyID, policyID, ruleName, policyName); err != nil {
			t.Fatalf("seed snapshot event: %v", err)
		}
	}

	seedRule("lb_snap1", "原规则名")
	policyA := seedPolicy("原策略名")
	seedSnapshotEvent("2026-08-12 10:00:02", "lb_snap1", policyA, "快照规则", "快照策略")
	seedRule("lb_snap2", "将删规则")
	policyB := seedPolicy("将删策略")
	seedSnapshotEvent("2026-08-12 10:00:01", "lb_snap2", policyB, "已删规则", "已删策略")

	if _, err := db.DB.Exec(`UPDATE lb_rules SET name='新规则名' WHERE caddy_id='lb_snap1'`); err != nil {
		t.Fatalf("rename rule: %v", err)
	}
	if _, err := db.DB.Exec(`UPDATE security_policies SET name='新策略名' WHERE id=?`, policyA); err != nil {
		t.Fatalf("rename policy: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM lb_rules WHERE caddy_id='lb_snap2'`); err != nil {
		t.Fatalf("delete rule: %v", err)
	}
	if _, err := db.DB.Exec(`DELETE FROM security_policies WHERE id=?`, policyB); err != nil {
		t.Fatalf("delete policy: %v", err)
	}

	// When the events list is requested
	recorder := getRequest(t, router, "/security/events")

	// Then snapshots win over the renamed join values and survive deletion
	if recorder.Code != http.StatusOK {
		t.Fatalf("list status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []struct {
				RuleCaddyID string `json:"rule_caddy_id"`
				RuleName    string `json:"rule_name"`
				PolicyName  string `json:"policy_name"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse list response: %v", err)
	}
	if len(resp.Data.Events) != 2 {
		t.Fatalf("events = %s", recorder.Body.String())
	}
	renamed := resp.Data.Events[0] // newest first
	if renamed.RuleCaddyID != "lb_snap1" || renamed.RuleName != "快照规则" || renamed.PolicyName != "快照策略" {
		t.Fatalf("renamed event = %+v, want snapshot names 快照规则/快照策略", renamed)
	}
	deleted := resp.Data.Events[1]
	if deleted.RuleCaddyID != "lb_snap2" || deleted.RuleName != "已删规则" || deleted.PolicyName != "已删策略" {
		t.Fatalf("deleted event = %+v, want snapshot names 已删规则/已删策略", deleted)
	}
}

func TestCategorizeAttack_familyMapping(t *testing.T) {
	cases := []struct {
		name          string
		ruleTriggered string
		ruleMsg       string
		want          string
	}{
		{"sqli", "942100", "SQL Injection Attack", "SQL注入"},
		{"xss", "941160", "XSS Filter", "XSS"},
		{"file inclusion", "930120", "OS File Access", "文件包含"},
		{"file read", "931130", "Path Traversal", "文件读取"},
		{"command injection", "932160", "Remote Command Execution", "命令注入"},
		{"php injection", "933150", "PHP Injection", "PHP注入"},
		{"code execution", "934100", "Code Execution", "代码执行"},
		{"protocol attack", "920350", "Protocol Attack", "协议攻击"},
		{"protocol anomaly", "921110", "HTTP Request Smuggling", "协议异常"},
		{"scanner", "913100", "Scanner Detected", "扫描探测"},
		{"blocking evaluation", "949110", "Inbound Anomaly Score Exceeded", "评估拦截"},
		{"custom prefix", "custom_12", "自定义拦截", "自定义规则"},
		{"ip blacklist via msg", "", "命中 IP 黑名单", "IP 访问控制"},
		{"ip whitelist via msg", "", "命中 IP 白名单", "IP 访问控制"},
		{"ip acl via msg", "", "触发 IP 访问控制", "IP 访问控制"},
		{"ip acl via id 2", "2", "", "IP 访问控制"},
		{"ip acl via id 3", "3", "", "IP 访问控制"},
		{"ip acl via id 4", "4", "", "IP 访问控制"},
		{"ip trust list via id 5", "5", "", "IP 访问控制"},
		{"empty input", "", "", "其他"},
		{"unmatched id", "123456", "something else", "其他"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := categorizeAttack(tc.ruleTriggered, tc.ruleMsg); got != tc.want {
				t.Fatalf("categorizeAttack(%q, %q) = %q, want %q", tc.ruleTriggered, tc.ruleMsg, got, tc.want)
			}
		})
	}
}

func TestGetSecurityOverview_returnsStoredCRSVersionAndUpdateStatus(t *testing.T) {
	// Given a stored CRS version row
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_crs_version (id, version, update_status) VALUES (1, 'v9.9.9', 'updating')`); err != nil {
		t.Fatalf("seed crs version: %v", err)
	}

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the stored version and update status are returned instead of any hardcoded value
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			CRSVersion   string `json:"crs_version"`
			UpdateStatus string `json:"update_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	if resp.Data.CRSVersion != "v9.9.9" {
		t.Fatalf("crs_version = %q, want v9.9.9", resp.Data.CRSVersion)
	}
	if resp.Data.UpdateStatus != "updating" {
		t.Fatalf("update_status = %q, want updating", resp.Data.UpdateStatus)
	}
}

func TestGetSecurityOverview_fallsBackToBundledCRSVersion(t *testing.T) {
	// Given no stored CRS version row
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the bundled version and idle status are reported
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			CRSVersion   string `json:"crs_version"`
			UpdateStatus string `json:"update_status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	if resp.Data.CRSVersion != services.CRSBundledVersion {
		t.Fatalf("crs_version = %q, want bundled %q", resp.Data.CRSVersion, services.CRSBundledVersion)
	}
	if resp.Data.UpdateStatus != "idle" {
		t.Fatalf("update_status = %q, want idle", resp.Data.UpdateStatus)
	}
}

func TestGetSecurityOverview_trendZeroFillsSevenDays(t *testing.T) {
	// Given events on only 2 of the last 7 days (blocked today, logged 3 days ago)
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	today := time.Now().UTC()
	day := func(offset int) string { return today.AddDate(0, 0, -offset).Format("2006-01-02") }
	seedWithAction := func(eventTime, action string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
			VALUES (?, 'lb_trend', 1, '192.0.2.9', 'GET', '/a', 'crs', '942100', 'SQL Injection', ?)`, eventTime, action); err != nil {
			t.Fatalf("seed trend event: %v", err)
		}
	}
	seedWithAction(day(0)+" 10:00:00", "blocked")
	seedWithAction(day(3)+" 11:00:00", "logged")

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the trend always covers today-6 … today ascending with zero-filled gaps
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	trend := resp.Data.Trend
	if len(trend) != 7 {
		t.Fatalf("trend length = %d, want exactly 7: %+v", len(trend), trend)
	}
	for i, point := range trend {
		if want := day(6 - i); point.Date != want {
			t.Fatalf("trend[%d].Date = %q, want %q (ascending today-6 … today)", i, point.Date, want)
		}
	}
	for _, point := range trend {
		switch point.Date {
		case day(0):
			if point.Blocked != 1 || point.Detected != 0 {
				t.Fatalf("today = blocked:%d detected:%d, want 1/0", point.Blocked, point.Detected)
			}
		case day(3):
			if point.Blocked != 0 || point.Detected != 1 {
				t.Fatalf("today-3 = blocked:%d detected:%d, want 0/1", point.Blocked, point.Detected)
			}
		default:
			if point.Blocked != 0 || point.Detected != 0 {
				t.Fatalf("day %s = blocked:%d detected:%d, want zero-filled 0/0", point.Date, point.Blocked, point.Detected)
			}
		}
	}
}

func TestGetSecurityOverview_topIPsListDistinctAttackFamilies(t *testing.T) {
	// Given one IP hitting SQLi rules twice (same family) and a custom rule once
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	seedSecurityEvent(t, now, "lb_x", 1, "942100", "SQL Injection")
	seedSecurityEvent(t, now, "lb_x", 1, "942190", "SQL Injection")
	seedSecurityEvent(t, now, "lb_x", 1, "custom_7", "自定义规则命中")

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the IP carries distinct categorized families joined by 、, most frequent first
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	if len(resp.Data.TopIPs) != 1 {
		t.Fatalf("top_ips = %+v, want exactly 1 entry", resp.Data.TopIPs)
	}
	if got, want := resp.Data.TopIPs[0].AttackType, "SQL注入、自定义规则"; got != want {
		t.Fatalf("attack_type = %q, want %q (distinct families, frequency desc)", got, want)
	}
}

func TestGetSecurityOverview_topIPsEmptyMessageYieldsOtherFamily(t *testing.T) {
	// Given an IP whose only event carries no rule id or message
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedSecurityEvent(t, time.Now().UTC().Format("2006-01-02 15:04:05"), "lb_x", 1, "", "")

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the uncategorized event surfaces as 其他, never an empty attack_type
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	if len(resp.Data.TopIPs) != 1 {
		t.Fatalf("top_ips = %+v, want exactly 1 entry", resp.Data.TopIPs)
	}
	if got := resp.Data.TopIPs[0].AttackType; got != "其他" {
		t.Fatalf("attack_type = %q, want %q", got, "其他")
	}
}

func TestGetSecurityOverview_groupsAttackTypesByFamily(t *testing.T) {
	// Given recent events spanning several families, with repeats inside a family
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedRecent := func(ruleTriggered, ruleMsg string, count int) {
		t.Helper()
		for i := 0; i < count; i++ {
			seedSecurityEvent(t, "2026-08-12 10:00:00", "lb_x", 1, ruleTriggered, ruleMsg)
		}
	}
	seedRecent("942100", "SQL Injection", 3)
	seedRecent("942190", "SQL Injection", 1) // same family as 942100
	seedRecent("941160", "XSS", 2)
	seedRecent("932160", "RCE", 1)
	seedRecent("custom_7", "自定义规则命中", 1)
	seedRecent("3", "命中 IP 黑名单", 1)

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then attack types are aggregated by family name, never by raw rule id
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			AttackTypes []struct {
				Name  string `json:"name"`
				Value int    `json:"value"`
			} `json:"attack_types"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	got := map[string]int{}
	for _, at := range resp.Data.AttackTypes {
		if at.Name == "942100" || at.Name == "941160" || at.Name == "932160" {
			t.Fatalf("raw rule id leaked into attack types: %+v", resp.Data.AttackTypes)
		}
		got[at.Name] = at.Value
	}
	want := map[string]int{"SQL注入": 4, "XSS": 2, "命令注入": 1, "自定义规则": 1, "IP 访问控制": 1}
	for name, value := range want {
		if got[name] != value {
			t.Fatalf("attack_types[%q] = %d, want %d (all: %+v)", name, got[name], value, resp.Data.AttackTypes)
		}
	}
}
