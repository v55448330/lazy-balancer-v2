package handlers

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

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

// seedSecurityEvent 播种一条**带归因快照**的事件：rule_name/policy_name 取自
// 当前规则/策略名并写入事件行（与摄取路径的真实形态一致）。列表查询只读快照
// 列（无 JOIN），所以「快照为空 → 名称列为空」的形态需直接 INSERT。
func seedSecurityEvent(t *testing.T, eventTime, ruleCaddyID string, policyID any, ruleTriggered, ruleMsg string) {
	t.Helper()
	var ruleName, policyName string
	// 规则/策略不存在时快照留空（种子允许只建事件），其余读取错误必须暴露——
	// 静默忽略会把库结构漂移伪装成「快照本来为空」。
	if err := db.DB.QueryRow("SELECT name FROM lb_rules WHERE caddy_id=?", ruleCaddyID).Scan(&ruleName); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("read rule name for %s: %v", ruleCaddyID, err)
	}
	if err := db.DB.QueryRow("SELECT name FROM security_policies WHERE id=?", policyID).Scan(&policyName); err != nil && !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("read policy name for %v: %v", policyID, err)
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, policy_name)
		VALUES (?, ?, ?, '185.199.109.9', 'GET', '/a', 'crs', ?, ?, 'blocked', ?, ?)`,
		eventTime, ruleCaddyID, policyID, ruleTriggered, ruleMsg, ruleName, policyName); err != nil {
		// 种子失败必须显式失败——空错误体让未播种形态被当成功能行为
		//（假绿/假红不可辨），聚合口径的回归保护随之失效。
		t.Fatalf("seed security event: %v", err)
	}
}

func TestListSecurityEvents_rejectsStartTimeAfterEndTime(t *testing.T) {
	// Given an event store queried with an inverted time range
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	// When the range start is later than the end
	recorder := getRequest(t, router, "/security/events?start_time=2026-08-12%2012:00:00&end_time=2026-08-12%2008:00:00")

	// Then the request is rejected with an explicit message instead of silently returning an empty page
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s, want 400", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "开始时间不能晚于结束时间") {
		t.Fatalf("body=%s, want explicit rejection message", recorder.Body.String())
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

	// Then each event carries its ingest-time snapshot name; unbound events show empty
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

func TestListSecurityEvents_excludeKeepsNullRuleTriggered(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,client_ip,method,uri,event_type,rule_triggered,rule_msg,action) VALUES
		('2026-08-12 10:00:01','93.184.216.7','GET','/null','crs',NULL,'other','blocked')`); err != nil {
		t.Fatal(err)
	}
	recorder := getRequest(t, router, "/security/events?rule_triggered_exclude=SQL注入")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Data.Total != 1 {
		t.Fatalf("total=%d, want 1（NULL rule_triggered 不得被 NOT(NULL) 吞掉）: %s", resp.Data.Total, recorder.Body.String())
	}
}

func TestListSecurityEvents_emptySnapshotRendersEmptyNames(t *testing.T) {
	// 契约：列表只读事件快照列（SELECT 无 JOIN lb_rules/security_policies）——
	// 快照为空的存量行显示空名称，不做事后 join 回退。本用例直接 INSERT 空快照，
	// 保证断言验证的是该契约本身，而不是种子自己写入的字段。
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)

	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id, name, protocol, listen_port) VALUES ('lb_legacy1', '遗留规则', 'http', 8080)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	// 规则/策略存在但事件快照列为空（迁移前写入的形态）
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action, rule_name, policy_name)
		VALUES ('2026-08-12 10:00:01','lb_legacy1',1,'185.199.109.9','GET','/a','crs','942100','SQL Injection','blocked','','')`); err != nil {
		t.Fatalf("seed legacy event: %v", err)
	}

	recorder := getRequest(t, router, "/security/events")
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
	if got := resp.Data.Events[0]; got.RuleName != "" || got.PolicyName != "" {
		t.Fatalf("empty-snapshot event = %+v, want empty names（列表不做 join 回退）", got)
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
			VALUES (?, ?, ?, '185.199.109.9', 'GET', '/a', 'waf', '942100', 'SQL Injection', 'blocked', ?, ?)`,
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

func TestListSecurityEvents_serverSideRequestContextMasking(t *testing.T) {
	cases := []struct {
		name       string
		role       string
		authType   string
		readOnly   bool
		headers    string
		wantPlain  bool
		wantObject bool
	}{
		{name: "admin JWT keeps plaintext", role: "admin", authType: "jwt", headers: `{"Authorization":"Bearer secret","Cookie":"session=secret","X-Request-ID":"ok"}`, wantPlain: true, wantObject: true},
		{name: "admin readwrite API key keeps plaintext", role: "admin", authType: "api_key", headers: `{"Authorization":"Bearer secret","Cookie":"session=secret","X-Request-ID":"ok"}`, wantPlain: true, wantObject: true},
		{name: "non admin is masked", role: "user", authType: "jwt", headers: `{"Authorization":"Bearer secret","Cookie":"session=secret","X-Request-ID":"ok"}`, wantObject: true},
		{name: "admin read-only API key is masked", role: "admin", authType: "api_key", readOnly: true, headers: `{"Authorization":"Bearer secret","Cookie":"session=secret","X-Request-ID":"ok"}`, wantObject: true},
		{name: "malformed headers fail closed", role: "user", authType: "jwt", headers: `not-json`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupSecurityPolicyTestDB(t)
			if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time,client_ip,method,uri,event_type,rule_triggered,rule_msg,action,request_headers,request_body) VALUES ('2026-10-18 10:00:00','93.184.216.7','POST','/login','crs','942100','SQL Injection','blocked',?,'username=alice&password=secret')`, tc.headers); err != nil {
				t.Fatal(err)
			}
			gin.SetMode(gin.TestMode)
			h := &Handlers{}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("role", tc.role)
				c.Set("auth_type", tc.authType)
				c.Set("api_key_read_only", tc.readOnly)
			})
			router.GET("/security/events", h.ListSecurityEvents)
			response := getRequest(t, router, "/security/events")
			if response.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			var payload struct {
				Data struct {
					Events []struct {
						RequestHeaders string `json:"request_headers"`
						RequestBody    string `json:"request_body"`
					} `json:"events"`
				} `json:"data"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
				t.Fatal(err)
			}
			if len(payload.Data.Events) != 1 {
				t.Fatalf("events=%d, want 1", len(payload.Data.Events))
			}
			event := payload.Data.Events[0]
			if tc.wantPlain {
				if event.RequestHeaders != tc.headers || event.RequestBody != "username=alice&password=secret" {
					t.Fatalf("privileged context changed: headers=%q body=%q", event.RequestHeaders, event.RequestBody)
				}
				return
			}
			if event.RequestBody != "" || strings.Contains(event.RequestHeaders, "secret") || strings.Contains(event.RequestHeaders, "alice") {
				t.Fatalf("sensitive context leaked: headers=%q body=%q", event.RequestHeaders, event.RequestBody)
			}
			if !tc.wantObject {
				if event.RequestHeaders != "{}" {
					t.Fatalf("malformed headers=%q, want {}", event.RequestHeaders)
				}
				return
			}
			if !strings.Contains(event.RequestHeaders, "••••••") || !strings.Contains(event.RequestHeaders, "X-Request-ID") {
				t.Fatalf("masked headers must retain names and mask marker: %q", event.RequestHeaders)
			}
		})
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
		{"generic attack", "934100", "Generic Attack", "通用攻击"},
		{"protocol enforcement", "920350", "Protocol Enforcement", "协议异常"},
		{"protocol attack", "921110", "HTTP Request Smuggling", "协议攻击"},
		{"scanner", "913100", "Scanner Detected", "扫描探测"},
		{"blocking evaluation", "949110", "Inbound Anomaly Score Exceeded", "请求阻断评估"},
		// 已装 CRS v4 组的具体分类（waf/crs/rules/
		// 目录实证规则 ID）——此前落兜底「其他」。
		{"multipart attack", "922110", "Multipart Attack", "Multipart 攻击"},
		{"response java leak", "952011", "Java Exception", "响应 Java 泄露"},
		{"response iis leak", "954012", "IIS Error", "响应 IIS 泄露"},
		{"web shell", "955011", "Web Shell Detected", "Web Shell"},
		{"response ruby leak", "956011", "Ruby Error", "响应 Ruby 泄露"},
		{"custom rule numeric id", "10001", "自定义拦截", "自定义规则"},
		{"synthetic custom rule id", "1000001", "旧版规则 命中", "自定义规则"},
		{"ip blacklist via msg", "", "命中 IP 黑名单", "IP 访问控制"},
		{"ip whitelist via msg", "", "命中 IP 白名单", "IP 访问控制"},
		{"ip acl via msg", "", "触发 IP 访问控制", "IP 访问控制"},
		{"ip acl via id 2", "2", "", "IP 访问控制"},
		// id:3/12 对齐 family 表/stage 桶归「信任名单」（发射
		// 为 pass,nolog 永不产事件——防御性归族，三侧同口径）
		{"trust precheck id 3", "3", "", "信任名单"},
		{"trust precheck id 12", "12", "", "信任名单"},
		{"ip acl via id 4", "4", "", "IP 访问控制"},
		// id:5 是「绕过模式占位」的信任名单 DetectionOnly 规则（id:3 同族
		// 变体）：历史/导入行按发射侧语义归「信任名单」。
		{"trust bypass id 5", "5", "", "信任名单"},
		{"geoip legacy id 8", "8", "", "地域拦截"},
		{"geoip precheck segment id", "800123", "", "地域拦截"},
		{"geoip precheck segment via msg", "800123", "GeoIP 区域拦截", "地域拦截"},
		{"geoip segment upper bound", "809999", "", "地域拦截"},
		{"crawler segment lower bound", "810016", "", "爬虫Bot"},
		{"crawler segment upper bound", "899999", "", "爬虫Bot"},
		// 限流：429 精确（与事件列表「限流」族/筛选同源）
		{"ratelimit 429", "429", "", "限流"},
		{"empty input", "", "", "其他"},
		{"custom rule six-digit id", "123456", "something else", "自定义规则"},
		// 收敛前语义钉：未列名 3 位前缀的 9xxxxx（CRS 保留段
		// 余数）在概览视图走 fall-through——msg 命中 IP 黑白名单门仍归 IP 访问
		// 控制，裸形态归「其他」（阶段视图则整段归 WAF，两视图有意分叉）。
		{"unlisted crs id with acl msg", "960100", "命中 IP 黑名单", "IP 访问控制"},
		{"unlisted crs id bare", "960100", "something else", "其他"},
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

func TestOverlayCRSOverviewUpdateStatus(t *testing.T) {
	for _, status := range []string{"checking", "downloading", "installing", "reloading"} {
		if got := overlayCRSOverviewUpdateStatus("idle", &services.CRSUpdateStatusSnapshot{Status: status}); got != status {
			t.Fatalf("active status %q overlaid as %q", status, got)
		}
	}
	if got := overlayCRSOverviewUpdateStatus("stored", nil); got != "stored" {
		t.Fatalf("nil manager snapshot must keep stored status, got %q", got)
	}
	if got := overlayCRSOverviewUpdateStatus("stored", &services.CRSUpdateStatusSnapshot{Status: "success"}); got != "stored" {
		t.Fatalf("terminal snapshot must not overwrite stored status, got %q", got)
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

// （2026-09-05 安全核心域审计 · 批准修复）：CRS 版本行查询失败必须显式报错。
// Given：库已初始化但 security_crs_version 表缺失（单表异常窗口——主库整体
// 故障时 ActivePolicies 会同挂触发 500，本测试钉住仅该表异常的静默窗口）。
// When：请求 /security/overview。
// Then：500「安全总览查询失败」——此前 err 被静默吞掉（err == nil 才应用），
// 违反本函数自述标准，面板静默回落捆绑版本 +「idle」与真实态不可区分。
// 无行（ErrNoRows）是全新安装的合法状态，200 回落契约由 fallsBackToBundled
// CRSVersion 钉住，不属故障。
func TestGetSecurityOverview_crsVersionQueryFailureReturns500(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	if _, err := db.DB.Exec(`DROP TABLE security_crs_version`); err != nil {
		t.Fatalf("drop crs version table: %v", err)
	}
	router := newSecurityEventsRouter(t)

	recorder := getRequest(t, router, "/security/overview")

	if recorder.Code != http.StatusInternalServerError {
		t.Fatalf("overview status=%d body=%s, want 500（CRS 版本查询失败必须显式报错，不得静默回落）", recorder.Code, recorder.Body.String())
	}
}

func TestGetSecurityOverview_trendBucketsLocalDateForNegativeOffset(t *testing.T) {
	// Given a western timezone (America/New_York, UTC-4 in summer) so the offset is negative
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	if _, err := time.LoadLocation("America/New_York"); err != nil {
		t.Fatalf("load America/New_York: %v", err)
	}
	services.ConfigureLocation("America/New_York")
	t.Cleanup(func() { services.ConfigureLocation("Asia/Shanghai") })

	loc := services.CurrentLocation()
	eventTime := time.Now().UTC()
	seedSecurityEvent(t, eventTime.Format("2006-01-02 15:04:05"), "lb_neg", 1, "942100", "SQL Injection")

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the event lands in the correct local-date bucket (no all-zero trend from "+-240")
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
	wantDate := eventTime.In(loc).Format("2006-01-02")
	for _, point := range resp.Data.Trend {
		if point.Date != wantDate {
			continue
		}
		if point.Blocked != 1 {
			t.Fatalf("trend[%s].blocked = %d, want 1: %+v", wantDate, point.Blocked, resp.Data.Trend)
		}
		return
	}
	t.Fatalf("trend missing bucket %s (got %+v)", wantDate, resp.Data.Trend)
}

func TestGetSecurityOverview_trendZeroFillsSevenDays(t *testing.T) {
	// Given events on only 2 of the last 7 days (blocked today, logged 3 days ago)
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	// 桶界按配置时区（Asia/Shanghai）计算，种子日期必须与 handler 同口径，
	// 否则在本地午夜后的第一个小时内（本地新一天、UTC 仍是前一天）跨界错位。
	today := time.Now().In(services.CurrentLocation())
	day := func(offset int) string { return today.AddDate(0, 0, -offset).Format("2006-01-02") }
	seedWithAction := func(eventTime, action string) {
		t.Helper()
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, rule_caddy_id, policy_id, client_ip, method, uri, event_type, rule_triggered, rule_msg, action)
			VALUES (?, 'lb_trend', 1, '185.199.109.9', 'GET', '/a', 'crs', '942100', 'SQL Injection', ?)`, eventTime, action); err != nil {
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
	seedSecurityEvent(t, now, "lb_x", 1, "10001", "自定义规则命中")

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

func TestGetSecurityOverview_topIPsSharesLocalSixDayWindowWithTrend(t *testing.T) {
	// Given a positive-offset timezone so local midnight precedes UTC midnight
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	services.ConfigureLocation("Asia/Shanghai")
	t.Cleanup(func() { services.ConfigureLocation("Asia/Shanghai") })
	loc := services.CurrentLocation()
	now := time.Now().In(loc)
	todayStartUTC := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc).UTC()
	// 落在本地 6 日窗口内、但早于 UTC 当日 0 点的事件：修复前 TopIPs 会漏掉。
	boundary := todayStartUTC.AddDate(0, 0, -6).Add(time.Hour).Format("2006-01-02 15:04:05")
	seedSecurityEvent(t, boundary, "lb_x", 1, "942100", "SQL Injection")

	// When the overview is requested
	recorder := getRequest(t, router, "/security/overview")

	// Then the boundary event is counted in BOTH the trend and TopIPs
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
	wantDate := todayStartUTC.AddDate(0, 0, -6).In(loc).Format("2006-01-02")
	foundTrend := false
	for _, point := range resp.Data.Trend {
		if point.Date == wantDate && point.Blocked >= 1 {
			foundTrend = true
			break
		}
	}
	if !foundTrend {
		t.Fatalf("trend missing boundary event on %s: %+v", wantDate, resp.Data.Trend)
	}
	foundTop := false
	for _, ip := range resp.Data.TopIPs {
		if ip.IP == "185.199.109.9" && ip.Blocked+ip.Detected >= 1 {
			foundTop = true
			break
		}
	}
	if !foundTop {
		t.Fatalf("TopIPs missing boundary event (local window not applied): %+v", resp.Data.TopIPs)
	}
}

func TestGetSecurityOverview_groupsAttackTypesByFamily(t *testing.T) {
	// Given recent events spanning several families, with repeats inside a family
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedRecent := func(ruleTriggered, ruleMsg string, count int) {
		t.Helper()
		// 事件时间必须落在总览「今日-6 天」窗口内：固定日期会随窗口推移掉出
		// 窗口（定时炸弹，跨午夜即现），按当前时间动态生成。
		eventTime := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05")
		for i := 0; i < count; i++ {
			seedSecurityEvent(t, eventTime, "lb_x", 1, ruleTriggered, ruleMsg)
		}
	}
	seedRecent("942100", "SQL Injection", 3)
	seedRecent("942190", "SQL Injection", 1) // same family as 942100
	seedRecent("941160", "XSS", 2)
	seedRecent("932160", "RCE", 1)
	seedRecent("10001", "自定义规则命中", 1)
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

func insertOverviewAggregateEvent(t *testing.T, metrics *sql.DB, eventTime string) {
	t.Helper()
	if _, err := metrics.Exec(`INSERT INTO security_events
		(event_time,client_ip,rule_triggered,rule_msg,action)
		VALUES (?,'185.199.109.9','942100','SQL Injection','blocked')`, eventTime); err != nil {
		t.Fatalf("seed aggregate event: %v", err)
	}
}

func overviewAggregateEventCount(data securityOverviewAggregates) int {
	total := 0
	for _, point := range data.trend {
		total += point.Blocked + point.Detected
	}
	return total
}

func TestLoadSecurityOverviewAggregates_cacheHitAndExpiry(t *testing.T) {
	// Given 一个真实指标库与固定缓存键。
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	today := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	const todayStart = "2026-10-18 16:00:00"
	const tzModifier = "+08:00"
	insertOverviewAggregateEvent(t, db.MetricsDB, "2026-10-19 01:00:00")
	first, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier)
	if err != nil || overviewAggregateEventCount(first) != 1 {
		t.Fatalf("first aggregate=(count %d, err %v), want (1,nil)", overviewAggregateEventCount(first), err)
	}

	// When 同键再次读取，期间新增事件不应穿透 30s 缓存。
	insertOverviewAggregateEvent(t, db.MetricsDB, "2026-10-19 01:01:00")
	cached, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier)
	if err != nil || overviewAggregateEventCount(cached) != 1 {
		t.Fatalf("cached aggregate=(count %d, err %v), want (1,nil)", overviewAggregateEventCount(cached), err)
	}

	// Then 缓存过期后同一键必须重算并看到新事件（直接调整测试缓存项的
	// 过期时刻，避免 30s wall-clock sleep）。
	securityOverviewAggCacheMu.Lock()
	for key, entry := range securityOverviewAggCache {
		if key.metrics == db.MetricsDB {
			entry.expiresAt = time.Now().Add(-time.Second)
			securityOverviewAggCache[key] = entry
		}
	}
	securityOverviewAggCacheMu.Unlock()
	expired, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier)
	if err != nil || overviewAggregateEventCount(expired) != 2 {
		t.Fatalf("expired aggregate=(count %d, err %v), want (2,nil)", overviewAggregateEventCount(expired), err)
	}
}

func TestLoadSecurityOverviewAggregates_cacheKeysIncludeDayTimezoneAndDatabase(t *testing.T) {
	// Given 同库初始键的缓存。
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	firstDB := db.MetricsDB
	today := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	const todayStart = "2026-10-18 16:00:00"
	insertOverviewAggregateEvent(t, firstDB, "2026-10-19 01:00:00")
	if _, err := loadSecurityOverviewAggregates(firstDB, today, todayStart, "+08:00"); err != nil {
		t.Fatal(err)
	}

	// When 日界变化，必须重算而不是复用前一日键。
	insertOverviewAggregateEvent(t, firstDB, "2026-10-19 01:01:00")
	nextDay, err := loadSecurityOverviewAggregates(firstDB, today.AddDate(0, 0, 1), "2026-10-19 16:00:00", "+08:00")
	if err != nil || overviewAggregateEventCount(nextDay) != 2 {
		t.Fatalf("next-day aggregate=(count %d, err %v), want (2,nil)", overviewAggregateEventCount(nextDay), err)
	}

	// Then 时区键变化同样重算；原始日界/时区键仍保留自己的快照。
	insertOverviewAggregateEvent(t, firstDB, "2026-10-19 01:02:00")
	otherTimezone, err := loadSecurityOverviewAggregates(firstDB, today.AddDate(0, 0, 1), "2026-10-19 16:00:00", "-04:00")
	if err != nil || overviewAggregateEventCount(otherTimezone) != 3 {
		t.Fatalf("timezone aggregate=(count %d, err %v), want (3,nil)", overviewAggregateEventCount(otherTimezone), err)
	}
	original, err := loadSecurityOverviewAggregates(firstDB, today, todayStart, "+08:00")
	if err != nil || overviewAggregateEventCount(original) != 1 {
		t.Fatalf("original key aggregate=(count %d, err %v), want cached (1,nil)", overviewAggregateEventCount(original), err)
	}

	// When 换指标库，即使日界与时区相同也不得命中旧库缓存。
	if err := db.InitializeMetricsDB(t.TempDir()); err != nil {
		t.Fatalf("initialize second metrics DB: %v", err)
	}
	secondDB := db.MetricsDB
	t.Cleanup(func() {
		_ = secondDB.Close()
		db.MetricsDB = firstDB
	})
	secondDBData, err := loadSecurityOverviewAggregates(secondDB, today, todayStart, "+08:00")
	if err != nil || overviewAggregateEventCount(secondDBData) != 0 {
		t.Fatalf("second DB aggregate=(count %d, err %v), want (0,nil)", overviewAggregateEventCount(secondDBData), err)
	}
}

func TestLoadSecurityOverviewAggregates_doesNotCacheFailures(t *testing.T) {
	// Given 同键首轮聚合因表缺失而失败。
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	today := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	const todayStart = "2026-10-18 16:00:00"
	if _, err := db.MetricsDB.Exec(`DROP TABLE security_events`); err != nil {
		t.Fatal(err)
	}
	if _, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, "+08:00"); err == nil {
		t.Fatal("aggregate with missing events table must fail")
	}

	// When 故障消除后用完全相同的键重试。
	if _, err := db.MetricsDB.Exec(`CREATE TABLE security_events (
		event_time DATETIME, action TEXT, client_ip TEXT, rule_triggered TEXT, rule_msg TEXT
	)`); err != nil {
		t.Fatalf("recreate events table: %v", err)
	}
	insertOverviewAggregateEvent(t, db.MetricsDB, "2026-10-19 01:00:00")
	recovered, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, "+08:00")

	// Then 失败轮不得缓存，重试必须真实执行并返回新数据。
	if err != nil || overviewAggregateEventCount(recovered) != 1 {
		t.Fatalf("recovered aggregate=(count %d, err %v), want (1,nil)", overviewAggregateEventCount(recovered), err)
	}
}

// (2026-09-10 审计):①family 筛选单数字前缀无长度约束,自定义 5 位 ID
// (24567 等)交叉命中 IP/地域族;②id:11(请求体解析失败守卫)三侧分类缺标签。
func TestRuleTriggeredFilterSQL_singleDigitFamiliesUseExactMatch(t *testing.T) {
	var args []any
	sql := ruleTriggeredFilterSQL("IP 访问控制", &args)
	if strings.Contains(sql, "LIKE") {
		t.Fatalf("单数字族必须精确匹配(不得 LIKE 前缀): %s", sql)
	}
	for _, a := range args {
		if s, ok := a.(string); ok && strings.HasSuffix(s, "%") {
			t.Fatalf("单数字族参数不得带 %% 通配: %v", args)
		}
	}
	// 自定义规则族不得命中 IP 族条件：其条件由长度约束的 GLOB 承载（非 LIKE
	// 前缀），且不追加查询参数（原 _ = customSQL 为假断言）。
	var customArgs []any
	customSQL := ruleTriggeredFilterSQL("自定义规则", &customArgs)
	if strings.Contains(customSQL, "LIKE") {
		t.Fatalf("自定义规则族不得用 LIKE 前缀匹配: %s", customSQL)
	}
	if !strings.Contains(customSQL, customRuleFamilyCondition) {
		t.Fatalf("自定义规则族须含长度约束条件 %q: %s", customRuleFamilyCondition, customSQL)
	}
	if len(customArgs) != 0 {
		t.Fatalf("自定义规则族不得追加查询参数: %v", customArgs)
	}
}

func TestCategorizeAttack_bodyProcessorErrorAndNoCrossFamily(t *testing.T) {
	if got := categorizeAttack("11", "请求体解析失败"); got != "请求体异常" {
		t.Fatalf("categorizeAttack(11)=%q, want 请求体异常", got)
	}
	// 自定义规则 5 位 ID 不落 IP/地域族
	if got := categorizeAttack("24567", ""); got != "自定义规则" {
		t.Fatalf("categorizeAttack(24567)=%q, want 自定义规则", got)
	}
	if got := categorizeAttack("82345", ""); got != "自定义规则" {
		t.Fatalf("categorizeAttack(82345)=%q, want 自定义规则", got)
	}
}

// MetricsDB 未装配的兜底返回必须与成功路径同形状——
// 键为 events（引入防 panic 时误用 list 键，前端按 events 解析
// 拿到 undefined 空列表）。
func TestListSecurityEvents_nilMetricsDBFallbackUsesEventsKey(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	orig := db.MetricsDB
	db.MetricsDB = nil
	t.Cleanup(func() { db.MetricsDB = orig })

	recorder := getRequest(t, router, "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200 (nil MetricsDB must degrade to empty page)", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data map[string]json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	eventsRaw, ok := payload.Data["events"]
	if !ok {
		t.Fatalf("data keys=%v, want events key (fallback must match success response shape)", payload.Data)
	}
	if string(eventsRaw) != "[]" {
		t.Fatalf("data.events=%s, want []", eventsRaw)
	}
}

// ---- 回归钉 ----

func TestListSecurityEvents_triggerTypePopulated(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	cases := map[string]string{
		"2":       "IP 访问控制",
		"800001":  "地域拦截",
		"810016":  "爬虫Bot",
		"850003":  "爬虫Bot",
		"429":     "限流",
		"942100":  "WAF·CRS",
		"10000":   "WAF·自定义",
		"1000001": "WAF·自定义",
		"11":      "请求体异常",
	}
	for rule := range cases {
		seedSecurityEvent(t, "2026-10-18 10:00:00", "", 0, rule, "")
	}
	recorder := getRequest(t, router, "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Events []models.SecurityEvent `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Data.Events) != len(cases) {
		t.Fatalf("events=%d, want %d", len(payload.Data.Events), len(cases))
	}
	for _, e := range payload.Data.Events {
		want, ok := cases[e.RuleTriggered]
		if !ok {
			continue
		}
		if e.TriggerType == "" {
			t.Fatalf("rule %s trigger_type empty（接线缺失）", e.RuleTriggered)
		}
		if e.TriggerType != want {
			t.Fatalf("rule %s trigger_type=%q, want %q", e.RuleTriggered, e.TriggerType, want)
		}
	}
}

func TestRuleTriggeredFilter_crawlerSegmentSQL(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	rows := []string{"800007", "810016", "850003", "899999", "10001", "10091", "942100"}
	for _, rule := range rows {
		if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, rule_triggered) VALUES ('2026-10-18 10:00:00', '93.184.216.7', ?)`, rule); err != nil {
			t.Fatal(err)
		}
	}
	query := func(label string) []string {
		var args []any
		cond := ruleTriggeredFilterSQL(label, &args)
		rs, err := db.MetricsDB.Query(`SELECT rule_triggered FROM security_events WHERE `+cond, args...)
		if err != nil {
			t.Fatalf("family %s query: %v (sql=%s)", label, err, cond)
		}
		defer rs.Close()
		var out []string
		for rs.Next() {
			var v string
			if err := rs.Scan(&v); err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	region := query("地域拦截")
	if len(region) != 1 || region[0] != "800007" {
		t.Fatalf("地域拦截 family=%v, want [800007]（爬虫 6 位段不得混入）", region)
	}
	crawler := query("爬虫Bot")
	have := map[string]bool{}
	for _, v := range crawler {
		have[v] = true
	}
	for _, want := range []string{"810016", "850003", "899999"} {
		if !have[want] {
			t.Fatalf("爬虫Bot family missing %s (got %v)", want, crawler)
		}
	}
	if have["800007"] || have["10001"] || have["10091"] || have["942100"] {
		t.Fatalf("爬虫Bot family leaked non-crawler ids: %v", crawler)
	}
}

func TestAttackFamilyClassOf_crawlerSegment(t *testing.T) {
	cases := map[string]attackFamilyClass{
		"800007": attackFamilyGeoIP,
		"810016": attackFamilyCrawler,
		"850003": attackFamilyCrawler,
		"899999": attackFamilyCrawler,
		"10001":  attackFamilyCustomRule,
		"942100": attackFamilyOther, // CRS 前缀由 crsAttackLabel 承载
	}
	for rule, want := range cases {
		if got := attackFamilyClassOf(rule, ""); got != want {
			t.Errorf("class(%s)=%v, want %v", rule, got, want)
		}
	}
	if got := categorizeAttack("810016", ""); got != "爬虫Bot" {
		t.Errorf("categorizeAttack(810016)=%q, want 爬虫Bot", got)
	}
	if got := stageCategorizeAttack("850003", ""); got != "IP 访问控制" {
		t.Errorf("stageCategorizeAttack(850003)=%q, want IP 访问控制", got)
	}
}

// Given 总览近 7 天卡片直读原始事件表。
// When 原始表被裁剪、覆盖完整或为空。
// Then API 始终披露最早原始事件时间，且只在窗口前段缺失时标记不完整。
func TestGetSecurityOverview_rawCoverageDisclosure(t *testing.T) {
	readData := func(t *testing.T) map[string]any {
		t.Helper()
		recorder := getRequest(t, newSecurityEventsRouter(t), "/security/overview")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		var payload struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode overview: %v", err)
		}
		return payload.Data
	}
	assertShape := func(t *testing.T, data map[string]any) (string, bool) {
		t.Helper()
		rawValue, rawOK := data["raw_coverage_from"]
		incompleteValue, incompleteOK := data["backfill_incomplete"]
		if !rawOK || !incompleteOK {
			t.Fatalf("覆盖披露字段缺失: %+v", data)
		}
		raw, rawIsString := rawValue.(string)
		incomplete, incompleteIsBool := incompleteValue.(bool)
		if !rawIsString || !incompleteIsBool {
			t.Fatalf("覆盖披露字段类型错误: %+v", data)
		}
		return raw, incomplete
	}

	t.Run("裁剪后披露缺口", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		seedThreatScreenEvent(t, utcStringAgo(time.Hour), "93.184.216.7", "942100", "SQL Injection", "blocked")
		raw, incomplete := assertShape(t, readData(t))
		if raw == "" || !incomplete {
			t.Fatalf("raw=%q incomplete=%v, want 非空且 true", raw, incomplete)
		}
	})
	t.Run("覆盖完整不误报", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		seedThreatScreenEvent(t, utcStringAgo(8*24*time.Hour), "93.184.216.7", "942100", "SQL Injection", "blocked")
		raw, incomplete := assertShape(t, readData(t))
		if raw == "" || incomplete {
			t.Fatalf("raw=%q incomplete=%v, want 非空且 false", raw, incomplete)
		}
	})
	t.Run("空表不算裁剪", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		raw, incomplete := assertShape(t, readData(t))
		if raw != "" || incomplete {
			t.Fatalf("raw=%q incomplete=%v, want 空且 false", raw, incomplete)
		}
	})
}

// Given 采集 daemon 连续失败达到阈值。
// When 事件列表 API 返回。
// Then ingestion 状态位显性暴露 unhealthy 与错误，供事件页提示。
func TestListSecurityEvents_disclosesIngestionHealth(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	services.SecurityEventsSetIngestionHealthForTest(services.SecurityEventsIngestionStatus{
		Observed:            true,
		Healthy:             false,
		ConsecutiveFailures: 3,
		LastError:           "metrics database unavailable",
		LastErrorAt:         "2026-10-19T00:00:00Z",
	})
	t.Cleanup(func() { services.SecurityEventsSetIngestionHealthForTest(services.SecurityEventsIngestionStatus{}) })

	recorder := getRequest(t, newSecurityEventsRouter(t), "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Ingestion services.SecurityEventsIngestionStatus `json:"ingestion"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	got := payload.Data.Ingestion
	if !got.Observed || got.Healthy || got.ConsecutiveFailures != 3 || got.LastError == "" {
		t.Fatalf("ingestion=%+v, want unhealthy snapshot with error", got)
	}
}

// 列表投影在 SQL 侧只取「截断上限 +1 字节」探针（CAST AS BLOB 按字节计），
// Go 侧仍按 rune 边界回退并追加同一截断标记——响应形态不变，但 DB→进程
// 传输不再是大字段全量（100 行 × 64KB/字段），多字节内容也不会 4× 过取。
func TestListSecurityEvents_largeFieldsCappedWithMarker(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	// 管理视角：服务端脱敏对 admin 不触发（否则 request_body 恒空、无法断言截断）。
	router.GET("/security/events", func(c *gin.Context) { c.Set("role", "admin") }, h.ListSecurityEvents)

	ascii := strings.Repeat("a", 20*1024)
	multibyte := strings.Repeat("中", 7000) // 21000 字节 > 16KB 上限
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, action, request_headers, request_body)
		VALUES ('2026-10-19 10:00:00','185.199.108.9','blocked',?,?)`, ascii, multibyte); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	recorder := getRequest(t, router, "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Events []models.SecurityEvent `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(payload.Data.Events) != 1 {
		t.Fatalf("events=%d, want 1", len(payload.Data.Events))
	}
	event := payload.Data.Events[0]
	if got, want := event.RequestHeaders, strings.Repeat("a", securityEventListFieldCap)+"\n...[TRUNCATED]"; got != want {
		t.Fatalf("request_headers len=%d, want 上限+标记（%d）", len(got), len(want))
	}
	if !strings.HasSuffix(event.RequestBody, "\n...[TRUNCATED]") {
		t.Fatalf("request_body lacks truncation marker (len=%d)", len(event.RequestBody))
	}
	trimmed := strings.TrimSuffix(event.RequestBody, "\n...[TRUNCATED]")
	if trimmed != strings.Repeat("中", len(trimmed)/len("中")) || !utf8.ValidString(trimmed) {
		t.Fatalf("request_body 截断必须落在字符边界且不超上限，len=%d", len(trimmed))
	}
	if len(trimmed) > securityEventListFieldCap {
		t.Fatalf("request_body 截断后 len=%d > cap=%d", len(trimmed), securityEventListFieldCap)
	}
	// 传输侧口径：多字节值在 SQL 侧也必须按字节截断（字符口径会取回
	// 16K 字符 ≈ 48KB）。探针 +1 字节用于 Go 侧判定「原值更长」。
	var projected string
	if err := db.MetricsDB.QueryRow("SELECT " + securityEventListFieldSQL("request_body") + " FROM security_events LIMIT 1").Scan(&projected); err != nil {
		t.Fatalf("SQL 投影: %v", err)
	}
	if len(projected) > securityEventListFieldCap+1 {
		t.Fatalf("SQL 投影取回 %d 字节 > cap+1（多字节内容按字符口径过取）", len(projected))
	}
}

// 缓存键必须是时区身份（loc.String()）而不是瞬时偏移：同样 +08:00 的两个
// 时区（Asia/Shanghai/Asia/Taipei）日桶按各自 location 逐日构造，若键只存
// 偏移就会在 TTL 内共用另一时区的聚合。
func TestLoadSecurityOverviewAggregates_timezoneIdentityKeyNotOffset(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	database := db.MetricsDB
	today := time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)
	insertOverviewAggregateEvent(t, database, "2026-10-19 01:00:00")

	if _, err := loadSecurityOverviewAggregates(database, today, "2026-10-18 16:00:00", "Asia/Shanghai"); err != nil {
		t.Fatal(err)
	}
	insertOverviewAggregateEvent(t, database, "2026-10-19 01:01:00")
	taipei, err := loadSecurityOverviewAggregates(database, today, "2026-10-18 16:00:00", "Asia/Taipei")
	if err != nil {
		t.Fatal(err)
	}
	if got := overviewAggregateEventCount(taipei); got != 2 {
		t.Fatalf("同偏移不同时区身份必须重算（got %d, want 2）", got)
	}
	cached, err := loadSecurityOverviewAggregates(database, today, "2026-10-18 16:00:00", "Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	if got := overviewAggregateEventCount(cached); got != 1 {
		t.Fatalf("原时区键快照必须保留（got %d, want 1）", got)
	}
}

// 近 7 天覆盖判定必须按「本地日界逐日回退」而不是「UTC 时刻 −6×24h」：
// 跨 DST 的 6 天不是 144h（这里是 145h），单一平移会让窗口起点偏 1h →
// backfill_incomplete 误报/漏报。
func TestSecurityOverviewSevenDayStartUTC_dstCorrect(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Skipf("tzdata unavailable: %v", err)
	}
	// 2026-11-01 美国夏令时结束；todayStart=11-02 00:00 EST（UTC-5）。
	todayStart := time.Date(2026, 11, 2, 0, 0, 0, 0, loc)
	got := securityOverviewSevenDayStartUTC(todayStart)
	// 本地 10-27 00:00 EDT（UTC-4）= 10-27 04:00 UTC。
	want := "2026-10-27 04:00:00"
	if got != want {
		t.Fatalf("seven-day start=%q, want %q（逐日回退，非 -144h 平移）", got, want)
	}
	if naive := todayStart.UTC().Add(-6 * 24 * time.Hour).Format("2006-01-02 15:04:05"); got == naive {
		t.Fatalf("覆盖判定仍用单一 UTC 平移（%q）", naive)
	}
}

// 事件列表错误形态统一：计数失败与主查询失败同文案（泛化「安全事件查询失败」，
// 不向登录用户泄露存储层错误文本）；MetricsDB 未装配的降级响应回显请求的分页
// 值（此前硬编码 page=1/page_size=20，前端/Agent 对分页字段假设失真）。
func TestListSecurityEvents_errorShapeUnified(t *testing.T) {
	t.Run("主查询失败泛化文案", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityEventsRouter(t)
		// 计数可查、主查询必败：以缺列同名表替换（COUNT(*) 不触列）。
		if _, err := db.MetricsDB.Exec(`ALTER TABLE security_events RENAME TO security_events_full`); err != nil {
			t.Fatal(err)
		}
		if _, err := db.MetricsDB.Exec(`CREATE TABLE security_events (id INTEGER)`); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = db.MetricsDB.Exec(`DROP TABLE security_events`)
			_, _ = db.MetricsDB.Exec(`ALTER TABLE security_events_full RENAME TO security_events`)
		})

		recorder := getRequest(t, router, "/security/events")
		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status=%d body=%s, want 500", recorder.Code, recorder.Body.String())
		}
		body := recorder.Body.String()
		if !strings.Contains(body, "安全事件查询失败") {
			t.Fatalf("body=%s, want 泛化文案「安全事件查询失败」", body)
		}
		if strings.Contains(body, "no such column") || strings.Contains(body, "SQL logic error") {
			t.Fatalf("body=%s, 不得向登录用户泄露存储层错误文本", body)
		}
	})

	t.Run("降级响应回显请求分页值", func(t *testing.T) {
		setupSecurityPolicyTestDB(t)
		router := newSecurityEventsRouter(t)
		orig := db.MetricsDB
		db.MetricsDB = nil
		t.Cleanup(func() { db.MetricsDB = orig })

		recorder := getRequest(t, router, "/security/events?page=3&page_size=7")
		if recorder.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
		}
		var payload struct {
			Data struct {
				Page     int `json:"page"`
				PageSize int `json:"page_size"`
			} `json:"data"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Data.Page != 3 || payload.Data.PageSize != 7 {
			t.Fatalf("降级响应分页=(%d,%d), want (3,7)（回显请求值）", payload.Data.Page, payload.Data.PageSize)
		}
	})
}

// 列表 16KB 裁剪与采集 64KB 裁剪的丢弃计数键分离：采集计数键原样保留，
// 列表裁剪计入独立键（前端按来源分文案——并入同一键会把 16KB 列表裁剪
// 误标为「超出 64KB 采集上限」）。
//
// 入参来自 SQL 侧 cap+1 字节前缀（超限行的列值必然被切断）：前缀内的完整
// 成员原样保留，被切断的尾部键数=总键数−已解出键数。
func TestTruncateEventListHeaders_prefixKeepsCompleteMembersAndCountsDropped(t *testing.T) {
	headers := map[string][]string{
		securityEventDroppedHeadersKey: {"2"}, // 采集侧已丢弃 2 条
		"Host":                         {"a.example.com"},
	}
	// 大量长键名短值头：序列化后远超 16KB（超限行只会取回前缀）。
	for i := range time.Duration(2000) {
		headers["x-trace-header-"+strings.Repeat("k", 40)+"-"+i.String()] = []string{"v"}
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= securityEventListFieldCap {
		t.Fatalf("夹具必须超过列表上限: %d", len(raw))
	}
	prefix := string(raw[:securityEventListFieldCap+1])

	got := truncateEventListHeaders(prefix, len(headers))
	if len(got) > securityEventListFieldCap {
		t.Fatalf("截断后 len=%d 超过列表上限 %d", len(got), securityEventListFieldCap)
	}
	var roundTrip map[string][]string
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("前缀裁剪必须保持合法 JSON: %v", err)
	}
	if values := roundTrip[securityEventDroppedHeadersKey]; len(values) != 1 || values[0] != "2" {
		t.Fatalf("采集 64KB 计数键必须原样保留（不并入）: %v", roundTrip)
	}
	kept := len(roundTrip)
	if _, present := roundTrip[securityEventListDroppedHeadersKey]; present {
		kept--
	}
	if values := roundTrip[securityEventListDroppedHeadersKey]; len(values) != 1 {
		t.Fatalf("列表 16KB 裁剪必须计入独立键: %v", roundTrip)
	} else if dropped, err := strconv.Atoi(values[0]); err != nil || dropped != len(headers)-kept {
		t.Fatalf("丢失计数=%q, want 总键数(%d)−保留键数(%d)", values[0], len(headers), kept)
	}
	// 完整成员的值不得被改写（只丢尾部键）
	for key, values := range roundTrip {
		if key == securityEventListDroppedHeadersKey {
			continue
		}
		if len(values) != len(headers[key]) {
			t.Fatalf("头 %s 值条目数变化: %d → %d", key, len(headers[key]), len(values))
		}
		for i, value := range values {
			if value != headers[key][i] {
				t.Fatalf("头 %s 的值被改写: %q → %q", key, headers[key][i], value)
			}
		}
	}
}

// 前缀内解不出任何完整成员（首个值就超限/非 JSON 脏行）时退回字节截断+
// 标记：此时保留半截 JSON 只会让前端解析失败，不如显式展示截断原文（前端
// 亮截断横幅）。
func TestTruncateEventListHeaders_unescapablePrefixFallsBackToByteTruncation(t *testing.T) {
	// 单个超长值：前缀只落在该值内部，解不出任何完整成员。
	headers := map[string][]string{"X-Long": {strings.Repeat("v", 20*1024)}}
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= securityEventListFieldCap {
		t.Fatalf("夹具必须超过列表上限: %d", len(raw))
	}
	for _, prefix := range []string{
		string(raw[:securityEventListFieldCap+1]),        // 超长单值前缀
		strings.Repeat("a", securityEventListFieldCap+1), // 非 JSON 脏行
	} {
		got := truncateEventListHeaders(prefix, len(headers))
		if len(got) > securityEventListFieldCap+len("\n...[TRUNCATED]") {
			t.Fatalf("字节截断结果 len=%d 超出上限+标记", len(got))
		}
		if !strings.HasSuffix(got, "\n...[TRUNCATED]") {
			t.Fatalf("无法保结构时必须追加截断标记: %q", got[len(got)-40:])
		}
		if strings.Contains(got, "_lb_list_dropped_headers") {
			t.Fatalf("字节截断形态不得伪造丢弃计数键: %q", got)
		}
	}
}

// 前缀内存在完整成员时保留结构（即使首个超长键被切断）：不因单值超限就
// 丢弃整块头表，仍返回合法 JSON + 丢弃计数。
func TestTruncateEventListHeaders_keepsCompleteMembersWhenValueTruncated(t *testing.T) {
	headers := map[string][]string{
		"Host":   {"a.example.com"},
		"X-Long": {strings.Repeat("v", 20*1024)},
	}
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	prefix := string(raw[:securityEventListFieldCap+1])
	got := truncateEventListHeaders(prefix, len(headers))
	var roundTrip map[string][]string
	if err := json.Unmarshal([]byte(got), &roundTrip); err != nil {
		t.Fatalf("有完整成员时必须保持合法 JSON: %v（body=%q）", err, got)
	}
	if values := roundTrip["Host"]; len(values) != 1 || values[0] != "a.example.com" {
		t.Fatalf("完整成员必须原样保留: %v", roundTrip["Host"])
	}
	if _, present := roundTrip["X-Long"]; present {
		t.Fatalf("被切断的成员不得以半截值出现: %v", roundTrip["X-Long"])
	}
	if values := roundTrip[securityEventListDroppedHeadersKey]; len(values) != 1 || values[0] != "1" {
		t.Fatalf("被切断的键必须计入丢弃计数: %v", roundTrip)
	}
}

// 结构化请求体截断的 base64 分支：载荷必须按 4 字符对齐切分并统一改写为
// base64-truncated: 前缀——否则前端 atob 抛错，正文整块退化为原文。
func TestTruncateEventListBody_base64PayloadAlignment(t *testing.T) {
	for _, input := range []string{
		"base64:" + strings.Repeat("A", 20*1024),
		"base64-truncated:" + strings.Repeat("A", 20*1024),
	} {
		got := truncateEventListBody(input)

		if len(got) > securityEventListFieldCap {
			t.Fatalf("截断后 len=%d 超过列表上限 %d", len(got), securityEventListFieldCap)
		}
		const prefix = "base64-truncated:"
		if !strings.HasPrefix(got, prefix) {
			t.Fatalf("base64 载荷截断后必须统一前缀 %q: %.24q", prefix, got)
		}
		payload := strings.TrimPrefix(got, prefix)
		if len(payload)%4 != 0 {
			t.Fatalf("base64 载荷必须 4 字符对齐（len=%d）", len(payload))
		}
		if _, err := base64.StdEncoding.DecodeString(payload); err != nil {
			t.Fatalf("截断后的 base64 载荷必须可解码: %v", err)
		}
	}
}

// 事件列表 total/events 含私网/保留地址，与总览 includes_reserved 同键披露
// （大屏 rollup 排除私网/保留——三面口径对称后跨面比数不等时有据可查）。
func TestListSecurityEvents_disclosesIncludesReserved(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	recorder := getRequest(t, newSecurityEventsRouter(t), "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			IncludesReserved *bool `json:"includes_reserved"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Data.IncludesReserved == nil || !*payload.Data.IncludesReserved {
		t.Fatalf("includes_reserved=%v, want true（口径披露与安全总览同键）", payload.Data.IncludesReserved)
	}
}

// 超限请求头按「SQL 前缀 + 前缀内完整成员重序列化」处理：
// 单行头不再整列（≤64KB/行）取回，响应仍是合法 JSON 头表（前缀内的完整头
// 逐字保留），被切断的键数计入 _lb_list_dropped_headers，前端据此展示
// 「已隐藏 N 个头」。
func TestListSecurityEvents_oversizedHeadersKeepJSONAndDiscloseDropped(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	gin.SetMode(gin.TestMode)
	h := &Handlers{}
	router := gin.New()
	// 管理视角：服务端脱敏对 admin 不触发（否则敏感头值被掩码，无法断言逐字保留）。
	router.GET("/security/events", func(c *gin.Context) { c.Set("role", "admin") }, h.ListSecurityEvents)

	const bulk = 80
	headers := make(map[string][]string, bulk+1)
	for i := range bulk {
		headers[fmt.Sprintf("X-Bulk-%03d", i)] = []string{strings.Repeat("v", 1024)}
	}
	headers["Host"] = []string{"a.example.com"}
	raw, err := json.Marshal(headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= securityEventListFieldCap {
		t.Fatalf("夹具必须超过列表上限: %d", len(raw))
	}
	if _, err := db.MetricsDB.Exec(`INSERT INTO security_events (event_time, client_ip, action, request_headers)
		VALUES ('2026-10-19 10:00:00','185.199.108.9','blocked',?)`, string(raw)); err != nil {
		t.Fatalf("seed event: %v", err)
	}

	recorder := getRequest(t, router, "/security/events")
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200", recorder.Code, recorder.Body.String())
	}
	var payload struct {
		Data struct {
			Events []models.SecurityEvent `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if len(payload.Data.Events) != 1 {
		t.Fatalf("events=%d, want 1", len(payload.Data.Events))
	}
	got := payload.Data.Events[0].RequestHeaders
	if len(got) > securityEventListFieldCap {
		t.Fatalf("request_headers len=%d > 列表上限 %d", len(got), securityEventListFieldCap)
	}
	if strings.HasSuffix(got, "\n...[TRUNCATED]") {
		t.Fatalf("合法 JSON 头必须保留结构（不得退化为字节截断）: %s", got[:80])
	}
	var parsed map[string][]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("响应头必须是合法 JSON: %v", err)
	}
	if values := parsed["Host"]; len(values) != 1 || values[0] != "a.example.com" {
		t.Fatalf("前缀内的完整头必须逐字保留: %v", parsed["Host"])
	}
	kept := 0
	for key, values := range parsed {
		if key == securityEventListDroppedHeadersKey {
			continue
		}
		kept++
		wantValue := strings.Repeat("v", 1024)
		if key == "Host" {
			wantValue = "a.example.com"
		}
		if len(values) != 1 || values[0] != wantValue {
			t.Fatalf("头 %s 的值被裁剪（应只丢弃尾部键，不改写保留值）: %v", key, values)
		}
	}
	dropValues := parsed[securityEventListDroppedHeadersKey]
	if len(dropValues) != 1 {
		t.Fatalf("必须披露被切断的键数: %+v", parsed)
	}
	dropped, err := strconv.Atoi(dropValues[0])
	if err != nil {
		t.Fatalf("丢弃计数非数字: %q", dropValues[0])
	}
	if dropped != len(headers)-kept || dropped <= 0 {
		t.Fatalf("dropped=%d, want 总键数(%d) - 保留键数(%d)", dropped, len(headers), kept)
	}

	// 传输侧口径：SQL 投影只取 cap+1 字节（不再整列取回 64KB 级头）。
	var projected string
	if err := db.MetricsDB.QueryRow("SELECT " + securityEventListFieldSQL("request_headers") + " FROM security_events LIMIT 1").Scan(&projected); err != nil {
		t.Fatalf("SQL 投影: %v", err)
	}
	if len(projected) > securityEventListFieldCap+1 {
		t.Fatalf("SQL 投影取回 %d 字节 > cap+1", len(projected))
	}
}

// 命中缓存必须返回深拷贝：四个切片不得与缓存条目共享底层数组（同型事故：
// 健康缓存「共享同一克隆」）。此前 data := entry.data 直接返回缓存切片，
// 任何消费者就地 sort/截断/改元素都会污染其他请求的 30s 缓存。
func TestLoadSecurityOverviewAggregates_cacheHitReturnsDeepCopy(t *testing.T) {
	setupSecurityPolicyTestDB(t)
	resetSecurityOverviewAggCacheForTest()
	t.Cleanup(resetSecurityOverviewAggCacheForTest)
	today := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	const todayStart = "2026-10-18 16:00:00"
	const tzModifier = "+08:00"
	insertOverviewAggregateEvent(t, db.MetricsDB, "2026-10-19 01:00:00")

	if _, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier); err != nil {
		t.Fatalf("first aggregate: %v", err)
	}

	// When：命中缓存后对返回值的切片就地改写/扩容
	hit, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier)
	if err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	if len(hit.trend) != 7 {
		t.Fatalf("trend len=%d, want 7（夹具失效）", len(hit.trend))
	}
	for i := range hit.trend {
		hit.trend[i].Blocked = 999
		hit.trend[i].Date = "MUTATED"
	}
	hit.topIPs = append(hit.topIPs, hit.topIPs...)
	hit.attackTypes = append(hit.attackTypes, hit.attackTypes...)
	hit.attackTypesStage = append(hit.attackTypesStage, hit.attackTypesStage...)

	// Then：再次命中缓存的返回值必须是未被污染的内容
	again, err := loadSecurityOverviewAggregates(db.MetricsDB, today, todayStart, tzModifier)
	if err != nil {
		t.Fatalf("second cache hit: %v", err)
	}
	if got := overviewAggregateEventCount(again); got != 1 {
		t.Fatalf("缓存被就地改写污染：trend 总计数=%d, want 1", got)
	}
	for _, point := range again.trend {
		if point.Date == "MUTATED" || point.Blocked == 999 {
			t.Fatalf("缓存日桶被污染: %+v", point)
		}
	}
}

func TestGetSecurityOverview_topIPsCarryRecentFrequency(t *testing.T) {
	// Given one IP with events at now / -30m / -2h
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	now := time.Now().UTC()
	seedSecurityEvent(t, now.Format("2006-01-02 15:04:05"), "lb_recent", 1, "942100", "SQL Injection")
	seedSecurityEvent(t, now.Add(-30*time.Minute).Format("2006-01-02 15:04:05"), "lb_recent", 1, "942100", "SQL Injection")
	seedSecurityEvent(t, now.Add(-2*time.Hour).Format("2006-01-02 15:04:05"), "lb_recent", 1, "942100", "SQL Injection")

	// When
	recorder := getRequest(t, router, "/security/overview")

	// Then top_ips carries separate 10m/1h windows independent of the 7d total
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int                     `json:"code"`
		Data models.SecurityOverview `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse overview: %v", err)
	}
	if len(resp.Data.TopIPs) != 1 {
		t.Fatalf("top_ips=%+v, want 1", resp.Data.TopIPs)
	}
	got := resp.Data.TopIPs[0]
	if got.Recent10m != 1 || got.Recent1h != 2 {
		t.Fatalf("recent_10m/recent_1h=%d/%d, want 1/2", got.Recent10m, got.Recent1h)
	}
}
