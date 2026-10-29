package handlers

// TCP 规则“显式输入契约”三入口一致性：Create 对 HTTP-only 字段显式携带
// 返回 400（保存门点名），Update 不得把它们静默改写为默认值——同一份显式
// 载荷在两个写入口必须给同一结论。未提交/存量死值仍走自愈（否则存量脏行
// 的无关编辑会 400 死端）。
// 同族：TCP 终态的安全策略绑定清理必须在启用/同协议编辑两处收口（渲染链不
// 加载策略，残留绑定是静默虚报）。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

func seedTCPRuleForExplicitInput(t *testing.T, caddyID string, port int, enabled bool, strategy, healthCheckHost string) {
	t.Helper()
	enabledVal := 0
	if enabled {
		enabledVal = 1
	}
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,listen_port,strategy,
		health_check_path,health_check_interval,health_check_timeout,health_check_unhealthy_threshold,health_check_healthy_threshold,
		enable_active_health_check,tcp_health_check_port,tcp_proxy_protocol,tcp_try_duration,tcp_try_interval,
		request_body_max_size_mb,upstream_keepalive_timeout,server_tokens_hidden,tls_source,enabled,health_check_host)
		VALUES (?,?,'','tcp',?,?,'',10,5,3,2,0,9001,0,5000,300,0,0,0,'manual',?,?)`,
		caddyID, caddyID, port, strategy, enabledVal, healthCheckHost); err != nil {
		t.Fatalf("seed tcp rule %s: %v", caddyID, err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES (?,'127.0.0.1',9000,1,1,'tcp')`, caddyID); err != nil {
		t.Fatalf("seed upstream %s: %v", caddyID, err)
	}
}

func newTCPRuleRouter(h *Handlers) (*gin.Engine, func(string, string) *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(func(c *gin.Context) { c.Set("user_id", 42) })
	router.PUT("/rules/:caddy_id", h.UpdateRule)
	router.POST("/rules/:caddy_id/enable", h.EnableRule)
	put := func(caddyID, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPut, "/rules/"+caddyID, strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		return response
	}
	return router, put
}

func readTCPRowStrategyAndHost(t *testing.T, caddyID string) (strategy, healthCheckHost string) {
	t.Helper()
	if err := db.DB.QueryRow(`SELECT COALESCE(strategy,''), COALESCE(health_check_host,'') FROM lb_rules WHERE caddy_id = ?`, caddyID).
		Scan(&strategy, &healthCheckHost); err != nil {
		t.Fatalf("read tcp row: %v", err)
	}
	return strategy, healthCheckHost
}

func TestUpdateRule_tcpExplicitCookieStrategyRejected(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_cookie", 18101, false, "weighted_round_robin", "")
	_, put := newTCPRuleRouter(handler)

	rec := put("lb_tcp_cookie", `{"strategy":"cookie"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "负载策略") {
		t.Fatalf("status=%d body=%s, want 400 点名负载策略（与 CreateRule 契约一致）", rec.Code, rec.Body.String())
	}
	if strategy, _ := readTCPRowStrategyAndHost(t, "lb_tcp_cookie"); strategy != "weighted_round_robin" {
		t.Fatalf("stored strategy=%q, want 原值保留（显式输入被拒不得写库）", strategy)
	}
}

func TestUpdateRule_tcpStoredCookieStrategySelfHeals(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_cookie_legacy", 18102, false, "cookie", "")
	_, put := newTCPRuleRouter(handler)

	rec := put("lb_tcp_cookie_legacy", `{"name":"renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（未提交策略=存量死值自愈）", rec.Code, rec.Body.String())
	}
	if strategy, _ := readTCPRowStrategyAndHost(t, "lb_tcp_cookie_legacy"); strategy != "weighted_round_robin" {
		t.Fatalf("stored strategy=%q, want weighted_round_robin（存量 cookie 自愈）", strategy)
	}
}

func TestUpdateRule_tcpExplicitHealthCheckHostRejected(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_host", 18103, false, "weighted_round_robin", "")
	_, put := newTCPRuleRouter(handler)

	rec := put("lb_tcp_host", `{"health_check_host":"hc.example.test"}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "健康检查域名仅 HTTP 规则支持") {
		t.Fatalf("status=%d body=%s, want 400 点名健康检查域名（与 CreateRule 契约一致）", rec.Code, rec.Body.String())
	}
	if _, host := readTCPRowStrategyAndHost(t, "lb_tcp_host"); host != "" {
		t.Fatalf("stored health_check_host=%q, want 空（显式输入被拒不得写库）", host)
	}
}

func TestUpdateRule_tcpStoredHealthCheckHostSelfHeals(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_host_legacy", 18104, false, "weighted_round_robin", "legacy.example.test")
	_, put := newTCPRuleRouter(handler)

	rec := put("lb_tcp_host_legacy", `{"name":"renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s, want 200（未提交=存量死值自愈）", rec.Code, rec.Body.String())
	}
	if _, host := readTCPRowStrategyAndHost(t, "lb_tcp_host_legacy"); host != "" {
		t.Fatalf("stored health_check_host=%q, want 空（存量死值自愈）", host)
	}
}

// Given 同协议 TCP 编辑显式提交任一 HTTP-only 死字段。
// When UpdateRule 保存。
// Then 与 CreateRule 同口径 400 点名拒绝，不得先清零再返回 200。
func TestUpdateRule_tcpExplicitHTTPOnlyFieldsRejected(t *testing.T) {
	cases := []struct {
		column string
		value  string
		want   string
	}{
		{column: "dynamic_dns", value: "true", want: "动态上游"},
		{column: "custom_routes_enabled", value: "true", want: "自定义路径规则"},
		{column: "proxy_dial_timeout", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_response_header_timeout", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_read_timeout", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_write_timeout", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_stream_timeout", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_flush_interval", value: "1", want: "HTTP 代理超时"},
		{column: "proxy_stream_close_delay", value: "1", want: "HTTP 代理超时"},
	}
	for index, tc := range cases {
		t.Run(tc.column, func(t *testing.T) {
			handler, _, _ := newAuditRuleHandlers(t, 0)
			caddyID := "lb_tcp_explicit_" + tc.column
			seedTCPRuleForExplicitInput(t, caddyID, 18200+index, false, "weighted_round_robin", "")
			_, put := newTCPRuleRouter(handler)

			rec := put(caddyID, `{"`+tc.column+`":`+tc.value+`}`)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s, want 400 包含 %q", rec.Code, rec.Body.String(), tc.want)
			}
			var stored int
			if err := db.DB.QueryRow(`SELECT `+tc.column+` FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&stored); err != nil {
				t.Fatalf("read rejected field: %v", err)
			}
			if stored != 0 {
				t.Fatalf("%s=%d, want 原值 0（拒绝请求不得写库）", tc.column, stored)
			}
		})
	}
}

// Given HTTP→TCP 协议切换同时显式提交 HTTP-only 字段。
// When 协议切换分支执行死字段归一。
// Then 显式值仍须留给保存门拒绝；只有未提交的存量值才自动清零。
func TestUpdateRule_httpToTCPExplicitHTTPOnlyFieldsRejected(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{name: "dynamic_dns", value: "true", want: "动态上游"},
		{name: "custom_routes_enabled", value: "true", want: "自定义路径规则"},
		{name: "proxy_dial_timeout", value: "1", want: "HTTP 代理超时"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler, _, _ := newAuditRuleHandlers(t, 0)
			caddyID := "lb_switch_explicit_" + tc.name
			seedAuditRule(t, caddyID, "switch", "switch-"+tc.name+".example.test", 18300, false, "manual", false)
			seedAuditUpstream(t, caddyID)
			_, put := newTCPRuleRouter(handler)

			rec := put(caddyID, `{"protocol":"tcp","`+tc.name+`":`+tc.value+`}`)
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("status=%d body=%s, want 400 包含 %q", rec.Code, rec.Body.String(), tc.want)
			}
			var protocol string
			if err := db.DB.QueryRow(`SELECT protocol FROM lb_rules WHERE caddy_id=?`, caddyID).Scan(&protocol); err != nil {
				t.Fatal(err)
			}
			if protocol != "http" {
				t.Fatalf("protocol=%q, want 原值 http（拒绝请求不得写库）", protocol)
			}
		})
	}
}

func seedPolicyAndBinding(t *testing.T, caddyID string) {
	t.Helper()
	result, err := db.DB.Exec(`INSERT INTO security_policies (name,policy_type,mode,enabled) VALUES ('tcp-binding-policy','stage1','blocking',1)`)
	if err != nil {
		t.Fatalf("seed policy: %v", err)
	}
	policyID, err := result.LastInsertId()
	if err != nil {
		t.Fatalf("policy id: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id,policy_id) VALUES (?,?)`, caddyID, policyID); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
}

func bindingCount(t *testing.T, caddyID string) int {
	t.Helper()
	var count int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM security_policy_bindings WHERE rule_caddy_id=?`, caddyID).Scan(&count); err != nil {
		t.Fatalf("count bindings: %v", err)
	}
	return count
}

func auditCountFor(t *testing.T, action, resource string) int {
	t.Helper()
	var count int
	if err := db.AuditDB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND resource=?`, action, resource).Scan(&count); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return count
}

func TestEnableRule_dropsTCPBindingsAndAudits(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_enable_bind", 18105, false, "weighted_round_robin", "")
	seedPolicyAndBinding(t, "lb_tcp_enable_bind")
	router, _ := newTCPRuleRouter(handler)
	before := auditCountFor(t, "启用", "安全策略")

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_tcp_enable_bind/enable", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("enable status=%d body=%s", response.Code, response.Body.String())
	}
	if got := bindingCount(t, "lb_tcp_enable_bind"); got != 0 {
		t.Fatalf("bindings=%d, want 0（TCP 渲染不加载策略，启用即清理）", got)
	}
	if got := auditCountFor(t, "启用", "安全策略") - before; got != 1 {
		t.Fatalf("binding cleanup audit rows=%d, want 1", got)
	}
}

func TestUpdateRule_dropsTCPBindingsOnSameProtocolEdit(t *testing.T) {
	handler, _, _ := newAuditRuleHandlers(t, 0)
	seedTCPRuleForExplicitInput(t, "lb_tcp_update_bind", 18106, false, "weighted_round_robin", "")
	seedPolicyAndBinding(t, "lb_tcp_update_bind")
	_, put := newTCPRuleRouter(handler)
	before := auditCountFor(t, "更新", "安全策略")

	rec := put("lb_tcp_update_bind", `{"name":"renamed"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("update status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := bindingCount(t, "lb_tcp_update_bind"); got != 0 {
		t.Fatalf("bindings=%d, want 0（同协议 TCP 编辑同族清理）", got)
	}
	if got := auditCountFor(t, "更新", "安全策略") - before; got != 1 {
		t.Fatalf("binding cleanup audit rows=%d, want 1", got)
	}
}
