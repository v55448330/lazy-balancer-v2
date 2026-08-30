package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"lazy-balancer-v2/internal/db"
)

func TestFormatIP2RegionLocation(t *testing.T) {
	cases := []struct {
		name   string
		region string
		want   string
	}{
		{"full china region", "中国|广东省|深圳市|电信|CN", "中国·广东·深圳"},
		{"municipality", "中国|北京市|北京市|联通|CN", "中国·北京·北京"},
		{"autonomous region", "中国|广西壮族自治区|南宁市|电信|CN", "中国·广西·南宁"},
		{"sar", "中国|香港特别行政区|九龙|0|CN", "中国·香港·九龙"},
		{"province only", "中国|山东省|0|0|CN", "中国·山东"},
		{"unknown province city", "中国|0|0|0|CN", "中国"},
		{"overseas", "美国|0|0|0|US", "海外"},
		{"unknown region", "0|0|0|0|0", ""},
		{"empty", "", ""},
		{"too few fields", "中国|广东省", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := formatIP2RegionLocation(tc.region); got != tc.want {
				t.Fatalf("formatIP2RegionLocation(%q)=%q, want %q", tc.region, got, tc.want)
			}
		})
	}
}

func TestEnrichIPLocation_emptyWithoutDatabaseNeverErrors(t *testing.T) {
	// Given: no xdb loaded (test process never installs one)
	// When / Then: lookups degrade to "" instead of failing
	if got := enrichIPLocation("192.0.2.1"); got != "" {
		t.Fatalf("enrichIPLocation without xdb=%q, want empty", got)
	}
	if got := enrichIPLocation(""); got != "" {
		t.Fatalf("enrichIPLocation(empty ip)=%q, want empty", got)
	}
}

func TestListSecurityEvents_carriesIPLocationField(t *testing.T) {
	// Given: one seeded event (no xdb in tests → location stays empty, never 500)
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedSecurityEvent(t, "2026-08-12 10:00:01", "lb_loc1", 1, "942100", "SQL Injection")

	// When
	recorder := getRequest(t, router, "/security/events")

	// Then: the response carries an ip_location field on every event
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			Events []struct {
				ClientIP   string `json:"client_ip"`
				IPLocation string `json:"ip_location"`
			} `json:"events"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.Events) != 1 {
		t.Fatalf("events = %s", recorder.Body.String())
	}
	if resp.Data.Events[0].ClientIP != "192.0.2.9" || resp.Data.Events[0].IPLocation != "" {
		t.Fatalf("event ip/ip_location = %q/%q, want 192.0.2.9/\"\" without xdb", resp.Data.Events[0].ClientIP, resp.Data.Events[0].IPLocation)
	}
}

func TestGetSecurityOverview_topIPsCarryIPLocationField(t *testing.T) {
	// Given: one recent event feeding the Top-10 table
	setupSecurityPolicyTestDB(t)
	router := newSecurityEventsRouter(t)
	seedSecurityEvent(t, time.Now().UTC().Format("2006-01-02 15:04:05"), "lb_loc2", 1, "942100", "SQL Injection")

	// When
	recorder := getRequest(t, router, "/security/overview")

	// Then: every top_ips entry carries ip_location (empty without xdb, never 500)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data struct {
			TopIPs []struct {
				IP         string `json:"ip"`
				IPLocation string `json:"ip_location"`
			} `json:"top_ips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data.TopIPs) != 1 {
		t.Fatalf("top_ips = %s", recorder.Body.String())
	}
	if resp.Data.TopIPs[0].IP != "192.0.2.9" || resp.Data.TopIPs[0].IPLocation != "" {
		t.Fatalf("top ip/ip_location = %q/%q, want 192.0.2.9/\"\" without xdb", resp.Data.TopIPs[0].IP, resp.Data.TopIPs[0].IPLocation)
	}
}

// N15-F2：ListSecurityPolicies 的 rule_caddy_id 过滤按绑定表筛出该规则绑定的
// 策略（IP 归属地弹窗按当前规则收敛可选策略列表所依赖的口径）。
func TestListSecurityPolicies_ruleCaddyIDFilter(t *testing.T) {
	// Given：两条启用策略，仅甲绑定到规则 lb_filter1
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('过滤甲', 1), ('过滤乙', 1)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO security_policy_bindings (rule_caddy_id, policy_id) SELECT 'lb_filter1', id FROM security_policies WHERE name='过滤甲'`); err != nil {
		t.Fatalf("seed binding: %v", err)
	}

	// When：按 rule_caddy_id 过滤
	recorder := getRequest(t, router, "/security/policies?rule_caddy_id=lb_filter1")

	// Then：仅返回绑定的策略
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "过滤甲" {
		t.Fatalf("policies = %s, want only 过滤甲", recorder.Body.String())
	}

	// And：未绑定任何策略的规则返回空列表
	empty := getRequest(t, router, "/security/policies?rule_caddy_id=lb_nobind")
	var emptyResp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(empty.Body.Bytes(), &emptyResp); err != nil {
		t.Fatalf("parse empty response: %v", err)
	}
	if len(emptyResp.Data) != 0 {
		t.Fatalf("unbound rule policies = %s, want empty", empty.Body.String())
	}
}

func TestListSecurityPolicies_enabledFilter(t *testing.T) {
	// Given: one enabled and one disabled policy
	setupSecurityPolicyTestDB(t)
	router := newSecurityRouter(t)
	if _, err := db.DB.Exec(`INSERT INTO security_policies (name, enabled) VALUES ('启用策略', 1), ('禁用策略', 0)`); err != nil {
		t.Fatalf("seed policies: %v", err)
	}

	// When: listing with enabled=true
	recorder := getRequest(t, router, "/security/policies?enabled=true")

	// Then: only the enabled policy is returned
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var resp struct {
		Code int `json:"code"`
		Data []struct {
			Name    string `json:"name"`
			Enabled bool   `json:"enabled"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse response: %v", err)
	}
	if len(resp.Data) != 1 || resp.Data[0].Name != "启用策略" || !resp.Data[0].Enabled {
		t.Fatalf("policies = %s, want only 启用策略", recorder.Body.String())
	}

	// And: without the flag both come back (backwards compatible)
	all := getRequest(t, router, "/security/policies")
	var allResp struct {
		Code int `json:"code"`
		Data []struct {
			Name string `json:"name"`
		} `json:"data"`
	}
	if err := json.Unmarshal(all.Body.Bytes(), &allResp); err != nil {
		t.Fatalf("parse all response: %v", err)
	}
	if len(allResp.Data) != 2 {
		t.Fatalf("policies without filter = %s, want both", all.Body.String())
	}
}
