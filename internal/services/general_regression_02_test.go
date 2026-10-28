package services

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// GetConfig 必须先检查 Caddy admin 的 HTTP 状态再解码。错误体即使是合法 JSON
// （{"error":"..."}），旧实现也会直接解码并把错误对象当配置返回；健康查询更
// 会静默退化为「无上游健康数据」的空白态。getRunningConfigBytes 是正确对照。
func TestCaddyService_GetConfig_rejectsNonOKAdminResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/config/" {
			t.Errorf("unexpected admin path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"loading new config: boom"}`)
	}))
	t.Cleanup(server.Close)

	config, err := NewCaddyService(server.URL).GetConfig()
	if err == nil {
		t.Fatalf("GetConfig() error=nil, want non-2xx error; config=%#v", config)
	}
	if !strings.Contains(err.Error(), "500") {
		t.Fatalf("GetConfig() error=%q, want admin status code in message", err)
	}
}

// 回归形状：200 正常响应照常解码（状态门不得误伤正常路径）。
func TestCaddyService_GetConfig_decodesOKAdminResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}}}}`)
	}))
	t.Cleanup(server.Close)

	config, err := NewCaddyService(server.URL).GetConfig()
	if err != nil {
		t.Fatalf("GetConfig() error=%v, want nil", err)
	}
	if _, ok := config["apps"].(map[string]interface{}); !ok {
		t.Fatalf("config=%#v, want decoded apps object", config)
	}
}

// GetUpstreamHealthDetailed 与 GetConfig 同源读取 /config/：非 2xx 必须报错，
// 不得返回「无健康数据」的空表 + nil。
func TestCaddyService_GetUpstreamHealthDetailed_rejectsNonOKConfigResponse(t *testing.T) {
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/metrics":
			w.WriteHeader(http.StatusServiceUnavailable)
		case "/reverse_proxy/upstreams":
			_, _ = io.WriteString(w, `[]`)
		case "/config/":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `{"error":"admin unavailable"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(admin.Close)

	health, err := NewCaddyService(admin.URL).GetUpstreamHealthDetailed()
	if err == nil {
		t.Fatalf("GetUpstreamHealthDetailed() error=nil, want non-2xx error; health=%#v", health)
	}
	if !strings.Contains(err.Error(), "502") {
		t.Fatalf("GetUpstreamHealthDetailed() error=%q, want admin status code in message", err)
	}
}

// 「协议/端口/启用上游」门与自排除语义。渲染层据此替代 R×N 逐对规范化。
func TestBuildPort80DomainOwners_indexesNormalizedCandidates(t *testing.T) {
	// Given 两条候选规则（同一域名大小写混合 + 多域名），以及自排除场景
	candidates := []port80RuleCandidate{
		{caddyID: "lb_a", domain: "Example.COM, a.example.com"},
		{caddyID: "lb_b", domain: " example.com "},
		{caddyID: "lb_c", domain: ""},
	}

	// When
	owners := buildPort80DomainOwners(candidates)

	// Then 规范化（小写）且同域名聚合两条规则；空域名不产出条目
	got := owners["example.com"]
	if len(got) != 2 || got[0] != "lb_a" || got[1] != "lb_b" {
		t.Fatalf("owners[example.com]=%v, want [lb_a lb_b]", got)
	}
	if _, exists := owners[""]; exists {
		t.Fatal("empty domain must not be indexed")
	}
	if len(owners) != 2 {
		t.Fatalf("index size=%d, want 2 distinct domains (example.com, a.example.com): %v", len(owners), owners)
	}
}

// 回归形状：80 端口规则零启用上游时不得作为遮蔽方，且同一条跳转
func TestGenerateCaddyConfig_httpsRedirect_disabledUpstreamPort80RuleDoesNotShadow(t *testing.T) {
	// Given 一条 TLS 跳转规则与一条同域名但全部上游禁用的 80 端口规则
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "shadow-disabled.test")
	seedGenerationRule(t, database, "lb_redir_disabled_shadow", false)
	seedGenerationRule(t, database, "lb_80_disabled", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='shadow-disabled.test', listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_redir_disabled_shadow'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='shadow-disabled.test', listen_port=80 WHERE caddy_id='lb_80_disabled'`); err != nil {
		t.Fatalf("enable port-80 rule: %v", err)
	}
	if _, err := database.Exec(`UPDATE upstreams SET enabled=0 WHERE rule_id='lb_80_disabled'`); err != nil {
		t.Fatalf("disable port-80 upstream: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then 死规则不作为遮蔽方，跳转仍生成
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_80")
	redirect := findRouteByID(t, routes, "lb_redir_disabled_shadow_redirect")
	if redirect == nil {
		t.Fatalf("零启用上游的 80 端口规则不得遮蔽跳转: %#v", routes)
	}
	assertEqual(t, routeMatcher(t, redirect)["host"], []string{"shadow-disabled.test"})
}

// 回归形状：多跳转规则 × 多 80 端口规则交叉遮蔽——只有真实冲突的域名被剔除，
// 且同一域名被多条 80 规则拥有时仍然阻断。
func TestGenerateCaddyConfig_httpsRedirect_multiRuleShadowIndexKeepsSemantics(t *testing.T) {
	// Given 两条跳转规则与两条 80 端口规则，域名交叉
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "one.test", "two.test", "three.test", "four.test")
	for _, id := range []string{"lb_redir_one", "lb_redir_two", "lb_80_one", "lb_80_two"} {
		seedGenerationRule(t, database, id, false)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='one.test, two.test', listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_redir_one'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect one: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='three.test, four.test', listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_redir_two'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect two: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='Two.TEST', listen_port=80 WHERE caddy_id='lb_80_one'`); err != nil {
		t.Fatalf("enable port-80 one: %v", err)
	}
	if _, err := database.Exec(`UPDATE lb_rules SET domain='two.test, three.test', listen_port=80 WHERE caddy_id='lb_80_two'`); err != nil {
		t.Fatalf("enable port-80 two: %v", err)
	}

	// When
	generated := generateCaddyConfigFromStore(database)

	// Then：two.test/three.test 被 80 端口规则拥有而剔除；one.test/four.test 无冲突保留
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	routes := httpRoutesFromServer(t, generated, "http_80")
	redirectOne := findRouteByID(t, routes, "lb_redir_one_redirect")
	if redirectOne == nil {
		t.Fatalf("one.test 未被遮蔽，跳转必须存在: %#v", routes)
	}
	assertEqual(t, routeMatcher(t, redirectOne)["host"], []string{"one.test"})
	redirectTwo := findRouteByID(t, routes, "lb_redir_two_redirect")
	if redirectTwo == nil {
		t.Fatalf("four.test 未被遮蔽，跳转必须存在: %#v", routes)
	}
	assertEqual(t, routeMatcher(t, redirectTwo)["host"], []string{"four.test"})
}
