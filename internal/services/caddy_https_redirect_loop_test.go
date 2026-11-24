package services

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// :80 上的 HTTP→HTTPS 跳转路由：
//   - 请求已是 HTTPS（X-Forwarded-Proto: https——前置代理终止 TLS 后以明文回源）
//     时不得再 301：同一 https 地址上的 301 就是浏览器里的无限跳转。这类请求
//     落到紧随全部跳转路由之后的诊断路由（400 + 说明文字）；
//   - 301 带 Cache-Control: no-store：跳转受规则开关控制，可缓存的 301 会让
//     浏览器在开关关闭后仍沿用旧跳转（「关了也没用」）。

func seedHTTPSRedirectRuleOnDefaultPort(t *testing.T, ruleID, domain string) map[string]interface{} {
	t.Helper()
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, domain)
	seedGenerationRule(t, database, ruleID, false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain=?, listen_port=443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id=?`, domain, certPEM, keyPEM, ruleID); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}
	generated := generateCaddyConfigFromStore(database)
	if message, failed := generated[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	return generated
}

func matcherSet(t *testing.T, route map[string]interface{}, name string) map[string]interface{} {
	t.Helper()
	matches, ok := route["match"].([]interface{})
	if !ok || len(matches) == 0 {
		t.Fatalf("%s: match=%#v", name, route["match"])
	}
	return mustMap(t, matches[0], name+" matcher")
}

func forwardedProtoPatterns(t *testing.T, matcher map[string]interface{}) []string {
	t.Helper()
	regexpMatchers, ok := matcher["header_regexp"].(map[string]interface{})
	if !ok {
		t.Fatalf("缺 header_regexp 匹配器: %#v", matcher)
	}
	xfp, ok := regexpMatchers["X-Forwarded-Proto"].(map[string]interface{})
	if !ok {
		t.Fatalf("header_regexp 缺 X-Forwarded-Proto: %#v", regexpMatchers)
	}
	pattern, _ := xfp["pattern"].(string)
	return []string{pattern}
}

func TestGenerateCaddyConfig_httpsRedirect_skipsRequestAlreadyHTTPS(t *testing.T) {
	generated := seedHTTPSRedirectRuleOnDefaultPort(t, "lb_loop_guard", "loop.example.test")
	routes := httpRoutesFromServer(t, generated, "http_80")

	redirect := findRouteByID(t, routes, "lb_loop_guard_redirect")
	set := matcherSet(t, redirect, "跳转路由")
	if hosts, _ := set["host"].([]string); len(hosts) != 1 || hosts[0] != "loop.example.test" {
		t.Fatalf("跳转路由的 host 匹配被改动: %#v", set["host"])
	}
	negated, ok := set["not"].([]interface{})
	if !ok || len(negated) != 1 {
		t.Fatalf("跳转路由必须排除「已是 HTTPS」的请求（not 匹配器）: %#v", set["not"])
	}
	patterns := forwardedProtoPatterns(t, mustMap(t, negated[0], "not 内匹配器"))
	if len(patterns) != 1 || patterns[0] != forwardedHTTPSHeaderPattern {
		t.Fatalf("not 内必须是对 X-Forwarded-Proto 的正则排除: %#v", negated)
	}
	response := firstHandler(t, redirect)
	headers := mustMap(t, response["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://{http.request.host}{http.request.uri}"})
	assertEqual(t, headers["Cache-Control"], []string{"no-store"})

	// 诊断路由：全部跳转路由之后、落地页之前
	var diagnostic map[string]interface{}
	diagnosticAt := -1
	redirectAt := -1
	for index, value := range routes {
		route := mustMap(t, value, "route")
		if route["@id"] == httpsRedirectLoopDiagnosticRouteID {
			diagnostic, diagnosticAt = route, index
		}
		if route["@id"] == "lb_loop_guard_redirect" {
			redirectAt = index
		}
	}
	if diagnostic == nil {
		t.Fatalf("缺「已是 HTTPS 不再跳转」诊断路由；:80 路由 ID=%v", routeIDs(routes))
	}
	if redirectAt < 0 || diagnosticAt <= redirectAt {
		t.Fatalf("诊断路由必须位于跳转路由之后: redirect=%d diagnostic=%d", redirectAt, diagnosticAt)
	}
	if diagnosticAt != len(routes)-2 {
		t.Fatalf("诊断路由必须紧邻落地页之前（第 %d/%d 条）", diagnosticAt+1, len(routes))
	}
	diagSet := matcherSet(t, diagnostic, "诊断路由")
	if hosts, _ := diagSet["host"].([]string); len(hosts) != 1 || hosts[0] != "loop.example.test" {
		t.Fatalf("诊断路由必须限定在跳转域名内: %#v", diagSet["host"])
	}
	diagPatterns := forwardedProtoPatterns(t, diagSet)
	if len(diagPatterns) != 1 || diagPatterns[0] != forwardedHTTPSHeaderPattern {
		t.Fatalf("诊断路由必须按 X-Forwarded-Proto=https 匹配: %#v", diagSet)
	}
	diagResponse := firstHandler(t, diagnostic)
	if diagResponse["handler"] != "static_response" || diagResponse["status_code"] != 400 {
		t.Fatalf("诊断路由应为 400 static_response: %#v", diagResponse)
	}
	diagHeaders := mustMap(t, diagResponse["headers"], "diagnostic headers")
	assertEqual(t, diagHeaders["Cache-Control"], []string{"no-store"})
	if body, _ := diagResponse["body"].(string); !strings.Contains(body, "X-Forwarded-Proto") {
		t.Fatalf("诊断响应正文必须点明 X-Forwarded-Proto: %q", diagResponse["body"])
	}
	if terminal, _ := diagnostic["terminal"].(bool); !terminal {
		t.Fatalf("诊断路由必须 terminal，不得落入落地页")
	}
	if landing := firstHandler(t, routes[len(routes)-1]); landing["body"] != DefaultLandingBody() {
		t.Fatalf("落地页必须是 :80 的最后一条路由")
	}
}

func TestGenerateCaddyConfig_diagnosticRouteCoversEveryRedirectDomain(t *testing.T) {
	// 多条跳转规则：诊断路由只有一条，域名并集覆盖全部跳转规则。
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	certPEM, keyPEM := matchingCertificatePair(t, "b.example.test", "c.example.test")
	seedGenerationRule(t, database, "lb_loop_b", false)
	if _, err := database.Exec(`UPDATE lb_rules SET domain='b.example.test, c.example.test', listen_port=8443,
		enable_tls=1, tls_source='manual', tls_cert=?, tls_key=?, tls_http_redirect=1
		WHERE caddy_id='lb_loop_b'`, certPEM, keyPEM); err != nil {
		t.Fatalf("enable TLS redirect: %v", err)
	}
	seedGenerationRule(t, database, "lb_loop_plain", false)
	multi := generateCaddyConfigFromStore(database)
	if message, failed := multi[caddyConfigGenerationErrorKey].(string); failed {
		t.Fatalf("generate config: %s", message)
	}
	multiRoutes := httpRoutesFromServer(t, multi, "http_80")
	diagnostic := findRouteByID(t, multiRoutes, httpsRedirectLoopDiagnosticRouteID)
	hosts, _ := matcherSet(t, diagnostic, "诊断路由")["host"].([]string)
	assertEqual(t, hosts, []string{"b.example.test", "c.example.test"})
	ids := routeIDs(multiRoutes)
	assertEqual(t, ids, []string{"lb_loop_b_redirect", httpsRedirectLoopDiagnosticRouteID, ""})
	for _, value := range multiRoutes[:len(multiRoutes)-1] {
		set := matcherSet(t, mustMap(t, value, "route"), "跳转/诊断路由")
		if _, ok := set["host"].([]string); !ok {
			t.Fatalf("未开跳转的域名不得进入 :80 跳转与诊断路由: %#v", set)
		}
	}
}

func TestGenerateCaddyConfig_noRedirectRuleEmitsNoDiagnosticRoute(t *testing.T) {
	useTemporaryCertDir(t)
	_, database := newClusterTestService(t)
	seedGenerationRule(t, database, "lb_plain_only", false)
	generated := generateCaddyConfigFromStore(database)
	routes := httpRoutesFromServer(t, generated, "http_80")
	assertEqual(t, routeIDs(routes), []string{""})
}

// 真实引擎验收（外部 caddy 二进制，与引擎验收族同约定）：渲染出的 :80 server
// 原样校验并启动，逐请求验证匹配语义。
func TestHTTPSRedirectRoutes_realEngineAcceptance(t *testing.T) {
	binary := caddyBinaryForAcceptance(t)
	generated := seedHTTPSRedirectRuleOnDefaultPort(t, "lb_engine_loop", "engine-loop.example.test")
	apps := mustMap(t, generated["apps"], "apps")
	httpServers := mustMap(t, mustMap(t, apps["http"], "http app")["servers"], "servers")
	server := mustMap(t, httpServers["http_80"], "http_80")
	port := reservePort(t)
	server["listen"] = []string{fmt.Sprintf("127.0.0.1:%d", port)}
	raw, err := json.Marshal(map[string]interface{}{
		"admin": map[string]interface{}{"disabled": true},
		"apps":  map[string]interface{}{"http": map[string]interface{}{"servers": map[string]interface{}{"http_80": server}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	validateCaddyJSONForAcceptance(t, binary, raw)
	path := filepath.Join(t.TempDir(), "http80.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	run := exec.CommandContext(t.Context(), binary, "run", "--config", path)
	output := &strings.Builder{}
	run.Stdout, run.Stderr = output, output
	if err := run.Start(); err != nil {
		t.Fatalf("start caddy: %v", err)
	}
	t.Cleanup(func() {
		_ = run.Process.Kill()
		_, _ = run.Process.Wait()
	})
	if err := waitForTCP(fmt.Sprintf("127.0.0.1:%d", port)); err != nil {
		t.Fatalf("引擎未在超时内监听: %v\n%s", err, output.String())
	}

	cases := []struct {
		name           string
		host           string
		forwardedProto string
		wantStatus     int
		wantLocation   string
	}{
		{"明文 http 跳 https", "engine-loop.example.test", "", http.StatusMovedPermanently, "https://engine-loop.example.test/p?a=1"},
		{"X-Forwarded-Proto: http 仍跳转", "engine-loop.example.test", "http", http.StatusMovedPermanently, "https://engine-loop.example.test/p?a=1"},
		{"已是 HTTPS 不再跳转", "engine-loop.example.test", "https", http.StatusBadRequest, ""},
		{"大小写不敏感", "engine-loop.example.test", "HTTPS", http.StatusBadRequest, ""},
		{"非跳转域名走落地页", "other.example.test", "", http.StatusOK, ""},
	}
	client := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/p?a=1", port), nil)
			req.Host = tc.host
			if tc.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.forwardedProto)
			}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = resp.Body.Close() }()
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status=%d want %d body=%q", resp.StatusCode, tc.wantStatus, body)
			}
			if got := resp.Header.Get("Location"); got != tc.wantLocation {
				t.Fatalf("Location=%q want %q", got, tc.wantLocation)
			}
			if tc.wantStatus == http.StatusMovedPermanently && resp.Header.Get("Cache-Control") != "no-store" {
				t.Fatalf("301 必须带 Cache-Control: no-store，实际 %q", resp.Header.Get("Cache-Control"))
			}
			if tc.wantStatus == http.StatusBadRequest && !strings.Contains(string(body), "X-Forwarded-Proto") {
				t.Fatalf("诊断页必须点明 X-Forwarded-Proto: %q", body)
			}
		})
	}
}

func TestForwardedProtoJudgment_inSyncWithListenerWrapperModule(t *testing.T) {
	// 监听包装器（独立模块 caddygeoip）与渲染层各写一份「已是 HTTPS」判据与
	// 诊断正文；两侧的字面量必须逐字一致（同 caddyl4sec 受信代理判据的成对同步纪律）。
	source, err := os.ReadFile(filepath.Join("..", "..", "caddygeoip", "https_redirect_wrapper.go"))
	if err != nil {
		t.Fatal(err)
	}
	for name, literal := range map[string]string{
		"forwardedHTTPSHeaderPattern": strconv.Quote(forwardedHTTPSHeaderPattern),
		"httpsRedirectLoopBody":       strconv.Quote(httpsRedirectLoopBody),
	} {
		if !strings.Contains(string(source), literal) {
			t.Errorf("caddygeoip 包装器必须与渲染层同字面量 %s=%s", name, literal)
		}
	}
}

func reservePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func waitForTCP(address string) error {
	deadline := time.Now().Add(10 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 300*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(50 * time.Millisecond)
	}
	return lastErr
}

func routeIDs(routes []interface{}) []string {
	ids := make([]string, 0, len(routes))
	for _, value := range routes {
		route, _ := value.(map[string]interface{})
		id, _ := route["@id"].(string)
		ids = append(ids, id)
	}
	return ids
}

// 路径规则跳转模式同样是用户配置的 301：修改或撤销跳转后，浏览器不得沿用缓存的
// 旧跳转（与面板入口 302、HTTP→HTTPS 301 同口径）。
func TestPathRuleRoute_redirectModeIsNotCacheable(t *testing.T) {
	rule := SingleRuleConfig{HealthCheckInterval: 10, HealthCheckTimeout: 2, HealthCheckUnhealthyThreshold: 3, HealthCheckHealthyThreshold: 2, GlobalRequestBodyMaxSizeMB: 128, CaddyID: "lb_prresp", Protocol: "http", ListenPort: 8080, Domain: "prresp.example.test",
		CustomRoutesEnabled: true,
		Upstreams:           []UpstreamConfig{{Host: "10.0.0.1", Port: 9000, Weight: 1, Enabled: true}},
		PathRules: []PathRuleConfig{
			{SortOrder: 0, MatchType: "prefix", Path: "/old/", ResponseMode: "redirect", RedirectTo: "https://new.example.com/landing"},
		}}
	routes := buildPathRuleRoutesForTest(t, rule)
	handler := staticResponseOf(t, findPathRoute(routes, "path_0"))
	headers := mustMap(t, handler["headers"], "redirect headers")
	assertEqual(t, headers["Location"], []string{"https://new.example.com/landing"})
	assertEqual(t, headers["Cache-Control"], []string{"no-store"})
}
