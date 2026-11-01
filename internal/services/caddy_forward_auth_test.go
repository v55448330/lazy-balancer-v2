package services

// 认证网关（forward_auth）渲染钉测 + NTLM 专用 transport 渲染钉测。
//
// forward_auth：Caddy 官方 forward_auth 指令的 JSON 展开形态
// （caddy adapt 实证 v2.11.7：reverse_proxy + rewrite method=GET/uri +
// headers 回传 X-Forwarded-Method/Uri + handle_response match status_code [2]
// 逐头 delete+条件 set 拷贝；非 2xx 无匹配 handle_response 条目 → 网关响应
// 原样回拷客户端）。链首插入（安全链之前）：未认证请求不进指标/安全链。
//
// NTLM transport：caddyserver/ntlm-transport v0.1.2（http_ntlm transport，
// Provision 强制 Versions=["1.1"] + keep-alive，连接级协商亲和）——ntlm=1 时
// transport.protocol 发射 http_ntlm 并省略 versions（模块强制，替代
// force_http1 的 versions 字段）；ntlm=0 行为逐字节不变。

import (
	"strings"
	"testing"
)

func forwardAuthRule() SingleRuleConfig {
	rule := baseHTTPRule()
	rule.ForwardAuthEnabled = 1
	rule.ForwardAuthUpstream = "http://gw.internal:7000"
	rule.ForwardAuthURI = "/api/authz/forward-auth"
	rule.ForwardAuthCopyHeaders = "Remote-User,Remote-Groups,Remote-Email,Remote-Name"
	return rule
}

// findHandler 在 handle 链中按 handler 名查找，返回（索引，处理器）。
func findHandlerInHandleChain(t *testing.T, chain []interface{}, name string) (int, map[string]interface{}) {
	t.Helper()
	for i, raw := range chain {
		handler, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		if handler["handler"] == name {
			return i, handler
		}
	}
	t.Fatalf("handler %q not found in chain of %d handlers", name, len(chain))
	return -1, nil
}

func TestBuildHTTPHandleChain_forwardAuthChainHead(t *testing.T) {
	rule := forwardAuthRule()
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if len(chain) == 0 {
		t.Fatal("empty handle chain")
	}
	// 链首即网关子请求处理器（先于 X-LB-Rule-ID headers / 指标 / 安全链）。
	head, ok := chain[0].(map[string]interface{})
	if !ok || head["handler"] != "reverse_proxy" {
		t.Fatalf("chain head = %#v, want forward_auth reverse_proxy", chain[0])
	}

	// rewrite：恒 GET + 网关校验路径。
	rewrite, ok := head["rewrite"].(map[string]interface{})
	if !ok || rewrite["method"] != "GET" || rewrite["uri"] != "/api/authz/forward-auth" {
		t.Fatalf("rewrite = %#v, want method=GET uri=/api/authz/forward-auth", head["rewrite"])
	}

	// 回传原始方法与 URI（自身被改写前捕获）。
	headers, ok := head["headers"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers = %#v", head["headers"])
	}
	request, ok := headers["request"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers.request = %#v", headers["request"])
	}
	sets, ok := request["set"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers.request.set = %#v", request["set"])
	}
	if got := sets["X-Forwarded-Method"]; len(got.([]string)) != 1 || got.([]string)[0] != "{http.request.method}" {
		t.Fatalf("X-Forwarded-Method = %#v", sets["X-Forwarded-Method"])
	}
	if got := sets["X-Forwarded-Uri"]; len(got.([]string)) != 1 || got.([]string)[0] != "{http.request.uri}" {
		t.Fatalf("X-Forwarded-Uri = %#v", sets["X-Forwarded-Uri"])
	}

	// upstreams：网关 dial（默认端口按 scheme 补全场景见 HTTPS 用例）。
	upstreams, ok := head["upstreams"].([]interface{})
	if !ok || len(upstreams) != 1 {
		t.Fatalf("upstreams = %#v", head["upstreams"])
	}
	dial := upstreams[0].(map[string]interface{})["dial"]
	if dial != "gw.internal:7000" {
		t.Fatalf("dial = %v, want gw.internal:7000", dial)
	}

	// handle_response：仅 2xx 条目；逐头 delete + 条件 set（与 caddy adapt
	// 展开形态逐块一致——网关未回传的头不置空值）。
	entries, ok := head["handle_response"].([]interface{})
	if !ok || len(entries) != 1 {
		t.Fatalf("handle_response = %#v", head["handle_response"])
	}
	entry, ok := entries[0].(map[string]interface{})
	if !ok {
		t.Fatalf("handle_response[0] = %#v", entries[0])
	}
	match, ok := entry["match"].(map[string]interface{})
	if !ok {
		t.Fatalf("handle_response[0].match = %#v", entry["match"])
	}
	codes, ok := match["status_code"].([]int)
	if !ok || len(codes) != 1 || codes[0] != 2 {
		t.Fatalf("match.status_code = %#v, want [2]", match["status_code"])
	}
	routes, ok := entry["routes"].([]interface{})
	if !ok {
		t.Fatalf("handle_response[0].routes = %#v", entry["routes"])
	}
	// 每个身份头恰好一组 delete+条件 set（默认清单 4 头 → 8 条 + 前导 vars）。
	if len(routes) != 1+2*4 {
		t.Fatalf("routes len = %d, want %d（vars + 4 头×(delete+条件 set)）", len(routes), 1+2*4)
	}
	deleted, setWithMatch := 0, 0
	for _, raw := range routes[1:] {
		route := raw.(map[string]interface{})
		handles := route["handle"].([]interface{})
		handler := handles[0].(map[string]interface{})
		if handler["handler"] != "headers" {
			t.Fatalf("unexpected handler in copy routes: %#v", handler)
		}
		req := handler["request"].(map[string]interface{})
		if _, hasDelete := req["delete"]; hasDelete {
			deleted++
			continue
		}
		// 条件 set：not vars {http.reverse_proxy.header.X} == ""（网关未回传
		// 该头时不注入空值）。
		matchers, ok := route["match"].([]interface{})
		if !ok || len(matchers) != 1 {
			t.Fatalf("set route missing not-empty matcher: %#v", route)
		}
		matcher := matchers[0].(map[string]interface{})
		notList := matcher["not"].([]interface{})
		varsMatcher := notList[0].(map[string]interface{})["vars"].(map[string]interface{})
		for placeholder := range varsMatcher {
			if !strings.HasPrefix(placeholder, "{http.reverse_proxy.header.") {
				t.Fatalf("unexpected vars placeholder %q", placeholder)
			}
		}
		setWithMatch++
	}
	if deleted != 4 || setWithMatch != 4 {
		t.Fatalf("copy routes deleted=%d setWithMatch=%d, want 4/4", deleted, setWithMatch)
	}
}

func TestBuildHTTPHandleChain_forwardAuthDisabled(t *testing.T) {
	// 回归形状：enabled=0 链零变化（链首仍是 X-LB-Rule-ID headers）。
	rule := baseHTTPRule()
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if chain[0].(map[string]interface{})["handler"] == "reverse_proxy" {
		t.Fatalf("disabled rule rendered forward_auth at chain head: %#v", chain[0])
	}
}

func TestBuildHTTPHandleChain_forwardAuthMalformed(t *testing.T) {
	// 畸形形状（带外脏行）：渲染显性失败（零兜底），错误进入
	// generationFailure → 保存门/启动聚合门拦截。
	cases := []struct {
		name   string
		mutate func(*SingleRuleConfig)
	}{
		{"upstream 缺失", func(r *SingleRuleConfig) { r.ForwardAuthUpstream = "" }},
		{"upstream 无 scheme", func(r *SingleRuleConfig) { r.ForwardAuthUpstream = "gw.internal:7000" }},
		{"upstream 非 http scheme", func(r *SingleRuleConfig) { r.ForwardAuthUpstream = "ftp://gw.internal:7000" }},
		{"uri 缺失", func(r *SingleRuleConfig) { r.ForwardAuthURI = "" }},
		{"uri 非 / 开头", func(r *SingleRuleConfig) { r.ForwardAuthURI = "api/verify" }},
		{"uri 含 CRLF", func(r *SingleRuleConfig) { r.ForwardAuthURI = "/api/verify\r\nX-Injected: 1" }},
		{"身份头清单为空", func(r *SingleRuleConfig) { r.ForwardAuthCopyHeaders = "" }},
		{"身份头含内部空白", func(r *SingleRuleConfig) { r.ForwardAuthCopyHeaders = "Remote-User,Remote User,Remote-Email" }},
		{"身份头含 CRLF", func(r *SingleRuleConfig) { r.ForwardAuthCopyHeaders = "Remote-User\r\nX: 1" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rule := forwardAuthRule()
			tc.mutate(&rule)
			if _, err := buildHTTPHandleChain(rule, rule.Upstreams); err == nil {
				t.Fatalf("%s: expected render failure, got nil", tc.name)
			}
		})
	}
}

func TestBuildHTTPHandleChain_forwardAuthHTTPSGateway(t *testing.T) {
	// https 网关：dial 默认端口 443 + transport 携带项目标准
	// insecure_skip_verify（与上游 https 渲染同口径）。
	rule := forwardAuthRule()
	rule.ForwardAuthUpstream = "https://auth.example.test"
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	_, head := findHandlerInHandleChain(t, chain, "reverse_proxy")
	upstreams := head["upstreams"].([]interface{})
	if dial := upstreams[0].(map[string]interface{})["dial"]; dial != "auth.example.test:443" {
		t.Fatalf("dial = %v, want auth.example.test:443", dial)
	}
	transport, ok := head["transport"].(map[string]interface{})
	if !ok {
		t.Fatalf("https gateway missing transport: %#v", head)
	}
	tlsConfig, ok := transport["tls"].(map[string]interface{})
	if !ok || tlsConfig["insecure_skip_verify"] != true {
		t.Fatalf("transport.tls = %#v, want insecure_skip_verify", transport["tls"])
	}
}

func TestBuildHTTPHandleChain_ntlmTransport(t *testing.T) {
	// 目标形状：ntlm=1 → transport.protocol=http_ntlm（连接级协商亲和）；
	// versions 省略（模块 Provision 强制 ["1.1"]，替代 force_http1 的 versions
	// 字段）；keep_alive 沿接管形态 300s 正常发射（模块 keep-alive 语义兼容）。
	rule := baseHTTPRule()
	rule.NTLMCompatible = 1
	rule.UpstreamForceHTTP1 = 1
	rule.Upstreams[0].Protocol = "https"
	rule.Upstreams[1].Protocol = "https"
	rule.UpstreamKeepaliveTimeout = 300
	rule.GlobalUpstreamKeepaliveTimeout = 120
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	_, proxy := findHandlerInHandleChain(t, chain, "reverse_proxy")
	transport, ok := proxy["transport"].(map[string]interface{})
	if !ok {
		t.Fatalf("ntlm rule missing transport: %#v", proxy)
	}
	if transport["protocol"] != "http_ntlm" {
		t.Fatalf("transport.protocol = %v, want http_ntlm", transport["protocol"])
	}
	if _, hasVersions := transport["versions"]; hasVersions {
		t.Fatalf("http_ntlm transport must not emit versions (module forces 1.1): %#v", transport)
	}
	keepAlive, ok := transport["keep_alive"].(map[string]interface{})
	if !ok || keepAlive["idle_timeout"] != "300s" {
		t.Fatalf("keep_alive = %#v, want idle_timeout 300s", transport["keep_alive"])
	}
}

func TestBuildHTTPHandleChain_ntlmTransportRegression(t *testing.T) {
	// 回归形状：ntlm=0 时 force_http1 的 versions 字段逐字节保持现状。
	rule := baseHTTPRule()
	rule.UpstreamForceHTTP1 = 1
	rule.Upstreams[0].Protocol = "https"
	rule.Upstreams[1].Protocol = "https"
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	_, proxy := findHandlerInHandleChain(t, chain, "reverse_proxy")
	transport, ok := proxy["transport"].(map[string]interface{})
	if !ok || transport["protocol"] != "http" {
		t.Fatalf("transport = %#v, want protocol http", proxy["transport"])
	}
	versions, ok := transport["versions"].([]string)
	if !ok || len(versions) != 1 || versions[0] != "1.1" {
		t.Fatalf("versions = %#v, want [1.1]", transport["versions"])
	}
}

func TestBuildHTTPHandleChain_ntlmTransportPlainHTTPUpstreams(t *testing.T) {
	// NTLM 接管典型形态（明文 http 上游）：此前 needsTransport=false 无
	// transport——ntlm=1 必须发射 http_ntlm transport（接管的核心语义）。
	rule := baseHTTPRule()
	rule.NTLMCompatible = 1
	rule.UpstreamForceHTTP1 = 1
	chain, err := buildHTTPHandleChain(rule, rule.Upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	_, proxy := findHandlerInHandleChain(t, chain, "reverse_proxy")
	transport, ok := proxy["transport"].(map[string]interface{})
	if !ok || transport["protocol"] != "http_ntlm" {
		t.Fatalf("plain http upstreams missing http_ntlm transport: %#v", proxy["transport"])
	}
}
