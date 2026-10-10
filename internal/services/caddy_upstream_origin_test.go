package services

import (
	"testing"
)

// 逐上游回源域名渲染（2026-10-10，原生 map 方案）：内建 http.handlers.map 处理器
// 以 {http.reverse_proxy.upstream.hostport} 为源晚绑定查表（map.go:127-175 实证——
// Source 在目标占位符被使用时才求值，恰为 reverse_proxy 选中上游后），destinations
// 产出 {lb.upstream_host}/{lb.upstream_sni} 供 reverse_proxy headers/transport 消费。
// 回退链 defaults 精确复现现状：Host=host_header 或 {http.request.hostport}（r.Host
// 原样）；SNI=host_header 或 {http.reverse_proxy.upstream.host}（dial 主机名）。

// findMapHandler 在 handle 链中定位 map 处理器（不存在返回 nil）。
func findMapHandler(chain []interface{}) map[string]interface{} {
	for _, h := range chain {
		m, ok := h.(map[string]interface{})
		if ok && m["handler"] == "map" {
			return m
		}
	}
	return nil
}

// lastReverseProxy 返回链尾 reverse_proxy 处理器（链构造契约：恒为末位）。
func lastReverseProxy(t *testing.T, chain []interface{}) map[string]interface{} {
	t.Helper()
	last, ok := chain[len(chain)-1].(map[string]interface{})
	if !ok || last["handler"] != "reverse_proxy" {
		t.Fatalf("last handler must be reverse_proxy, got %#v", chain[len(chain)-1])
	}
	return last
}

// Given: 上游 A 配置回源域名、上游 B 留空；规则级后端域名已配
// When: 构建 HTTP handle 链
// Then: 发射 map 处理器（仅收录 A；SNI 输出剥端口）+ reverse_proxy Host 占位符，
//
//	defaults 回退规则级后端域名
func TestBuildHTTPHandleChain_originDomainEmitsMapHandler(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_origin", Protocol: "http", ListenPort: 80, HostHeader: "backend.example.com"}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin-a.example.com"},
		{Host: "10.0.0.2", Port: 8080, Weight: 1, Enabled: true},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}

	m := findMapHandler(chain)
	if m == nil {
		t.Fatalf("map handler must be emitted when any upstream carries origin_domain, chain=%#v", chain)
	}
	if m["source"] != "{http.reverse_proxy.upstream.hostport}" {
		t.Fatalf("map source=%#v, want {http.reverse_proxy.upstream.hostport}", m["source"])
	}
	dests, ok := m["destinations"].([]string)
	if !ok || len(dests) != 2 || dests[0] != "{lb.upstream_host}" || dests[1] != "{lb.upstream_sni}" {
		t.Fatalf("map destinations=%#v, want [{lb.upstream_host} {lb.upstream_sni}]", m["destinations"])
	}
	mappings, ok := m["mappings"].([]map[string]interface{})
	if !ok || len(mappings) != 1 {
		t.Fatalf("map mappings=%#v, want exactly 1 entry（仅收录配了回源域名的上游）", m["mappings"])
	}
	if mappings[0]["input"] != "10.0.0.1:8080" {
		t.Fatalf("mapping input=%#v, want 10.0.0.1:8080", mappings[0]["input"])
	}
	outputs, ok := mappings[0]["outputs"].([]string)
	if !ok || len(outputs) != 2 || outputs[0] != "origin-a.example.com" || outputs[1] != "origin-a.example.com" {
		t.Fatalf("mapping outputs=%#v, want [origin-a.example.com origin-a.example.com]（校验层禁端口，SNI 剥端口为防御性兜底）", mappings[0]["outputs"])
	}
	defaults, ok := m["defaults"].([]string)
	if !ok || len(defaults) != 2 || defaults[0] != "backend.example.com" || defaults[1] != "backend.example.com" {
		t.Fatalf("map defaults=%#v, want 规则级后端域名回退", m["defaults"])
	}

	proxy := lastReverseProxy(t, chain)
	headers := proxy["headers"].(map[string]interface{})["request"].(map[string]interface{})
	set, ok := headers["set"].(map[string]interface{})
	if !ok {
		t.Fatalf("headers.request.set missing: %#v", headers)
	}
	hostSet, ok := set["Host"].([]string)
	if !ok || len(hostSet) != 1 || hostSet[0] != "{lb.upstream_host}" {
		t.Fatalf("Host set=%#v, want [{lb.upstream_host}]", set["Host"])
	}
}

// Given: 回源域名上游存在且含 https 上游
// When: 构建链
// Then: transport.tls.server_name 切换为 {lb.upstream_sni} 占位符
func TestBuildHTTPHandleChain_originDomainHttpsSwitchesServerName(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_sni", Protocol: "http", ListenPort: 443, HostHeader: "backend.example.com"}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8443, Weight: 1, Enabled: true, Protocol: "https", OriginDomain: "origin-a.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	proxy := lastReverseProxy(t, chain)
	transport, ok := proxy["transport"].(map[string]interface{})
	if !ok {
		t.Fatalf("transport missing: %#v", proxy)
	}
	tls, ok := transport["tls"].(map[string]interface{})
	if !ok {
		t.Fatalf("transport.tls missing: %#v", transport)
	}
	if tls["server_name"] != "{lb.upstream_sni}" {
		t.Fatalf("tls.server_name=%#v, want {lb.upstream_sni}", tls["server_name"])
	}
}

// Given: 无上游配置回源域名（现状钉——零行为变化契约）
// When: 构建链（host_header 有/无两形态）
// Then: 不发射 map 处理器；Host set 仅 host_header 非空时存在且为静态值
func TestBuildHTTPHandleChain_noOriginDomainKeepsCurrentShape(t *testing.T) {
	upstreams := []UpstreamConfig{{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true}}
	for _, tc := range []struct {
		name       string
		hostHeader string
	}{
		{"host_header 为空", ""},
		{"host_header 已配", "backend.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := SingleRuleConfig{CaddyID: "lb_pin", Protocol: "http", ListenPort: 80, HostHeader: tc.hostHeader}
			chain, err := buildHTTPHandleChain(rule, upstreams)
			if err != nil {
				t.Fatalf("buildHTTPHandleChain: %v", err)
			}
			if m := findMapHandler(chain); m != nil {
				t.Fatalf("map handler must NOT be emitted without origin_domain, got %#v", m)
			}
			proxy := lastReverseProxy(t, chain)
			headers := proxy["headers"].(map[string]interface{})["request"].(map[string]interface{})
			set, hasSet := headers["set"].(map[string]interface{})
			if tc.hostHeader == "" {
				if hasSet && set["Host"] != nil {
					t.Fatalf("Host set must stay absent without host_header, got %#v", set)
				}
			} else {
				if !hasSet {
					t.Fatalf("Host set missing for host_header=%q", tc.hostHeader)
				}
				hostSet, _ := set["Host"].([]string)
				if len(hostSet) != 1 || hostSet[0] != tc.hostHeader {
					t.Fatalf("Host set=%#v, want static [%s]", set["Host"], tc.hostHeader)
				}
			}
		})
	}
}

// Given: 规则级后端域名为空 + 上游配回源域名
// When: 构建链
// Then: map defaults 回退现状默认占位符（Host={http.request.hostport} 透传/
//
//	transport 改写值；SNI={http.reverse_proxy.upstream.host} dial 主机名）
func TestBuildHTTPHandleChain_originDomainDefaultsWithoutHostHeader(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_dft", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin-a.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	m := findMapHandler(chain)
	if m == nil {
		t.Fatal("map handler must be emitted")
	}
	defaults, ok := m["defaults"].([]string)
	if !ok || len(defaults) != 2 ||
		defaults[0] != "{http.request.hostport}" ||
		defaults[1] != "{http.reverse_proxy.upstream.host}" {
		t.Fatalf("defaults=%#v, want [{http.request.hostport} {http.reverse_proxy.upstream.host}]", m["defaults"])
	}
}

// Given: 动态上游（dynamic_dns）规则携带回源域名（校验侧拒绝外的渲染守卫）
// When: 构建链
// Then: 不发射 map 处理器（动态池 dial=解析后 IP，静态映射永不命中）
func TestBuildHTTPHandleChain_originDomainSkippedForDynamicDNS(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_dyn", Protocol: "http", ListenPort: 80, DynamicDNS: true}
	upstreams := []UpstreamConfig{
		{Host: "up.example.com", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "origin-a.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	if m := findMapHandler(chain); m != nil {
		t.Fatalf("map handler must NOT be emitted for dynamic_dns rules, got %#v", m)
	}
}

// Given: 同 dial 地址重复条目（保存侧查重之外的渲染防御——备份导入等旁路）
// When: 构建链
// Then: 该 dial 仅一条 mapping（map Validate 拒绝重复 input，map.go:107-115），先出现者生效
func TestBuildHTTPHandleChain_originDomainDedupesDial(t *testing.T) {
	rule := SingleRuleConfig{CaddyID: "lb_dup", Protocol: "http", ListenPort: 80}
	upstreams := []UpstreamConfig{
		{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true, OriginDomain: "first.example.com"},
		{Host: "10.0.0.1", Port: 8080, Weight: 2, Enabled: true, OriginDomain: "second.example.com"},
	}

	chain, err := buildHTTPHandleChain(rule, upstreams)
	if err != nil {
		t.Fatalf("buildHTTPHandleChain: %v", err)
	}
	m := findMapHandler(chain)
	if m == nil {
		t.Fatal("map handler must be emitted")
	}
	mappings, ok := m["mappings"].([]map[string]interface{})
	if !ok || len(mappings) != 1 {
		t.Fatalf("mappings=%#v, want exactly 1 deduped entry", m["mappings"])
	}
	outputs, _ := mappings[0]["outputs"].([]string)
	if len(outputs) != 2 || outputs[0] != "first.example.com" {
		t.Fatalf("outputs=%#v, want first-wins [first.example.com ...]", mappings[0]["outputs"])
	}
}

// Given: 主动健康检查开启 + 健康检查域名已配（规则级后端域名亦配）
// When: 构建链
// Then: health_checks.active.headers.Host=健康检查域名（优先级高于后端域名）
func TestBuildHTTPHandleChain_healthCheckHostOverridesProbeHost(t *testing.T) {
	upstreams := []UpstreamConfig{{Host: "10.0.0.1", Port: 8080, Weight: 1, Enabled: true}}
	for _, tc := range []struct {
		name            string
		hostHeader      string
		healthCheckHost string
		wantHost        string
		wantAbsent      bool
	}{
		{"健康检查域名优先于后端域名", "backend.example.com", "probe.example.com", "probe.example.com", false},
		{"留空跟随后端域名（现状钉）", "backend.example.com", "", "backend.example.com", false},
		{"两者皆空不发射 headers 键（现状钉）", "", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rule := SingleRuleConfig{
				CaddyID: "lb_hc", Protocol: "http", ListenPort: 80,
				HostHeader: tc.hostHeader, HealthCheckHost: tc.healthCheckHost,
				EnableActiveHealthCheck: true,
			}
			chain, err := buildHTTPHandleChain(rule, upstreams)
			if err != nil {
				t.Fatalf("buildHTTPHandleChain: %v", err)
			}
			proxy := lastReverseProxy(t, chain)
			healthChecks, ok := proxy["health_checks"].(map[string]interface{})
			if !ok {
				t.Fatalf("health_checks missing: %#v", proxy)
			}
			active, ok := healthChecks["active"].(map[string]interface{})
			if !ok {
				t.Fatalf("health_checks.active missing: %#v", healthChecks)
			}
			headers, hasHeaders := active["headers"].(map[string]interface{})
			if tc.wantAbsent {
				if hasHeaders {
					t.Fatalf("active.headers must stay absent, got %#v", headers)
				}
				return
			}
			if !hasHeaders {
				t.Fatalf("active.headers missing, want Host=%q", tc.wantHost)
			}
			host, ok := headers["Host"].([]string)
			if !ok || len(host) != 1 || host[0] != tc.wantHost {
				t.Fatalf("active headers Host=%#v, want [%s]", headers["Host"], tc.wantHost)
			}
		})
	}
}
