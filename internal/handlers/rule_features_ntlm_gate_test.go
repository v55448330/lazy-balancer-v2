package handlers

import (
	"strings"
	"testing"
)

// NTLM 兼容与「HTTPS 上游 + origin_domain」组合互斥（保存门）：
// 该组合下连接走 TLS 直连通道旁路 NTLM 接管的 unbinder 包裹——长连接亲和
// 失效且 ntlm-transport 连接逐连接累积不回收。 Create/Update 与 v2 导入
// 三链同门；非 https 上游、无 origin_domain、TCP 规则不受影响。
func TestValidateRuleFeatures_ntlmComboWithHTTPSOriginDomainRejected(t *testing.T) {
	combo := ruleFeatureInput{
		Protocol:                     "http",
		Strategy:                     "cookie",
		NTLMCompatible:               1,
		UpstreamForceHTTP1:           1,
		TCPTryDuration:               -1,
		ProxyFlushInterval:           -1,
		UpstreamKeepaliveTimeout:     300,
		EnabledUpstreamProtocols:     []string{"https"},
		EnabledUpstreamOriginDomains: []string{"origin.example.com"},
		EnabledUpstreamHosts:         []string{"mail.example.com"},
	}
	err := validateRuleFeatures(combo)
	if err == nil {
		t.Fatal("NTLM+HTTPS 上游+origin_domain 组合必须被拒绝")
	}
	if !strings.Contains(err.Error(), "NTLM 兼容不支持") {
		t.Fatalf("错误文案应点名 NTLM 兼容互斥: %v", err)
	}

	// 非 https 上游携带 origin_domain：放行（组合不成立）
	httpOrigin := combo
	httpOrigin.EnabledUpstreamProtocols = []string{"http"}
	if err := validateRuleFeatures(httpOrigin); err != nil {
		t.Fatalf("http 上游+origin_domain 不应被 NTLM 门拒绝: %v", err)
	}

	// https 上游但无 origin_domain：放行（组合不成立）
	httpsNoOrigin := combo
	httpsNoOrigin.EnabledUpstreamOriginDomains = []string{""}
	if err := validateRuleFeatures(httpsNoOrigin); err != nil {
		t.Fatalf("https 上游无 origin_domain 不应被 NTLM 门拒绝: %v", err)
	}
}

// v2 导入链同门：备份上游行携带 https+origin_domain 且规则 ntlm_compatible=1
// 时整包拒绝（规则号点名）。
func TestValidateV2BackupRules_ntlmComboRejectedOnImport(t *testing.T) {
	tables := map[string][]map[string]any{
		"lb_rules": {{
			"id": 1, "caddy_id": "lb_ntlmcombo", "name": "ntlm-combo",
			"domain":   "ntlm-combo.example.com",
			"protocol": "http", "strategy": "cookie", "enabled": 1,
			"ntlm_compatible": 1, "upstream_force_http1": 1,
			"tcp_try_duration": -1, "proxy_flush_interval": -1,
			"upstream_keepalive_timeout": 300, "listen_port": 8080,
		}},
		"upstreams": {{
			"id": 1, "rule_id": "lb_ntlmcombo", "host": "mail.example.com",
			"port": 443, "protocol": "https", "origin_domain": "origin.example.com",
			"enabled": 1,
		}},
		"path_rules": {},
	}
	err := validateV2BackupRules(tables)
	if err == nil {
		t.Fatal("导入链必须拒绝 NTLM+HTTPS 上游+origin_domain 组合")
	}
	if !strings.Contains(err.Error(), "NTLM 兼容不支持") {
		t.Fatalf("导入错误文案应点名 NTLM 兼容互斥: %v", err)
	}
}
