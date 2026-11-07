package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
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

// 复制链同门：源行 ntlm_compatible=1（接管四列齐）且启用上游为
// https+origin_domain 时，复制必须 400 点名源规则。复制链把源行投影为
// ruleFeatureInput 时若缺逐上游协议/回源域名两数组，组合门零迭代空转，
// 组合源行被原样放大为副本（旁路 Create/Update/导入三链同门）。
func TestDuplicateRule_ntlmComboSourceRejected(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.POST("/rules/:caddy_id/duplicate", handler.DuplicateRule)

	// 直改 DB 造存量源行（复制只读存量）：NTLM 接管四列齐的合法形态 +
	// 单个启用 https 上游携带 origin_domain。
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,enable_compress,
		ntlm_compatible,upstream_force_http1,tcp_try_duration,proxy_flush_interval,upstream_keepalive_timeout)
		VALUES ('lb_dupntlmcombo','dup-ntlm-combo','','http','dup-ntlm.test',18810,'cookie',0,1,
		1,1,-1,-1,300)`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol,origin_domain)
		VALUES ('lb_dupntlmcombo','mail.example.com',443,1,1,'https','origin.example.com')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/rules/lb_dupntlmcombo/duplicate", nil))

	if response.Code != http.StatusBadRequest {
		t.Fatalf("NTLM+HTTPS 上游+origin_domain 源行复制必须 400, got %d body=%s", response.Code, response.Body.String())
	}
	body := response.Body.String()
	if !strings.Contains(body, "源规则配置不合法") || !strings.Contains(body, "NTLM 兼容不支持") {
		t.Fatalf("响应应点名互斥原因: %s", body)
	}

	// 被拒源行不得产生副本。
	var copies int
	if err := db.DB.QueryRow(`SELECT COUNT(*) FROM lb_rules WHERE caddy_id LIKE 'lb_dupntlmcombo%' AND caddy_id != 'lb_dupntlmcombo'`).Scan(&copies); err != nil {
		t.Fatalf("count copies: %v", err)
	}
	if copies != 0 {
		t.Fatalf("拒绝的源行不得产生副本, got %d", copies)
	}
}
