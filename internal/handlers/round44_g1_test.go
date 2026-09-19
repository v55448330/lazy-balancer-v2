package handlers

// 第 44 轮 G1 组修复钉住测试:SEC44-1(429 剔除出拦截状态码白名单)+
// LB44-1(tcp→http 回切恢复 dns_family 默认)。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"lazy-balancer-v2/internal/db"
)

// SEC44-1(第 44 轮):validBlockStatus 白名单剔除 429——拦截语义 429 保留给
// 限流(overviewmetrics.go:83-90 限流卡片按 code=429 计数),WAF 拦截页 429
// 会混入限流指标口径。
func TestSEC441_validateSecurityPolicyEnums_rejectsBlockStatus429(t *testing.T) {
	// Given 合法基线枚举(mode/ip_acl_mode/geoip_mode 均合法)

	// When block_status_code=429(限流专用语义)
	err := validateSecurityPolicyEnums("blocking", "deny", "deny", 429, 5)

	// Then 必须拒绝
	if err == nil || !strings.Contains(err.Error(), "拦截状态码") {
		t.Fatalf("block_status_code=429 must be rejected, got %v", err)
	}

	// 其余既有枚举(含 0=默认)不受影响
	for _, code := range []int{0, 400, 401, 403, 404, 503} {
		if err := validateSecurityPolicyEnums("blocking", "deny", "deny", code, 5); err != nil {
			t.Fatalf("block_status_code=%d must stay valid, got %v", code, err)
		}
	}
}

// LB44-1(第 44 轮):tcp→http 协议回切恢复 dns_family 默认 'ipv4'(与
// CreateRule :758-760 默认同口径;切 TCP 清零在 :1337,不补恢复会让存量 ”
// 直接落库,DB 终态与创建态分叉)。
func TestLB441_protocolSwitchBackToHTTPRestoresDNSFamily(t *testing.T) {
	handler := newRuleFeatureTestHandlers(t)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.PUT("/rules/:caddy_id", handler.UpdateRule)

	// Given 存量 TCP 规则(dns_family 已被切 TCP 分支清零)
	if _, err := db.DB.Exec(`INSERT INTO lb_rules (caddy_id,name,description,protocol,domain,listen_port,strategy,enabled,dns_family)
		VALUES ('lb_dnsrestore','dnsrestore','','tcp','',18582,'weighted_round_robin',1,'')`); err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	if _, err := db.DB.Exec(`INSERT INTO upstreams (rule_id,host,port,weight,enabled,protocol) VALUES ('lb_dnsrestore','up.test',80,1,1,'tcp')`); err != nil {
		t.Fatalf("seed upstream: %v", err)
	}

	// When 回切 http
	request := httptest.NewRequest(http.MethodPut, "/rules/lb_dnsrestore", strings.NewReader(`{"protocol":"http","domain":"dnsrestore.test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("switch back to http: status=%d body=%s", response.Code, response.Body.String())
	}

	// Then dns_family 恢复默认 ipv4
	var dnsFamily string
	if err := db.DB.QueryRow(`SELECT COALESCE(dns_family,'') FROM lb_rules WHERE caddy_id='lb_dnsrestore'`).Scan(&dnsFamily); err != nil {
		t.Fatal(err)
	}
	if dnsFamily != "ipv4" {
		t.Fatalf("dns_family must restore to default ipv4 after tcp→http switch, got %q", dnsFamily)
	}
}
